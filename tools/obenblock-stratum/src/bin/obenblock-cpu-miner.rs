//! obenblock-cpu-miner: a multi-threaded SHA-256d CPU miner for ObenBlock
//! that mines through any Stratum V1 server exactly as stock ASIC firmware
//! does (ported from the Bloch proxy's rehearsal miner).
//!
//! ```text
//! obenblock-cpu-miner -o stratum+tcp://HOST:3333 -u <obb1 address>[.<worker>] [-p x] [-t THREADS] [--kernel K]
//! obenblock-cpu-miner --bench SECS [-t THREADS] [--kernel K]
//! ```
//!
//! * All logical CPUs by default (`-t` to choose); each thread owns its own
//!   extranonce2 lane (thread i takes extranonce2 = i, i + T, i + 2T, ...), so
//!   threads never repeat work, and the server's unique extranonce1 keeps
//!   machines apart.
//! * Per extranonce2: the coinbase `coinb1 ‖ extranonce1 ‖ extranonce2 ‖
//!   coinb2`, its txid folded up the merkle branch with SHA-256d (Bitcoin's
//!   tree, ObenBlock's header root), the 80-byte header, its midstate and
//!   the first three rounds of the second block once
//!   (`obenblock_stratum::hasher`); per nonce the rest, N nonces at a time
//!   in SIMD lanes (AVX-512, AVX2 or SSE2, chosen at run time), the outer
//!   hash stopped as soon as the id's top word is known.
//! * At start every kernel the CPU supports is measured and the fastest is
//!   used (`--kernel sha2|lanes4|avx2|avx512` forces one; `sha2` is the `sha2`
//!   crate per nonce, which uses SHA-NI where the CPU has it).
//! * Submits every hash that meets the easier of the share target and the
//!   block target, so a solo CPU miner never drops a block below its share
//!   difficulty; suggests a difficulty of about one share per 10 s
//!   (`mining.suggest_difficulty`); reconnects forever.
//! * `--bench SECS` measures every kernel on one thread, then the chosen
//!   one on `-t` threads at once, prints MH/s and exits.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use obenblock_stratum::hasher::{target_top_word, Kernel, Prepared};
use obenblock_stratum::job::NotifiedJob;
use obenblock_stratum::validator::{bits_to_target, difficulty_to_target, header80, meets_target, Target};
use serde_json::{json, Value};

/// Seconds per share the miner aims its suggested difficulty at.
const SHARE_SECS: f64 = 10.0;
/// Nonces per kernel call; also how often a lane looks for a new job.
const CHUNK: u32 = 1 << 16;

#[derive(Clone)]
struct Work {
    job: Arc<NotifiedJob>,
    en1: Vec<u8>,
    en2_size: usize,
    /// The easier of the share target and the block target.
    target: Target,
    block_target: Target,
    generation: u64,
}

struct Shared {
    work: Mutex<Option<Work>>,
    generation: AtomicU64,
    hashes: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    stop: AtomicBool,
    /// `--block-pause-ms`: no lane hashes before this instant (set after a
    /// block).
    resume_at: Mutex<Option<Instant>>,
}

struct Args {
    url: String,
    user: String,
    pass: String,
    threads: usize,
    once: bool,
    kernel: Option<Kernel>,
    bench: Option<f64>,
    /// After each block, every lane pauses this long (0: never).
    block_pause: Duration,
}

fn usage() -> ! {
    eprintln!("usage: obenblock-cpu-miner -o stratum+tcp://HOST:PORT -u <obb1 address>[.<worker>] [-p x] [-t THREADS] \
               [--kernel sha2|lanes4|avx2|avx512] [--block-pause-ms MS]\n       obenblock-cpu-miner --bench SECS [-t THREADS] [--kernel K]");
    std::process::exit(2);
}

fn parse_args() -> Args {
    let a: Vec<String> = std::env::args().collect();
    let mut args = Args {
        url: String::new(),
        user: String::new(),
        pass: "x".into(),
        threads: thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
        once: false,
        kernel: None,
        bench: None,
        block_pause: Duration::ZERO,
    };
    let mut i = 1;
    while i < a.len() {
        let val = || a.get(i + 1).cloned().unwrap_or_else(|| usage());
        match a[i].as_str() {
            "-o" | "--url" => { args.url = val(); i += 2; }
            "-u" | "--user" => { args.user = val(); i += 2; }
            "-p" | "--pass" => { args.pass = val(); i += 2; }
            "-t" | "--threads" => { args.threads = val().parse().unwrap_or_else(|_| usage()); i += 2; }
            "--kernel" => {
                let k = Kernel::parse(&val()).unwrap_or_else(|| usage());
                if !k.available() {
                    eprintln!("kernel {} is not supported by this CPU", k.name());
                    std::process::exit(2);
                }
                args.kernel = Some(k);
                i += 2;
            }
            "--bench" => { args.bench = Some(val().parse().unwrap_or_else(|_| usage())); i += 2; }
            // Exit instead of reconnecting when the connection ends (tests).
            // Pace a solo miner on a chain where about every hash is a block
            // (ObenBlock regtest, the launch rehearsal): at most one block per
            // pause, so the network runs at a block rate like mainnet's
            // relative to propagation, not thousands of blocks a minute.
            "--block-pause-ms" => {
                args.block_pause = Duration::from_millis(val().parse().unwrap_or_else(|_| usage()));
                i += 2;
            }
            "--once" => { args.once = true; i += 1; }
            "-h" | "--help" => usage(),
            other => { eprintln!("unknown argument {other}"); usage() }
        }
    }
    if args.threads == 0 || (args.bench.is_none() && (args.url.is_empty() || args.user.is_empty())) {
        usage();
    }
    args
}

/// Pick the kernel: the forced one, or the fastest measured.
fn choose_kernel(forced: Option<Kernel>, secs: f64, verbose: bool) -> Kernel {
    if let Some(k) = forced {
        return k;
    }
    let (best, rates) = Kernel::fastest(secs);
    if verbose {
        let list: Vec<String> = rates.iter().map(|(k, r)| format!("{} {:.2}", k.name(), r / 1e6)).collect();
        eprintln!("[miner] kernels (MH/s, one thread): {}; using {}", list.join(", "), best.name());
    }
    best
}

/// `--bench`: every kernel on one thread, then the chosen one on all threads.
fn bench(args: &Args, secs: f64) {
    for k in Kernel::available_all() {
        let mut runs: Vec<f64> = (0..3).map(|_| k.measure(secs / 3.0)).collect();
        runs.sort_by(|a, b| a.total_cmp(b));
        println!("kernel {:<7} 1 thread: {:.3} MH/s (median of 3)", k.name(), runs[1] / 1e6);
    }
    let k = choose_kernel(args.kernel, 0.3, false);
    let t0 = Instant::now();
    let rates: Vec<f64> = (0..args.threads)
        .map(|_| thread::spawn(move || k.measure(secs)))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    let total: f64 = rates.iter().sum();
    println!("kernel {:<7} {} threads: {:.2} MH/s total, {:.3} MH/s per thread ({:.1} s)", k.name(), args.threads,
             total / 1e6, total / 1e6 / args.threads as f64, t0.elapsed().as_secs_f64());
}

fn mine_lane(lane: u32, stride: u32, kernel: Kernel, shared: Arc<Shared>, submit: mpsc::Sender<String>, user: String,
             block_pause: Duration) {
    // Never reset, not even on a new job: a re-sent identical job must not
    // repeat work. Wraps after 2^32 / threads lanes per thread.
    let mut en2_counter: u64 = lane as u64;
    // After a block on a job, the lane waits for the next job: more blocks
    // on the same parents would only be siblings (and on regtest, where
    // about every other hash is a block, a flood).
    let mut done_gen = u64::MAX;
    let mut candidates: Vec<u32> = Vec::with_capacity(1024);
    while !shared.stop.load(Ordering::Relaxed) {
        let paused = shared.resume_at.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|t| Instant::now() < t);
        if paused {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let work = shared.work.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(w) = work.filter(|w| w.generation != done_gen) else {
            thread::sleep(Duration::from_millis(20));
            continue;
        };
        let en2: Vec<u8> = (0..w.en2_size).map(|k| (en2_counter >> (8 * (w.en2_size - 1 - k))) as u8).collect();
        en2_counter = en2_counter.wrapping_add(stride as u64);
        let job = &w.job;
        let root = job.merkle_root_for(&w.en1, &en2);
        let p = Prepared::new(&header80(job.version, &job.parents_commitment, &root, job.time, job.bits, 0));
        let top = target_top_word(&w.target.0);
        let en2_hex = hex::encode(&en2);
        let mut start: u64 = 0;
        'lane: while start < 1u64 << 32 {
            candidates.clear();
            kernel.scan(&p, start as u32, CHUNK, top, &mut candidates);
            for &nonce in &candidates {
                let id = p.id(nonce);
                if !meets_target(&id, &w.target) {
                    continue;
                }
                let line = json!({"id": 100 + (nonce as u64 % 1_000_000), "method": "mining.submit",
                    "params": [user, job.job_id, en2_hex, format!("{:08x}", job.time), format!("{nonce:08x}")]});
                let _ = submit.send(line.to_string());
                if meets_target(&id, &w.block_target) {
                    done_gen = w.generation;
                    if !block_pause.is_zero() {
                        *shared.resume_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + block_pause);
                    }
                    shared.hashes.fetch_add(CHUNK as u64, Ordering::Relaxed);
                    break 'lane;
                }
            }
            shared.hashes.fetch_add(CHUNK as u64, Ordering::Relaxed);
            if shared.generation.load(Ordering::Relaxed) != w.generation || shared.stop.load(Ordering::Relaxed) {
                break;
            }
            start += CHUNK as u64;
        }
    }
}

/// One connection, until it ends.
fn session(args: &Args, shared: &Arc<Shared>, writer: &Arc<Mutex<Option<TcpStream>>>, suggested: f64)
    -> Result<(), String>
{
    let addr = args.url.trim_start_matches("stratum+tcp://").trim_start_matches("tcp://").trim_end_matches('/');
    let stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_nodelay(true);
    let mut wr = stream.try_clone().map_err(|e| e.to_string())?;
    *writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream.try_clone().map_err(|e| e.to_string())?);
    let mut send = |v: Value| -> Result<(), String> {
        wr.write_all(format!("{v}\n").as_bytes()).map_err(|e| e.to_string())
    };
    send(json!({"id": 2, "method": "mining.subscribe", "params": [format!("obenblock-cpu-miner/{}", env!("CARGO_PKG_VERSION"))]}))?;
    send(json!({"id": 3, "method": "mining.suggest_difficulty", "params": [suggested]}))?;
    send(json!({"id": 4, "method": "mining.authorize", "params": [args.user, args.pass]}))?;
    eprintln!("[miner] connected to {addr}");

    let mut rd = BufReader::new(stream);
    let mut en1: Vec<u8> = Vec::new();
    let mut en2_size = 4usize;
    let mut share_diff = suggested;
    let mut line = String::new();
    loop {
        line.clear();
        match rd.read_line(&mut line) {
            Ok(0) => return Err("server closed the connection".into()),
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        let id = v.get("id").and_then(Value::as_u64);
        match v.get("method").and_then(Value::as_str) {
            Some("mining.set_difficulty") => {
                if let Some(d) = v["params"][0].as_f64() {
                    share_diff = d;
                }
            }
            Some("mining.notify") => match NotifiedJob::parse(&v["params"]) {
                Ok(job) => {
                    let block_target = bits_to_target(job.bits);
                    let share_target = difficulty_to_target(share_diff);
                    let target = if block_target > share_target { block_target } else { share_target };
                    let generation = shared.generation.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!("[miner] job {} bits {:08x} difficulty {share_diff}", job.job_id, job.bits);
                    *shared.work.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(Work { job: Arc::new(job), en1: en1.clone(), en2_size, target, block_target, generation });
                }
                Err(e) => eprintln!("[miner] unusable job: {e}"),
            },
            Some(_) => {}
            None => match id {
                Some(2) => {
                    en1 = v["result"][1].as_str().and_then(|s| hex::decode(s).ok()).unwrap_or_default();
                    en2_size = v["result"][2].as_u64().unwrap_or(4) as usize;
                    if en2_size == 0 || en2_size > 8 {
                        return Err(format!("unsupported extranonce2 size {en2_size}"));
                    }
                }
                Some(4) => {
                    if v["result"] != json!(true) {
                        return Err(format!("authorization refused: {}", v["error"]));
                    }
                }
                Some(n) if n >= 100 => {
                    if v["result"] == json!(true) {
                        shared.accepted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        shared.rejected.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[miner] share rejected: {}", v["error"]);
                    }
                }
                _ => {}
            },
        }
    }
}

fn main() {
    let args = parse_args();
    if let Some(secs) = args.bench {
        bench(&args, secs);
        return;
    }
    let kernel = choose_kernel(args.kernel, 0.2, true);
    let per_thread = kernel.measure(0.3);
    let rate = per_thread * args.threads as f64;
    let suggested = (rate * SHARE_SECS / 4_294_967_296.0).max(1e-9);
    eprintln!("[miner] {} threads ({}), about {:.1} MH/s, suggesting difficulty {suggested:.6}", args.threads,
              kernel.name(), rate / 1e6);
    let shared = Arc::new(Shared {
        work: Mutex::new(None),
        generation: AtomicU64::new(0),
        hashes: AtomicU64::new(0),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        resume_at: Mutex::new(None),
    });
    let writer: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
    let (subtx, subrx) = mpsc::channel::<String>();
    {
        let writer = writer.clone();
        thread::spawn(move || {
            for line in subrx {
                if let Some(s) = writer.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                    let _ = s.write_all(format!("{line}\n").as_bytes());
                }
            }
        });
    }
    for lane in 0..args.threads {
        let (shared, subtx, user) = (shared.clone(), subtx.clone(), args.user.clone());
        let stride = args.threads as u32;
        let pause = args.block_pause;
        thread::spawn(move || mine_lane(lane as u32, stride, kernel, shared, subtx, user, pause));
    }
    {
        let shared = shared.clone();
        thread::spawn(move || {
            let mut last = (Instant::now(), 0u64);
            loop {
                thread::sleep(Duration::from_secs(30));
                let h = shared.hashes.load(Ordering::Relaxed);
                let dt = last.0.elapsed().as_secs_f64();
                eprintln!("[miner] {:.1} MH/s, shares accepted {} rejected {}", (h - last.1) as f64 / dt / 1e6,
                          shared.accepted.load(Ordering::Relaxed), shared.rejected.load(Ordering::Relaxed));
                last = (Instant::now(), h);
            }
        });
    }
    loop {
        let r = session(&args, &shared, &writer, suggested);
        *shared.work.lock().unwrap_or_else(|e| e.into_inner()) = None;
        shared.generation.fetch_add(1, Ordering::SeqCst);
        *writer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        match r {
            Ok(()) => {}
            Err(e) => eprintln!("[miner] {e}"),
        }
        if args.once {
            shared.stop.store(true, Ordering::Relaxed);
            std::process::exit(1);
        }
        thread::sleep(Duration::from_secs(5));
    }
}
