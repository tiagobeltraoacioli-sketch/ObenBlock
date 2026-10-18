//! obenblock-cpu-miner: a multi-threaded SHA-256d CPU miner for ObenBlock
//! that mines through the stratum server, like the ASICs (ported from the
//! Bloch proxy's rehearsal miner).
//!
//! ```text
//! obenblock-cpu-miner -o stratum+tcp://HOST:3333 -u <obb1 address>[.<worker>] [-p x] [-t THREADS]
//! ```
//!
//! * All logical CPUs by default (`-t` to choose); each thread owns its own
//!   extranonce2 lane (thread i takes extranonce2 = i, i + T, i + 2T, ...), so
//!   threads never repeat work, and the server's unique extranonce1 keeps
//!   machines apart.
//! * Per extranonce2: the coinbase txid, ObenBlock's header root
//!   (`obenblock-root` stratum extension), the 80-byte header and its SHA-256
//!   midstate once; per nonce only the second block and the outer SHA-256.
//! * Submits every hash that meets the easier of the share target and the
//!   block target, so a solo CPU miner never drops a block below its share
//!   difficulty.
//! * Benchmarks itself at start and suggests a difficulty of about one share
//!   per 10 s (`mining.suggest_difficulty`); reconnects forever.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use obenblock_stratum::job::NotifiedJob;
use obenblock_stratum::session::OBENBLOCK_ROOT_EXTENSION;
use obenblock_stratum::validator::{
    bits_to_target, difficulty_to_target, header80, id_from_midstate, meets_target, midstate, tail_block, Target,
};
use serde_json::{json, Value};

/// Seconds per share the miner aims its suggested difficulty at.
const SHARE_SECS: f64 = 10.0;
/// Nonces between checks for a new job.
const CHECK_EVERY: u32 = 1 << 16;

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
}

struct Args {
    url: String,
    user: String,
    pass: String,
    threads: usize,
    once: bool,
}

fn usage() -> ! {
    eprintln!("usage: obenblock-cpu-miner -o stratum+tcp://HOST:PORT -u <obb1 address>[.<worker>] [-p x] [-t THREADS]");
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
    };
    let mut i = 1;
    while i < a.len() {
        let val = || a.get(i + 1).cloned().unwrap_or_else(|| usage());
        match a[i].as_str() {
            "-o" | "--url" => { args.url = val(); i += 2; }
            "-u" | "--user" => { args.user = val(); i += 2; }
            "-p" | "--pass" => { args.pass = val(); i += 2; }
            "-t" | "--threads" => { args.threads = val().parse().unwrap_or_else(|_| usage()); i += 2; }
            // Exit instead of reconnecting when the connection ends (tests).
            "--once" => { args.once = true; i += 1; }
            "-h" | "--help" => usage(),
            other => { eprintln!("unknown argument {other}"); usage() }
        }
    }
    if args.url.is_empty() || args.user.is_empty() || args.threads == 0 {
        usage();
    }
    args
}

/// Hashes per second of one thread (midstate path), measured for `secs`.
fn bench_one_thread(secs: f64) -> f64 {
    let h = header80(0x2000_0000, &[1; 32], &[2; 32], 1_800_000_000, 0x1d00_ffff, 0);
    let mid = midstate(&h);
    let mut tail = tail_block(&h);
    let t0 = Instant::now();
    let mut n: u64 = 0;
    let mut acc = 0u8;
    while t0.elapsed().as_secs_f64() < secs {
        for _ in 0..4096u32 {
            tail[12..16].copy_from_slice(&(n as u32).to_le_bytes());
            acc ^= id_from_midstate(&mid, &tail)[0];
            n += 1;
        }
    }
    std::hint::black_box(acc);
    n as f64 / t0.elapsed().as_secs_f64()
}

fn mine_lane(lane: u32, stride: u32, shared: Arc<Shared>, submit: mpsc::Sender<String>, user: String) {
    // Never reset, not even on a new job: a re-sent identical job must not
    // repeat work. Wraps after 2^32 / threads lanes per thread.
    let mut en2_counter: u64 = lane as u64;
    // After a block on a job, the lane waits for the next job: more blocks
    // on the same parents would only be siblings (and on regtest, where
    // about every other hash is a block, a flood).
    let mut done_gen = u64::MAX;
    while !shared.stop.load(Ordering::Relaxed) {
        let work = shared.work.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(w) = work.filter(|w| w.generation != done_gen) else {
            thread::sleep(Duration::from_millis(20));
            continue;
        };
        let en2: Vec<u8> = (0..w.en2_size).map(|k| (en2_counter >> (8 * (w.en2_size - 1 - k))) as u8).collect();
        en2_counter = en2_counter.wrapping_add(stride as u64);
        let job = &w.job;
        let root = job.merkle_root_for(&w.en1, &en2);
        let header = header80(job.version, &job.parents_commitment, &root, job.time, job.bits, 0);
        let mid = midstate(&header);
        let mut tail = tail_block(&header);
        let en2_hex = hex::encode(&en2);
        let mut nonce: u32 = 0;
        loop {
            tail[12..16].copy_from_slice(&nonce.to_le_bytes());
            let id = id_from_midstate(&mid, &tail);
            if meets_target(&id, &w.target) {
                let line = json!({"id": 100 + (nonce as u64 % 1_000_000), "method": "mining.submit",
                    "params": [user, job.job_id, en2_hex, format!("{:08x}", job.time), format!("{nonce:08x}")]});
                let _ = submit.send(line.to_string());
                if meets_target(&id, &w.block_target) {
                    done_gen = w.generation;
                    break;
                }
            }
            if nonce % CHECK_EVERY == CHECK_EVERY - 1 {
                shared.hashes.fetch_add(CHECK_EVERY as u64, Ordering::Relaxed);
                if shared.generation.load(Ordering::Relaxed) != w.generation || shared.stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            if nonce == u32::MAX {
                break; // lane exhausted: next extranonce2
            }
            nonce += 1;
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
    send(json!({"id": 1, "method": "mining.configure", "params": [[OBENBLOCK_ROOT_EXTENSION], {}]}))?;
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
                Some(1) => {
                    if v["result"][OBENBLOCK_ROOT_EXTENSION] != json!(true) {
                        return Err(format!("the server did not grant the {OBENBLOCK_ROOT_EXTENSION} extension: \
                                            not an ObenBlock stratum server"));
                    }
                }
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
    let per_thread = bench_one_thread(0.5);
    let rate = per_thread * args.threads as f64;
    let suggested = (rate * SHARE_SECS / 4_294_967_296.0).max(1e-9);
    eprintln!("[miner] {} threads, about {:.1} MH/s, suggesting difficulty {suggested:.6}", args.threads, rate / 1e6);

    let shared = Arc::new(Shared {
        work: Mutex::new(None),
        generation: AtomicU64::new(0),
        hashes: AtomicU64::new(0),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        stop: AtomicBool::new(false),
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
        thread::spawn(move || mine_lane(lane as u32, stride, shared, subtx, user));
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
