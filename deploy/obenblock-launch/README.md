# ObenBlock mainnet launch kit

This kit launches ObenBlock mainnet on three servers, step by step from
the Mac. The procedure is in [LAUNCH-RUNBOOK.md](LAUNCH-RUNBOOK.md).

```
cp kit.conf.example kit.conf
./obb-launch.sh preflight
./obb-launch.sh genesis --rehearsal
./obb-launch.sh genesis
./obb-launch.sh build
./obb-launch.sh deploy
./obb-launch.sh explorer-tls
./obb-launch.sh start
./obb-launch.sh verify
```

| File | Runs on | Purpose |
| --- | --- | --- |
| `obb-launch.sh` | Mac | The steps: preflight, genesis, build, deploy, explorer-tls, start, verify, logs, stop, rollback, remove |
| `kit.conf.example` | Mac | Hosts, owner address, launch time, ports |
| `lib/common.sh` | Mac | SSH, scp and rsync for key hosts; expect for the password host |
| `lib/pw-ssh.exp` | Mac | Password login (`ssh -tt`, sudo prompts); never installs a key |
| `lib/apply_genesis.py` | Mac, build host | Writes the mined constants over the LAUNCH PLACEHOLDER |
| `lib/check_address.py` | Mac | Checks the owner address with the reference codec |
| `lib/verify_summary.py` | Mac | Checks the hosts' status against the plan |
| `lib/first_blocks.py` | anywhere | First-block timing for a given hashrate |
| `host/genesis-build.sh` | build host | Mines, writes, rewrites the vectors, runs the genesis tests |
| `host/release-build.sh` | build host | Builds the release binaries and the bundle with `SHA256SUMS` |
| `host/install.sh` | each host (sudo) | Users, directories, env files, keys, units, ufw; starts nothing |
| `host/obenblock-launch` | each host | Builds the node's command line from `/etc/obenblock/obenblock.env` |
| `host/obenblock-stratum-launch` | 136 | Builds the stratum proxy's command line from `/etc/obenblock/stratum.env` |
| `host/*.service` | each host | `obenblock-node`, `obenblock-explorer-api`, `obenblock-stratum` |
| `host/explorer-tls.sh` | each host (sudo) | Let's Encrypt certificate for the sslip.io origin |
| `host/status.py` | each host | Status as one JSON line |
| `host/rollback.sh` | each host (sudo) | stop, previous, remove |
| `rehearse-regtest.sh` | build host | The whole kit in regtest, without systemd or root |
| `test_launch_kit.py` | anywhere | Kit tests (Linux runs all of them) |

`state/` (created on first use, never committed) holds:

- the release tarballs;
- the logs;
- the genesis result;
- the explorer API shared secret.
