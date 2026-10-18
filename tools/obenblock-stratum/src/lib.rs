//! obenblock-stratum: a Stratum V1 job server (solo pool) for ObenBlock's
//! SHA-256d proof of work, and the library of `obenblock-cpu-miner`.
//! README.md has the operator guide; docs/OBENBLOCK-MINING.md (repository
//! root) the node interface it speaks.
pub mod addr;
pub mod codec;
pub mod extranonce;
#[doc(hidden)]
pub mod fixtures;
pub mod job;
pub mod jobstore;
pub mod metrics;
pub mod pplns;
pub mod rpc;
pub mod server;
pub mod session;
pub mod template;
pub mod types;
pub mod validator;
pub mod vardiff;
