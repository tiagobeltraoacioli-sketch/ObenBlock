//! Noise NX handshake, responder (server) side.
//!
//! The initiator sends act 1 (64 bytes: its ElligatorSwift-encoded ephemeral
//! key); the responder answers act 2 (234 bytes: its ephemeral key, its
//! encrypted static key and the encrypted SIGNATURE_NOISE_MESSAGE, a
//! certificate of the static key signed by the authority key) and both sides
//! switch to transport mode. The cryptography (ECDH over secp256k1, the
//! certificate, ChaCha20-Poly1305, zeroization) is SRI's `noise_sv2::Responder`;
//! this module feeds it the socket bytes under a timeout and runs the
//! responder on the blocking pool (the listener caps concurrent handshakes,
//! `MAX_CONCURRENT_HANDSHAKES`). Ported from the
//! legacy Bloch server (genesis3-node `src/stratum_v2/handshake.rs`).

use std::time::Duration;

use noise_sv2::{NoiseCodec, Responder, ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::keypair::AuthorityKeypair;
use super::Sv2Error;

/// Total time allowed for the handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Validity of the per-session certificate (from the handshake time).
pub const DEFAULT_CERT_VALIDITY_SECS: u32 = 30 * 86_400;

/// Act 1 size (initiator's ephemeral key).
pub const ACT1_SIZE: usize = ELLSWIFT_ENCODING_SIZE;

/// Act 2 size (responder's answer).
pub const ACT2_SIZE: usize = INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE;

/// Run the responder side of Noise NX on `stream`, returning the transport
/// codec.
pub async fn perform_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authority: &AuthorityKeypair,
    cert_validity_secs: u32,
    timeout_after: Duration,
) -> Result<NoiseCodec, Sv2Error> {
    timeout(timeout_after, async {
        let mut act1 = [0u8; ACT1_SIZE];
        stream.read_exact(&mut act1).await?;
        // The secp256k1 work (a static key, an ElligatorSwift ECDH, a BIP 340
        // certificate signature) runs on the blocking pool, not on a runtime
        // worker shared with P2P, RPC and finality.
        let public = authority.public;
        let secret = zeroize::Zeroizing::new(*authority.secret());
        let (act2, codec) = tokio::task::spawn_blocking(move || {
            let mut responder = Responder::from_authority_kp(&public, &secret, Duration::from_secs(cert_validity_secs as u64))
                .map_err(|e| Sv2Error::Keypair(format!("noise responder: {e:?}")))?;
            responder.step_1(act1).map_err(|e| Sv2Error::Keypair(format!("noise step 1: {e:?}")))
        })
        .await
        .map_err(|e| Sv2Error::Keypair(format!("handshake task: {e}")))??;
        stream.write_all(&act2).await?;
        stream.flush().await?;
        Ok::<_, Sv2Error>(codec)
    })
    .await
    .map_err(|_| Sv2Error::Keypair("handshake timeout".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use noise_sv2::Initiator;
    use tokio::net::{TcpListener, TcpStream};

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (b, _) = l.accept().await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn handshake_happy_path_and_transport_round_trip() {
        let auth = AuthorityKeypair::generate();
        let public = auth.public;
        let (mut client, mut server) = pair().await;
        let srv = tokio::spawn(async move {
            perform_handshake(&mut server, &auth, DEFAULT_CERT_VALIDITY_SECS, Duration::from_secs(5)).await
                .map(|c| (c, server))
        });
        let mut initiator = Initiator::from_raw_k(public).expect("initiator pins the authority key");
        client.write_all(&initiator.step_0().unwrap()).await.unwrap();
        let mut act2 = [0u8; ACT2_SIZE];
        client.read_exact(&mut act2).await.unwrap();
        let mut client_codec = initiator.step_2(act2).expect("the certificate verifies against the pinned key");
        let (mut server_codec, _server) = srv.await.unwrap().expect("server handshake");

        let mut msg = b"hello".to_vec();
        client_codec.encrypt(&mut msg).unwrap();
        server_codec.decrypt(&mut msg).unwrap();
        assert_eq!(msg, b"hello");
    }

    #[tokio::test]
    async fn a_client_pinning_another_key_refuses_the_server() {
        let auth = AuthorityKeypair::generate();
        let other = AuthorityKeypair::generate();
        let (mut client, mut server) = pair().await;
        tokio::spawn(async move {
            let _ = perform_handshake(&mut server, &auth, DEFAULT_CERT_VALIDITY_SECS, Duration::from_secs(5)).await;
        });
        let mut initiator = Initiator::from_raw_k(other.public).unwrap();
        client.write_all(&initiator.step_0().unwrap()).await.unwrap();
        let mut act2 = [0u8; ACT2_SIZE];
        client.read_exact(&mut act2).await.unwrap();
        assert!(initiator.step_2(act2).is_err(), "the certificate is not signed by the pinned key");
    }

    #[tokio::test]
    async fn handshake_rejects_short_act1() {
        let auth = AuthorityKeypair::generate();
        let (mut client, mut server) = pair().await;
        let srv = tokio::spawn(async move {
            perform_handshake(&mut server, &auth, DEFAULT_CERT_VALIDITY_SECS, Duration::from_secs(2)).await.map(|_| ())
        });
        client.write_all(&[0u8; 30]).await.unwrap();
        drop(client);
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn handshake_times_out_on_a_silent_client() {
        let auth = AuthorityKeypair::generate();
        let (_client, mut server) = pair().await;
        let r = perform_handshake(&mut server, &auth, DEFAULT_CERT_VALIDITY_SECS, Duration::from_millis(200)).await;
        let e = r.map(|_| ()).unwrap_err().to_string();
        assert!(e.contains("timeout"), "{e}");
    }
}
