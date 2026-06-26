// Software Solana off-chain message (OCMS) sign + keyless verify, the ed25519
// sibling of the Tron/Bitcoin message cores. Shared by iOS, Android, and BOTH
// hardware flows (Ledger + Trezor) so every wallet produces byte-identical
// output.
//
// Format: the hardware "Off-Chain Message" envelope (SIMD-0048), the one the
// Ledger Solana app (SIGN_OFFCHAIN_MESSAGE, INS 0x07) and Trezor firmware
// (SolanaSignMessage) both parse and sign. NOT the simplified solana-sdk
// `OffchainMessage` (which omits the application domain + signers list), and NOT
// Phantom's raw `signMessage`. The serialized envelope is:
//
//   "\xffsolana offchain"  (16-byte signing domain)
//   version                (1 byte, 0)
//   application_domain     (32 bytes, all-zero here)
//   message_format         (1 byte: 0 = ASCII, 1 = UTF-8)
//   signer_count           (1 byte, 1)
//   signers                (signer_count x 32-byte ed25519 pubkey)
//   message_length         (u16 little-endian)
//   message                (message_length bytes)
//
// ed25519 has no signature recovery, so the signer pubkey is carried in the
// signers list and `verify` always needs the address (which IS the base58
// pubkey). Both devices sign these exact host-built bytes RAW and validate that
// the device-derived pubkey appears in the signers list. So we build the
// envelope once (here / via `sol_offchain_envelope`) and feed identical bytes
// to software ed25519, Ledger, and Trezor: the 64-byte ed25519 signature is
// deterministic (RFC 8032), so all three agree byte-for-byte.
//
// Software wallets derive the 32-byte SLIP-0010 ed25519 secret at
// m/44'/501'/<account>'/0' (WalletCore on iOS, BouncyCastle on Android) and
// hand it to `sol_sign_message`. Hardware flows call `sol_offchain_envelope`
// with the device pubkey, send the bytes to the device, then assemble the
// result with `sol_hardware_signed_message`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// 0xff + "solana offchain" = 16 bytes.
const SIGNING_DOMAIN: &[u8] = b"\xffsolana offchain";
/// v0 application domain. Any 32 bytes are accepted by both devices; we use the
/// neutral all-zero domain so sign + verify (and all three wallet types) agree.
const APP_DOMAIN: [u8; 32] = [0u8; 32];
/// Both devices treat the short (ASCII/UTF-8) form as a single packet capped at
/// 1232 serialized bytes. Our attestation messages are tiny; reject anything
/// that would overflow the short form rather than silently switch to long/v1.
const MAX_ENVELOPE_LEN: usize = 1232;

/// A Solana OCMS signed message: the base58 ed25519 address it binds to and the
/// base58 64-byte signature (Solana's everywhere-encoding).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SolanaSignedMessage {
    /// base58 ed25519 public key the signature is bound to (the wallet address).
    pub address: String,
    /// base58-encoded 64-byte ed25519 signature.
    pub signature: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SolanaMsgError {
    #[error("invalid ed25519 key")]
    InvalidKey,
    #[error("invalid signer public key")]
    InvalidPubkey,
    #[error("message too long for the off-chain short form")]
    MessageTooLong,
    #[error("signing failed")]
    SigningFailed,
}

/// 0 = ASCII (all printable ASCII), 1 = UTF-8. We never emit format 2
/// (long/v1), keeping the envelope inside the short form both devices accept.
fn message_format(message: &[u8]) -> u8 {
    if message.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        0
    } else {
        1
    }
}

/// Build the SIMD-0048 off-chain message envelope for a single signer. This is
/// the exact byte string that gets ed25519-signed by software AND by the
/// devices.
fn build_envelope(message: &[u8], signer_pubkey: &[u8; 32]) -> Result<Vec<u8>, SolanaMsgError> {
    if message.len() > u16::MAX as usize {
        return Err(SolanaMsgError::MessageTooLong);
    }
    let mut v = Vec::with_capacity(16 + 1 + 32 + 1 + 1 + 32 + 2 + message.len());
    v.extend_from_slice(SIGNING_DOMAIN); // 16
    v.push(0); // version 0
    v.extend_from_slice(&APP_DOMAIN); // 32
    v.push(message_format(message)); // 1
    v.push(1); // signer_count
    v.extend_from_slice(signer_pubkey); // 32
    v.extend_from_slice(&(message.len() as u16).to_le_bytes()); // 2 (LE)
    v.extend_from_slice(message);
    if v.len() > MAX_ENVELOPE_LEN {
        return Err(SolanaMsgError::MessageTooLong);
    }
    Ok(v)
}

/// Sign `message` (software path) with the raw 32-byte SLIP-0010 ed25519 secret.
#[uniffi::export]
pub fn sol_sign_message(
    secret_seed: Vec<u8>,
    message: String,
) -> Result<SolanaSignedMessage, SolanaMsgError> {
    let seed: [u8; 32] = secret_seed
        .as_slice()
        .try_into()
        .map_err(|_| SolanaMsgError::InvalidKey)?;
    let sk = SigningKey::from_bytes(&seed);
    let pubkey = sk.verifying_key().to_bytes();
    let envelope = build_envelope(message.as_bytes(), &pubkey)?;
    let sig = sk.sign(&envelope);
    Ok(SolanaSignedMessage {
        address: bs58::encode(pubkey).into_string(),
        signature: bs58::encode(sig.to_bytes()).into_string(),
    })
}

/// Verify an OCMS signature against the base58 address (keyless). Rebuilds the
/// envelope from the recovered pubkey + message and ed25519-verifies.
#[uniffi::export]
pub fn sol_verify_message(address: String, message: String, signature: String) -> bool {
    verify_inner(&address, &message, &signature).unwrap_or(false)
}

fn verify_inner(address: &str, message: &str, signature: &str) -> Option<bool> {
    let pk_bytes: [u8; 32] = bs58::decode(address.trim())
        .into_vec()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).ok()?;
    let sig_bytes: [u8; 64] = bs58::decode(signature.trim())
        .into_vec()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let envelope = build_envelope(message.as_bytes(), &pk_bytes).ok()?;
    Some(vk.verify(&envelope, &sig).is_ok())
}

/// Build the exact OCMS envelope bytes the host sends to a hardware device
/// (Ledger SIGN_OFFCHAIN_MESSAGE / Trezor SolanaSignMessage), given the device's
/// 32-byte ed25519 pubkey. The device signs these bytes raw.
#[uniffi::export]
pub fn sol_offchain_envelope(
    message: String,
    signer_pubkey: Vec<u8>,
) -> Result<Vec<u8>, SolanaMsgError> {
    let pk: [u8; 32] = signer_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| SolanaMsgError::InvalidPubkey)?;
    build_envelope(message.as_bytes(), &pk)
}

/// Assemble a `SolanaSignedMessage` from a hardware device's output: the signer
/// pubkey (32 bytes) and the device-returned 64-byte signature. Keeps the
/// base58 formatting identical to the software path.
#[uniffi::export]
pub fn sol_hardware_signed_message(
    signer_pubkey: Vec<u8>,
    signature: Vec<u8>,
) -> Result<SolanaSignedMessage, SolanaMsgError> {
    if signer_pubkey.len() != 32 {
        return Err(SolanaMsgError::InvalidPubkey);
    }
    if signature.len() != 64 {
        return Err(SolanaMsgError::SigningFailed);
    }
    Ok(SolanaSignedMessage {
        address: bs58::encode(signer_pubkey).into_string(),
        signature: bs58::encode(signature).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed 32-byte ed25519 seed -> deterministic address + round-trip.
    fn seed() -> Vec<u8> {
        vec![0x11u8; 32]
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let signed = sol_sign_message(seed(), "hello solana".into()).unwrap();
        // base58 ed25519 pubkey + 64-byte sig.
        assert!(!signed.address.is_empty());
        assert!(!signed.signature.is_empty());
        assert!(sol_verify_message(
            signed.address.clone(),
            "hello solana".into(),
            signed.signature.clone()
        ));
        // Tampered message must fail.
        assert!(!sol_verify_message(
            signed.address,
            "hello solan".into(),
            signed.signature
        ));
    }

    #[test]
    fn hardware_envelope_matches_software() {
        // The bytes a device would sign must equal what the software path signs.
        let seed_arr: [u8; 32] = seed().as_slice().try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed_arr);
        let pubkey = sk.verifying_key().to_bytes();
        let env = sol_offchain_envelope("attest".into(), pubkey.to_vec()).unwrap();
        // Signing that envelope by hand == sol_sign_message's signature.
        let want = sol_sign_message(seed(), "attest".into()).unwrap();
        let got = sol_hardware_signed_message(pubkey.to_vec(), sk.sign(&env).to_bytes().to_vec())
            .unwrap();
        assert_eq!(got.address, want.address);
        assert_eq!(got.signature, want.signature);
    }

    #[test]
    fn envelope_layout() {
        let pk = [0x22u8; 32];
        let env = build_envelope(b"hi", &pk).unwrap();
        assert_eq!(&env[..16], b"\xffsolana offchain");
        assert_eq!(env[16], 0); // version
        assert_eq!(&env[17..49], &[0u8; 32]); // app domain
        assert_eq!(env[49], 0); // format ASCII
        assert_eq!(env[50], 1); // signer count
        assert_eq!(&env[51..83], &pk); // signer
        assert_eq!(&env[83..85], &[2, 0]); // len = 2, LE
        assert_eq!(&env[85..], b"hi");
    }

    #[test]
    fn verify_rejects_garbage() {
        assert!(!sol_verify_message(
            "11111111111111111111111111111111".into(),
            "x".into(),
            "deadbeef".into()
        ));
    }

    // Cross-platform known-answer vector (the same corpus iOS + Android assert).
    const KAT: &str = include_str!("../test-vectors/solana-message-signing-kat.json");

    #[test]
    fn solana_kat_corpus_matches() {
        let v: serde_json::Value = serde_json::from_str(KAT).unwrap();
        let s = &v["solana"];
        let seed = hex::decode(s["secretKeyHex"].as_str().unwrap()).unwrap();
        let msg = s["message"].as_str().unwrap().to_string();
        let want_addr = s["expectedAddress"].as_str().unwrap();
        let want_sig = s["expectedSignature"].as_str().unwrap();

        let signed = sol_sign_message(seed, msg.clone()).unwrap();
        assert_eq!(signed.address, want_addr);
        assert_eq!(signed.signature, want_sig);
        assert!(sol_verify_message(
            want_addr.to_string(),
            msg,
            want_sig.to_string()
        ));
    }
}
