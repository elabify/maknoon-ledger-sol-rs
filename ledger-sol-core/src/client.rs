use std::sync::Arc;

use crate::error::LedgerSolError;
use crate::transport::SolanaLedgerTransport;
use crate::types::SolanaSignature;

// Solana app APDU constants. Source of truth:
// https://github.com/LedgerHQ/app-solana/blob/develop/internal docs
// Cross-checked against @ledgerhq/hw-app-solana (TypeScript reference).
const CLA: u8 = 0xE0;
const INS_GET_APP_CONFIG: u8 = 0x04;
const INS_GET_PUBKEY: u8 = 0x05;
const INS_SIGN_MESSAGE: u8 = 0x06;
const INS_SIGN_OFFCHAIN_MESSAGE: u8 = 0x07;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;

// Continuation bits for chunked SIGN_MESSAGE / SIGN_OFFCHAIN_MESSAGE.
const P2_EXTEND: u8 = 0x01;
const P2_MORE: u8 = 0x02;

// APDU max data size in a single command. Solana app uses the
// standard 255-byte short-frame ceiling.
const MAX_APDU_DATA: usize = 255;

const SW_SUCCESS: u16 = 0x9000;

/// Top-level client for the Ledger Solana app. Construct once per
/// device session, then call any number of `get_app_configuration`,
/// `get_public_key`, `sign_transaction`, or `sign_offchain_message`
/// methods.
///
/// Thread-safe: methods take `&self` and the foreign transport
/// naturally serializes concurrent calls (BLE allows one in-flight
/// APDU exchange at a time).
#[derive(uniffi::Object)]
pub struct LedgerSolanaClient {
    transport: Arc<dyn SolanaLedgerTransport>,
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerSolanaClient {
    /// Construct a new client backed by the given transport.
    #[uniffi::constructor]
    pub fn new(transport: Arc<dyn SolanaLedgerTransport>) -> Arc<Self> {
        Arc::new(Self { transport })
    }

    /// Returns the Solana app version on-device as a triple
    /// `(major, minor, patch)` packed into a `Vec<u8>` of length 3.
    /// The first response byte carries config flags which we
    /// discard; callers that need them can call the device directly.
    pub async fn get_app_configuration(&self) -> Result<Vec<u8>, LedgerSolError> {
        let response = self
            .exchange(CLA, INS_GET_APP_CONFIG, 0x00, 0x00, &[])
            .await?;
        if response.len() < 4 {
            return Err(LedgerSolError::protocol(format!(
                "GET_APP_CONFIG: expected ≥4 bytes, got {}",
                response.len()
            )));
        }
        // Layout: [flags, major, minor, patch]
        Ok(vec![response[1], response[2], response[3]])
    }

    /// Returns the Ed25519 public key for the given BIP44 account
    /// at the standard Solana path `m/44'/501'/{account}'/0'`.
    ///
    /// Output is the raw 32-byte pubkey plus the same key encoded
    /// as a base58 Solana address. `display = true` prompts the
    /// user on-device to confirm the address before returning.
    pub async fn get_address_for_account(
        &self,
        account: u32,
        display: bool,
    ) -> Result<SolanaAddress, LedgerSolError> {
        let components = standard_solana_path(account);
        self.get_address_inner(&components, display).await
    }

    /// Returns the Ed25519 public key at an explicit BIP-32 path.
    /// Path syntax follows BIP-32 with `'` for hardened: e.g.
    /// `"m/44'/501'/0'/0'"`. Empty `m/` returns the master key.
    pub async fn get_address_at_path(
        &self,
        path: String,
        display: bool,
    ) -> Result<SolanaAddress, LedgerSolError> {
        let components = parse_bip32_path(&path)?;
        self.get_address_inner(&components, display).await
    }

    /// Sign a Solana transaction message at the standard BIP44
    /// account path `m/44'/501'/{account}'/0'`. The `message` is
    /// the wire-format Solana message (NOT a serialized
    /// Transaction, which prepends signature slots).
    ///
    /// Returns the 64-byte Ed25519 signature; the caller assembles
    /// the full Transaction by placing it in the signature slot
    /// for the corresponding signer pubkey.
    pub async fn sign_transaction_for_account(
        &self,
        account: u32,
        message: Vec<u8>,
    ) -> Result<SolanaSignature, LedgerSolError> {
        let components = standard_solana_path(account);
        self.sign_inner(INS_SIGN_MESSAGE, &components, &message)
            .await
    }

    /// Sign a Solana transaction message at an explicit BIP-32
    /// path. See `sign_transaction_for_account` for semantics.
    pub async fn sign_transaction_at_path(
        &self,
        path: String,
        message: Vec<u8>,
    ) -> Result<SolanaSignature, LedgerSolError> {
        let components = parse_bip32_path(&path)?;
        self.sign_inner(INS_SIGN_MESSAGE, &components, &message)
            .await
    }

    /// Sign an off-chain message (SIP-1) at the given BIP-32 path.
    /// Used for proving wallet control without on-chain activity.
    /// Payload format is application-defined per SIP-1; the
    /// device will display a hash-of-message if it can't be
    /// safely rendered as text.
    pub async fn sign_offchain_message_at_path(
        &self,
        path: String,
        message: Vec<u8>,
    ) -> Result<SolanaSignature, LedgerSolError> {
        let components = parse_bip32_path(&path)?;
        self.sign_inner(INS_SIGN_OFFCHAIN_MESSAGE, &components, &message)
            .await
    }
}

/// Public address record returned by `get_address_*`. Carries
/// both the raw bytes and the base58 form that Solana CLI /
/// JSON-RPC use everywhere.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SolanaAddress {
    /// Raw 32-byte Ed25519 public key.
    pub pubkey: Vec<u8>,
    /// Base58 representation. This is the user-visible address.
    pub base58: String,
}

impl LedgerSolanaClient {
    /// Shared body for the two `get_address_*` entry points. Takes
    /// already-parsed path components so the public API can either
    /// build them from an account number or parse a path string.
    async fn get_address_inner(
        &self,
        components: &[u32],
        display: bool,
    ) -> Result<SolanaAddress, LedgerSolError> {
        let payload = encode_path(components);
        let p1 = if display { P1_CONFIRM } else { P1_NON_CONFIRM };
        let response = self
            .exchange(CLA, INS_GET_PUBKEY, p1, 0x00, &payload)
            .await?;
        if response.len() < 32 {
            return Err(LedgerSolError::protocol(format!(
                "GET_PUBKEY: expected ≥32 bytes, got {}",
                response.len()
            )));
        }
        let pubkey_bytes = response[..32].to_vec();
        let base58 = bs58::encode(&pubkey_bytes).into_string();
        Ok(SolanaAddress {
            pubkey: pubkey_bytes,
            base58,
        })
    }

    /// Shared body for the three `sign_*` entry points. Verifies
    /// the message isn't empty, then chunks-and-sends the payload.
    /// `ins` selects SIGN_MESSAGE vs SIGN_OFFCHAIN_MESSAGE; the
    /// wire layout of the payload is identical.
    async fn sign_inner(
        &self,
        ins: u8,
        components: &[u32],
        message: &[u8],
    ) -> Result<SolanaSignature, LedgerSolError> {
        if message.is_empty() {
            return Err(LedgerSolError::invalid_message("message is empty"));
        }
        let payload = build_sign_payload(components, message);
        let response = self.send_chunked(CLA, ins, P1_CONFIRM, &payload).await?;
        if response.len() < 64 {
            return Err(LedgerSolError::protocol(format!(
                "sign INS 0x{ins:02X}: expected ≥64 bytes, got {}",
                response.len()
            )));
        }
        let sig = response[..64].to_vec();
        let base58 = bs58::encode(&sig).into_string();
        Ok(SolanaSignature { bytes: sig, base58 })
    }

    /// Encode an APDU, send it through the foreign transport, and
    /// translate the response into our error space.
    async fn exchange(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerSolError> {
        if data.len() > MAX_APDU_DATA {
            return Err(LedgerSolError::protocol(format!(
                "APDU payload {} exceeds {} byte ceiling",
                data.len(),
                MAX_APDU_DATA
            )));
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.push(cla);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        let response = self.transport.exchange(apdu).await?;
        if response.status_word != SW_SUCCESS {
            return Err(LedgerSolError::from_status(
                response.status_word,
                &format!("INS 0x{ins:02X}"),
            ));
        }
        Ok(response.data)
    }

    /// Chunk a payload across multiple APDUs using Solana's
    /// (P2_EXTEND | P2_MORE) continuation scheme. Only the final
    /// chunk's response is returned, matching how the device
    /// behaves: intermediate chunks return empty payload + 0x9000,
    /// last chunk returns the signature.
    async fn send_chunked(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, LedgerSolError> {
        if payload.len() <= MAX_APDU_DATA {
            return self.exchange(cla, ins, p1, 0x00, payload).await;
        }

        // P2 continuation bits per @ledgerhq/hw-app-solana. The P2
        // for each chunk depends on that chunk's own position, so it
        // MUST be computed from the *current* chunk, not carried over
        // from the previous iteration:
        //   - EXTEND set on every chunk EXCEPT the first (it marks a
        //     continuation of the in-progress message).
        //   - MORE   set on every chunk EXCEPT the last (it tells the
        //     device another chunk is still coming).
        // So:
        //   first chunk (of many): p2 = MORE
        //   middle chunk:          p2 = EXTEND | MORE
        //   last chunk:            p2 = EXTEND
        // The earlier implementation computed p2 one iteration late,
        // which left the first chunk with no MORE bit (device parsed
        // a truncated message) and the last chunk with a stray MORE
        // bit; both surface on-device as 0x6A80. Single-chunk
        // messages take the fast path above and never reach here.
        let mut offset = 0;
        let mut is_first = true;
        let mut last_response = Vec::new();
        while offset < payload.len() {
            let end = (offset + MAX_APDU_DATA).min(payload.len());
            let is_last = end == payload.len();
            let chunk = &payload[offset..end];
            let mut p2 = 0u8;
            if !is_first {
                p2 |= P2_EXTEND;
            }
            if !is_last {
                p2 |= P2_MORE;
            }
            last_response = self.exchange(cla, ins, p1, p2, chunk).await?;
            offset = end;
            is_first = false;
        }
        Ok(last_response)
    }
}

/// Build the standard Solana account path `m/44'/501'/{account}'/0'`
/// as four hardened u32 components. Used by every default-shape
/// call where the host just specifies an account number.
fn standard_solana_path(account: u32) -> Vec<u32> {
    vec![harden(44), harden(501), harden(account), harden(0)]
}

const HARDENED_BIT: u32 = 0x8000_0000;

fn harden(index: u32) -> u32 {
    index | HARDENED_BIT
}

/// Parse a BIP-32 derivation path string like `m/44'/501'/0'/0'`
/// into its u32 components, with the hardened bit set on
/// `'`-suffixed entries.
fn parse_bip32_path(path: &str) -> Result<Vec<u32>, LedgerSolError> {
    let trimmed = path.trim();
    let body = trimmed.strip_prefix("m/").unwrap_or(trimmed);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in body.split('/') {
        let (digits, hardened) = if let Some(stripped) = raw.strip_suffix('\'') {
            (stripped, true)
        } else if let Some(stripped) = raw.strip_suffix('h') {
            (stripped, true)
        } else {
            (raw, false)
        };
        let n: u32 = digits.parse().map_err(|_| LedgerSolError::InvalidPath {
            reason: format!("'{raw}' is not a valid path component"),
        })?;
        if n >= HARDENED_BIT {
            return Err(LedgerSolError::InvalidPath {
                reason: format!("component {n} exceeds 31-bit range"),
            });
        }
        out.push(if hardened { harden(n) } else { n });
    }
    Ok(out)
}

/// Encode a derivation path as the Solana app expects: a single
/// length byte followed by N big-endian u32 components.
fn encode_path(components: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + components.len() * 4);
    out.push(components.len() as u8);
    for c in components {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

/// Compose the SIGN_MESSAGE / SIGN_OFFCHAIN_MESSAGE payload:
///
///   [num_signers=1] [path_len] [path_components_be...] [message...]
///
/// We only sign one path per call. Multi-signer flows compose this
/// at the host layer by calling sign_transaction_* once per signer.
fn build_sign_payload(components: &[u32], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + components.len() * 4 + message.len());
    out.push(1); // num_signers
    out.extend_from_slice(&encode_path(components));
    out.extend_from_slice(message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_path_matches_hw_app_solana() {
        // m/44'/501'/3'/0' encoded as 4 BE u32 with hardened bit set.
        let path = standard_solana_path(3);
        let encoded = encode_path(&path);
        let expected: Vec<u8> = vec![
            0x04, // 4 components
            0x80, 0x00, 0x00, 0x2C, // 44'
            0x80, 0x00, 0x01, 0xF5, // 501'
            0x80, 0x00, 0x00, 0x03, // 3'
            0x80, 0x00, 0x00, 0x00, // 0'
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn parse_path_accepts_h_and_apostrophe() {
        let a = parse_bip32_path("m/44'/501'/0'/0'").unwrap();
        let b = parse_bip32_path("m/44h/501h/0h/0h").unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0], 44 | HARDENED_BIT);
    }

    #[test]
    fn parse_path_rejects_garbage() {
        assert!(parse_bip32_path("m/abc'/501'").is_err());
    }

    #[test]
    fn empty_path_is_master() {
        let p = parse_bip32_path("m/").unwrap();
        assert!(p.is_empty());
        let enc = encode_path(&p);
        assert_eq!(enc, vec![0]);
    }

    #[test]
    fn sign_payload_layout() {
        let path = vec![harden(44), harden(501), harden(0), harden(0)];
        let msg = vec![0xAAu8, 0xBB, 0xCC];
        let payload = build_sign_payload(&path, &msg);
        // [1, 4, 4× BE u32 = 16, msg.len 3] = 21 bytes
        assert_eq!(payload.len(), 1 + 1 + 16 + 3);
        assert_eq!(payload[0], 1, "num_signers");
        assert_eq!(payload[1], 4, "path_len");
        assert_eq!(&payload[18..], &[0xAA, 0xBB, 0xCC]);
    }
}
