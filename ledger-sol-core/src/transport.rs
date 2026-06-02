use thiserror::Error;

/// Errors raised by the foreign Transport implementation. The host
/// platform (Swift / Kotlin) builds these from its own BLE / USB
/// stack errors. The Rust side never constructs them.
#[derive(Debug, Error, uniffi::Error)]
pub enum SolanaTransportError {
    #[error("transport disconnected: {reason}")]
    Disconnected { reason: String },
    #[error("transport timed out: {reason}")]
    Timeout { reason: String },
    #[error("transport I/O error: {reason}")]
    Io { reason: String },
}

/// One APDU round-trip response from the device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SolanaExchangeResponse {
    /// SW1 SW2 as a big-endian u16. 0x9000 = success.
    pub status_word: u16,
    /// Response payload bytes EXCLUDING the trailing SW1 SW2.
    pub data: Vec<u8>,
}

/// Foreign callback interface implemented by the host platform.
/// The Swift / Kotlin transport handles:
///
///   - BLE GATT writes/notifies (or USB I/O on Android).
///   - Ledger's 5-byte BLE framing (tag/idx/total_len) and the
///     Nano X 153-byte MTU chunking.
///   - Multi-packet response reassembly.
///   - Keep-alive heartbeat (verified-stable at 400ms initial,
///     500ms interval).
///   - Timeout enforcement.
///
/// `exchange` receives a complete APDU (header + Lc + data, no Le)
/// and returns the reassembled response payload plus status word.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SolanaLedgerTransport: Send + Sync {
    async fn exchange(&self, apdu: Vec<u8>)
        -> Result<SolanaExchangeResponse, SolanaTransportError>;
}
