use thiserror::Error;

use crate::transport::SolanaTransportError;

/// Errors surfaced from the public API. Designed for clean
/// marshalling through UniFFI: each variant carries a `reason`
/// string so Swift / Kotlin callers can show or log a useful
/// message without inspecting the variant.
#[derive(Debug, Error, uniffi::Error)]
pub enum LedgerSolError {
    /// The injected Transport failed (BLE disconnect, timeout,
    /// device unplugged, etc.). The host platform owns transport
    /// and supplies the description.
    #[error("transport error: {reason}")]
    Transport { reason: String },

    /// The Solana app returned a non-success status word.
    /// 0x6985 is the canonical "user denied" (we surface that as
    /// `UserCanceled` instead). All other non-0x9000 status words
    /// map here, with the SW byte preserved for diagnostics.
    #[error("device rejected (status 0x{status_word:04X}): {reason}")]
    DeviceRejected { status_word: u16, reason: String },

    /// Derivation path argument couldn't be parsed.
    #[error("invalid derivation path: {reason}")]
    InvalidPath { reason: String },

    /// Transaction message argument was malformed.
    #[error("invalid transaction message: {reason}")]
    InvalidMessage { reason: String },

    /// Anything unexpected in the protocol exchange that isn't
    /// covered by the more specific variants above.
    #[error("protocol error: {reason}")]
    Protocol { reason: String },

    /// The user pressed reject on the device (status word
    /// 0x6985). Special-cased because UI typically wants to
    /// distinguish "user said no" from "something broke."
    #[error("user canceled on device")]
    UserCanceled,
}

impl From<SolanaTransportError> for LedgerSolError {
    fn from(err: SolanaTransportError) -> Self {
        LedgerSolError::Transport {
            reason: err.to_string(),
        }
    }
}

#[allow(dead_code)]
impl LedgerSolError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        LedgerSolError::Protocol { reason: msg.into() }
    }

    pub(crate) fn invalid_path(msg: impl Into<String>) -> Self {
        LedgerSolError::InvalidPath { reason: msg.into() }
    }

    pub(crate) fn invalid_message(msg: impl Into<String>) -> Self {
        LedgerSolError::InvalidMessage { reason: msg.into() }
    }

    pub(crate) fn from_status(status_word: u16, command_label: &str) -> Self {
        match status_word {
            0x6985 => LedgerSolError::UserCanceled,
            sw => LedgerSolError::DeviceRejected {
                status_word: sw,
                reason: format!("{command_label}: device returned 0x{sw:04X}"),
            },
        }
    }
}
