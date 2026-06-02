// ledger-sol-core: cross-platform Ledger Solana signing client.
//
// LedgerHQ does not maintain a Rust client for the Solana app
// (the canonical implementation is `@ledgerhq/hw-app-solana` in
// TypeScript). This crate hand-rolls the APDU encoding following
// that reference, exposing it through a UniFFI foreign-callback
// transport so iOS / Android can share the implementation with
// `ledger-btc-core`.
//
// Public API surface is documented in client.rs.

mod client;
mod error;
mod transport;
mod types;

pub use client::{LedgerSolanaClient, SolanaAddress};
pub use error::LedgerSolError;
pub use transport::{SolanaExchangeResponse, SolanaLedgerTransport, SolanaTransportError};
pub use types::SolanaSignature;

uniffi::setup_scaffolding!();
