/// Signature returned by `sign_transaction` / `sign_offchain_message`.
/// Solana signatures are 64-byte Ed25519. Base58 form is what the
/// JSON-RPC `sendTransaction` interface and explorers display.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SolanaSignature {
    /// Raw 64-byte Ed25519 signature.
    pub bytes: Vec<u8>,
    /// Base58 representation, as printed by Solana CLI / Explorer.
    pub base58: String,
}
