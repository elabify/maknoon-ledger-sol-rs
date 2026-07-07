# ledger-sol-rs

A Rust core + [UniFFI](https://github.com/mozilla/uniffi-rs) bindings for talking to the
**Ledger Solana app** from iOS and Android. The Rust crate implements the
Ledger Solana app's APDU protocol directly (address derivation, transaction signing, and
off-chain message signing), while the host platform owns its own BLE transport.

Single source of truth, two artifacts:

```
ledger-sol-rs/
   ├── ledger-sol-core   ←  Rust crate (LedgerSolanaClient)
   ├── ios               ←  build-xcframework.sh → LedgerSolCore.xcframework
   └── android           ←  android/build-aar.sh → ledger-sol-core.aar
```

The Trezor counterpart across all four chains is `trezor-core-rs` (one unified crate).

## Design pillars

1. **Audit surface = Ledger device protocol only.** No Solana RPC / SDK dependency; the
   crate speaks the Ledger Solana app protocol and nothing else.
2. **Native owns transport.** BLE framing, MTU chunking, and keep-alive live on the
   Swift side; Rust gets complete APDUs in, complete responses out.
3. **Async end-to-end.** The UniFFI callback transport is async; the client is `async`
   throughout (Swift sees `async throws`). Addresses are base58-encoded.

## Public API

```rust
let client = LedgerSolanaClient::new(my_transport);
let cfg:  Vec<u8> = client.get_app_configuration().await?;
let addr: String  = client.get_address_at_path("m/44'/501'/0'".into(), false).await?;
let sig:  Vec<u8> = client.sign_transaction_at_path(path, message_bytes).await?;
let msig: Vec<u8> = client.sign_offchain_message_at_path(path, message).await?;
```

`*_for_account` convenience variants take an account index instead of a full path.

## Building

```sh
make                    # fmt-check + clippy + test (CI default)
make ios                # produces ios/LedgerSolCore.xcframework (run setup-ios-targets once)
./android/build-aar.sh  # produces the ledger-sol-core.aar for Android
make clean
```

## License

Apache-2.0.

## Acknowledgements

- [Mozilla UniFFI](https://github.com/mozilla/uniffi-rs) for the cross-language binding generator.
- Ledger's Solana app APDU specification.
