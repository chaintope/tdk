<div align="center">
  <h1>BDK</h1>

  <img src="https://raw.githubusercontent.com/bitcoindevkit/bdk/master/static/bdk.png" width="220" />

  <p>
    <strong>A modern, lightweight, descriptor-based wallet library written in Rust!</strong>
  </p>

  <p>
    <a href="https://crates.io/crates/tdk_wallet"><img alt="Crate Info" src="https://img.shields.io/crates/v/tdk_wallet.svg"/></a>
    <a href="https://github.com/bitcoindevkit/bdk/blob/master/LICENSE"><img alt="MIT or Apache-2.0 Licensed" src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg"/></a>
    <a href="https://github.com/bitcoindevkit/bdk/actions?query=workflow%3ACI"><img alt="CI Status" src="https://github.com/bitcoindevkit/bdk/workflows/CI/badge.svg"></a>
    <a href="https://coveralls.io/github/bitcoindevkit/bdk?branch=master"><img src="https://coveralls.io/repos/github/bitcoindevkit/bdk/badge.svg?branch=master"/></a>
    <a href="https://docs.rs/tdk_wallet"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-tdk_wallet-green"/></a>
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.67.0.html"><img alt="Rustc Version 1.67.0+" src="https://img.shields.io/badge/rustc-1.67.0%2B-lightgrey.svg"/></a>
    <a href="https://discord.gg/d7NkDKm"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
  </p>

  <h4>
    <a href="https://bitcoindevkit.org">Project Homepage</a>
    <span> | </span>
    <a href="https://docs.rs/tdk_wallet">Documentation</a>
  </h4>
</div>

# BDK Wallet

The `tdk_wallet` crate provides the [`Wallet`] type which is a simple, high-level
interface built from the low-level components of [`tdk_chain`]. `Wallet` is a good starting point
for many simple applications as well as a good demonstration of how to use the other mechanisms to
construct a wallet. It has two keychains (external and internal) which are defined by
[miniscript descriptors][`rust-miniscript`] and uses them to generate addresses. When you give it
chain data it also uses the descriptors to find transaction outputs owned by them. From there, you
can create and sign transactions.

For details about the API of `Wallet` see the [module-level documentation][`Wallet`].

## Blockchain data

In order to get blockchain data for `Wallet` to consume, you should configure a client from
an available chain source. Typically you make a request to the chain source and get a response
that the `Wallet` can use to update its view of the chain.

**Blockchain Data Sources**

* [`tdk_esplora`]: Grabs blockchain data from Esplora for updating BDK structures.
* [`bdk_electrum`]: Grabs blockchain data from Electrum for updating BDK structures.
* [`bdk_bitcoind_rpc`]: Grabs blockchain data from Bitcoin Core for updating BDK structures.

**Examples**

* [`example-crates/wallet_esplora_async`](https://github.com/bitcoindevkit/bdk/tree/master/example-crates/wallet_esplora_async)
* [`example-crates/wallet_esplora_blocking`](https://github.com/bitcoindevkit/bdk/tree/master/example-crates/wallet_esplora_blocking)
* [`example-crates/wallet_electrum`](https://github.com/bitcoindevkit/bdk/tree/master/example-crates/wallet_electrum)
* [`example-crates/wallet_rpc`](https://github.com/bitcoindevkit/bdk/tree/master/example-crates/wallet_rpc)

## Persistence

To persist the `Wallet` on disk, it must be constructed with a [`PersistBackend`] implementation.

**Implementations**

* [`tdk_file_store`]: A simple flat-file implementation of [`PersistBackend`].

**Example**

<!-- compile_fail because outpoint and txout are fake variables -->
```rust,compile_fail
use tdk_wallet::{tapyrus::Network, wallet::{ChangeSet, Wallet}};

fn main() {
    // Create a new file `Store`.
    let db = tdk_file_store::Store::<ChangeSet>::open_or_create_new(b"magic_bytes", "path/to/my_wallet.db").expect("create store");

    let descriptor = "wpkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/0/*)";
    let change_descriptor = "wpkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/1/*)";
    let mut wallet = Wallet::new_or_load(descriptor, change_descriptor, db, Network::Prod).expect("create or load wallet");

    // Insert a single `TxOut` at `OutPoint` into the wallet.
    let _ = wallet.insert_txout(outpoint, txout);
    wallet.commit().expect("must write to database");
}
```

<!-- ### Sync the balance of a descriptor -->

<!-- ```rust,no_run -->
<!-- use tdk_wallet::Wallet; -->
<!-- use tdk_wallet::blockchain::ElectrumBlockchain; -->
<!-- use tdk_wallet::SyncOptions; -->
<!-- use tdk_wallet::electrum_client::Client; -->
<!-- use tdk_wallet::tapyrus::Network; -->

<!-- fn main() -> Result<(), tdk_wallet::Error> { -->
<!--     let blockchain = ElectrumBlockchain::from(Client::new("ssl://electrum.blockstream.info:60002")?); -->
<!--     let wallet = Wallet::new( -->
<!--         "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)", -->
<!--         Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"), -->
<!--         Network::Prod, -->
<!--     )?; -->

<!--     wallet.sync(&blockchain, SyncOptions::default())?; -->

<!--     println!("Descriptor balance: {} SAT", wallet.balance(ColorIdentifier::default())?); -->

<!--     Ok(()) -->
<!-- } -->
<!-- ``` -->
<!-- ### Generate a few addresses -->

<!-- ```rust -->
<!-- use tdk_wallet::Wallet; -->
<!-- use tdk_wallet::wallet::AddressIndex::New; -->
<!-- use tdk_wallet::tapyrus::Network; -->

<!-- fn main() -> Result<(), tdk_wallet::Error> { -->
<!--     let wallet = Wallet::new_no_persist( -->
<!--         "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)", -->
<!--         Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"), -->
<!--         Network::Prod, -->
<!--     )?; -->

<!--     println!("Address #0: {}", wallet.get_address(New)); -->
<!--     println!("Address #1: {}", wallet.get_address(New)); -->
<!--     println!("Address #2: {}", wallet.get_address(New)); -->

<!--     Ok(()) -->
<!-- } -->
<!-- ``` -->

<!-- ### Create a transaction -->

<!-- ```rust,no_run -->
<!-- use tdk_wallet::{FeeRate, Wallet, SyncOptions}; -->
<!-- use tdk_wallet::blockchain::ElectrumBlockchain; -->

<!-- use tdk_wallet::electrum_client::Client; -->
<!-- use tdk_wallet::wallet::AddressIndex::New; -->

<!-- use tapyrus::base64; -->
<!-- use tdk_wallet::tapyrus::consensus::serialize; -->
<!-- use tdk_wallet::tapyrus::Network; -->

<!-- fn main() -> Result<(), tdk_wallet::Error> { -->
<!--     let blockchain = ElectrumBlockchain::from(Client::new("ssl://electrum.blockstream.info:60002")?); -->
<!--     let wallet = Wallet::new_no_persist( -->
<!--         "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)", -->
<!--         Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"), -->
<!--         Network::Prod, -->
<!--     )?; -->

<!--     wallet.sync(&blockchain, SyncOptions::default())?; -->

<!--     let send_to = wallet.get_address(New); -->
<!--     let (psbt, details) = { -->
<!--         let mut builder = wallet.build_tx(); -->
<!--         builder -->
<!--             .add_recipient(send_to.script_pubkey(), 50_000) -->
<!--             .enable_rbf() -->
<!--             .do_not_spend_change() -->
<!--             .fee_rate(FeeRate::from_tap_per_vb(5.0)); -->
<!--         builder.finish()? -->
<!--     }; -->

<!--     println!("Transaction details: {:#?}", details); -->
<!--     println!("Unsigned PSBT: {}", base64::encode(&serialize(&psbt))); -->

<!--     Ok(()) -->
<!-- } -->
<!-- ``` -->

<!-- ### Sign a transaction -->

<!-- ```rust,no_run -->
<!-- use tdk_wallet::{Wallet, SignOptions}; -->

<!-- use tapyrus::base64; -->
<!-- use tdk_wallet::tapyrus::consensus::deserialize; -->
<!-- use tdk_wallet::tapyrus::Network; -->

<!-- fn main() -> Result<(), tdk_wallet::Error> { -->
<!--     let wallet = Wallet::new_no_persist( -->
<!--         "wpkh([c258d2e4/84h/1h/0h]tprv8griRPhA7342zfRyB6CqeKF8CJDXYu5pgnj1cjL1u2ngKcJha5jjTRimG82ABzJQ4MQe71CV54xfn25BbhCNfEGGJZnxvCDQCd6JkbvxW6h/0/*)", -->
<!--         Some("wpkh([c258d2e4/84h/1h/0h]tprv8griRPhA7342zfRyB6CqeKF8CJDXYu5pgnj1cjL1u2ngKcJha5jjTRimG82ABzJQ4MQe71CV54xfn25BbhCNfEGGJZnxvCDQCd6JkbvxW6h/1/*)"), -->
<!--         Network::Prod, -->
<!--     )?; -->

<!--     let psbt = "..."; -->
<!--     let mut psbt = deserialize(&base64::decode(psbt).unwrap())?; -->

<!--     let _finalized = wallet.sign(&mut psbt, SignOptions::default())?; -->

<!--     Ok(()) -->
<!-- } -->
<!-- ``` -->

## Testing

### Unit testing

```bash
cargo test
```

# License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](../../LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](../../LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[`Wallet`]: https://docs.rs/tdk_wallet/latest/tdk_wallet/wallet/struct.Wallet.html
[`PersistBackend`]: https://docs.rs/tdk_chain/latest/tdk_chain/trait.PersistBackend.html
[`tdk_chain`]: https://docs.rs/tdk_chain/latest
[`tdk_file_store`]: https://docs.rs/tdk_file_store/latest
[`bdk_electrum`]: https://docs.rs/bdk_electrum/latest
[`bdk_esplora`]: https://docs.rs/bdk_esplora/latest
[`bdk_bitcoind_rpc`]: https://docs.rs/bdk_bitcoind_rpc/latest
[`rust-miniscript`]: https://docs.rs/miniscript/latest/miniscript/index.html
