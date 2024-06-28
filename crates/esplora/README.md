# TDK Esplora

TDK Esplora extends [`esplora-client`] to update [`tdk_chain`] structures
from an Esplora server.

## Usage

There are two versions of the extension trait (blocking and async).

For blocking-only:
```toml
tdk_esplora = { version = "0.3", features = ["blocking"] }
```

For async-only:
```toml
tdk_esplora = { version = "0.3", features = ["async"] }
```

For async-only (with https):
```toml
tdk_esplora = { version = "0.3", features = ["async-https"] }
```

To use the extension traits:
```rust
// for blocking
use tdk_esplora::EsploraExt;
// for async
// use tdk_esplora::EsploraAsyncExt;
```

For full examples, refer to [`example-crates/wallet_esplora_blocking`](https://github.com/chaintope/tdk/tree/master/example-crates/wallet_esplora_blocking) and [`example-crates/wallet_esplora_async`](https://github.com/chaintope/tdk/tree/master/example-crates/wallet_esplora_async).

[`esplora-client`]: https://docs.rs/esplora-client/
[`tdk_chain`]: https://docs.rs/tdk-chain/
