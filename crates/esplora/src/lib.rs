#![doc = include_str!("../README.md")]

//! This crate is used for updating structures of [`tdk_chain`] with data from an Esplora server.
//!
//! The two primary methods are [`EsploraExt::sync`] and [`EsploraExt::full_scan`]. In most cases
//! [`EsploraExt::sync`] is used to sync the transaction histories of scripts that the application
//! cares about, for example the scripts for all the receive addresses of a Wallet's keychain that it
//! has shown a user. [`EsploraExt::full_scan`] is meant to be used when importing or restoring a
//! keychain where the range of possibly used scripts is not known. In this case it is necessary to
//! scan all keychain scripts until a number (the "stop gap") of unused scripts is discovered. For a
//! sync or full scan the user receives relevant blockchain data and output updates for [`tdk_chain`]
//! via a new [`TxGraph`] to be appended to any existing [`TxGraph`] data.
//!
//! Refer to [`example_esplora`] for a complete example.
//!
//! [`TxGraph`]: tdk_chain::tx_graph::TxGraph
//! [`example_esplora`]: https://github.com/chaintope/tdk/tree/master/example-crates/example_esplora

use esplora_client::TxStatus;
use tdk_chain::{BlockId, ConfirmationTimeHeightAnchor};

pub use esplora_client;

#[cfg(feature = "blocking")]
mod blocking_ext;
#[cfg(feature = "blocking")]
pub use blocking_ext::*;

#[cfg(feature = "async")]
mod async_ext;
#[cfg(feature = "async")]
pub use async_ext::*;

#[cfg(feature = "serde")]
pub extern crate serde_crate as serde;

fn anchor_from_status(status: &TxStatus) -> Option<ConfirmationTimeHeightAnchor> {
    if let TxStatus {
        block_height: Some(height),
        block_hash: Some(hash),
        block_time: Some(time),
        ..
    } = status.clone()
    {
        Some(ConfirmationTimeHeightAnchor {
            anchor_block: BlockId { height, hash },
            confirmation_height: height,
            confirmation_time: time,
        })
    } else {
        None
    }
}
