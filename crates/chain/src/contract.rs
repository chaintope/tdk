//! Module for Pay-To-Contract
//!
//! This module contains an implementation for storing Contract information and using it in a wallet.
use alloc::{string::String, vec::Vec};
use tapyrus::PublicKey;

/// The [`ChangeSet`] represents changes to [`Contract`].
pub type ChangeSet = Vec<Contract>;

/// Contract is a data structure for holding information for receiving payments to pay-to-contract.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate",)
)]
pub struct Contract {
    /// The contract ID is an identifier that uniquely identifies the contract.
    pub contract_id: String,
    /// The contract represents the content of the contract.
    pub contract: Vec<u8>,
    /// Public key for generating P2C addresses.
    pub payment_base: PublicKey,
    /// Set to 1 if available for payment, 0 if not
    pub spendable: bool,
}
