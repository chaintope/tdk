//! Module for Pay-To-Contract
//!
//! This module contains an implementation for storing Contract information and using it in a wallet.
use alloc::collections::BTreeMap;

use alloc::{string::String, vec::Vec};
use num_bigint::BigUint;
use tapyrus::key::Error;
use tapyrus::secp256k1::{Scalar, SecretKey};
use tapyrus::{
    hashes::{Hash, HashEngine},
    PrivateKey,
};
use tapyrus::{Network, PublicKey};

/// The [`ChangeSet`] represents changes to [`Contract`].
pub type ChangeSet = BTreeMap<String, Contract>;

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

impl Contract {
    /// Create private key for Pay-to-Contract
    pub fn create_private_key(
        &self,
        payment_base: &PublicKey,
        network: Network,
    ) -> Result<PrivateKey, Error> {
        let commitment: Scalar =
            Self::create_pay_to_contract_commitment(payment_base, self.contract.clone());
        let sk = SecretKey::from_slice(&commitment.to_be_bytes())?;
        Ok(PrivateKey::new(sk, network))
    }

    /// Compute pay-to-contract commitment as Scalar.
    pub fn create_pay_to_contract_commitment(
        payment_base: &PublicKey,
        contract: Vec<u8>,
    ) -> Scalar {
        let mut engine = tapyrus::hashes::sha256::HashEngine::default();
        engine.input(&payment_base.inner.serialize());
        engine.input(&contract);
        let result = tapyrus::hashes::sha256::Hash::from_engine(engine);
        Self::scalar_from(&result.to_byte_array()[..])
    }

    /// Generate Scalar from bytes
    pub fn scalar_from(bytes: &[u8]) -> Scalar {
        let order: BigUint = BigUint::from_bytes_be(&Scalar::MAX.to_be_bytes()) + 1u32;
        let n: BigUint = BigUint::from_bytes_be(bytes);
        let n = n % order;
        let bytes = n.to_bytes_be();
        let mut value = [0u8; 32];
        value[32 - bytes.len()..].copy_from_slice(&bytes);
        Scalar::from_be_bytes(value).unwrap()
    }
}
