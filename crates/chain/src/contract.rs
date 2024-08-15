//! Module for Pay-To-Contract
//!
//! This module contains an implementation for storing Contract information and using it in a wallet.
use alloc::collections::BTreeMap;

use alloc::{string::String, vec::Vec};
use num_bigint::BigUint;
use tapyrus::key::{Error, Secp256k1};
use tapyrus::secp256k1::{All, Scalar};
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
    pub fn create_pay_to_contract_private_key(
        &self,
        payment_base_private_key: &PrivateKey,
        payment_base: &PublicKey,
        network: Network,
    ) -> Result<PrivateKey, Error> {
        let commitment: Scalar =
            Self::create_pay_to_contract_commitment(payment_base, self.contract.clone());
        let p2c_private_key = payment_base_private_key.inner.add_tweak(&commitment)?;
        Ok(PrivateKey::new(p2c_private_key, network))
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

    /// Generate public key for Pay-to-Contract
    pub fn create_pay_to_contract_public_key(
        payment_base: &PublicKey,
        contracts: Vec<u8>,
        secp: &Secp256k1<All>,
    ) -> PublicKey {
        let commitment: Scalar =
            Self::create_pay_to_contract_commitment(payment_base, contracts.clone());
        let pubkey = payment_base.inner.add_exp_tweak(secp, &commitment).unwrap();
        PublicKey {
            compressed: true,
            inner: pubkey,
        }
    }
}

#[cfg(test)]
mod signers_container_tests {
    use core::str::FromStr;
    use std::string::ToString;

    use tapyrus::key::Secp256k1;

    use super::*;
    use crate::tapyrus::hashes::hex::FromHex;

    #[test]
    fn test_create_pay_to_contract_private_key() {
        let payment_base_private_key = PrivateKey::from_slice(
            &Vec::<u8>::from_hex(
                "c5580f6c26f83fb513dd5e0d1b03c36be26fcefa139b1720a7ca7c0dedd439c2",
            )
            .unwrap(),
            Network::Dev,
        )
        .unwrap();
        let payment_base =
            PublicKey::from_private_key(&Secp256k1::signing_only(), &payment_base_private_key);
        let contract = Contract {
            contract_id: "contract_id".to_string(),
            contract: "metadata".as_bytes().to_vec(),
            payment_base,
            spendable: true,
        };
        let key =
            contract.create_pay_to_contract_private_key(&payment_base_private_key, &payment_base, Network::Dev);
        assert!(key.is_ok());
        assert_eq!(
            key.unwrap(),
            PrivateKey::from_slice(
                &Vec::<u8>::from_hex(
                    "78612a8498322787104379330ec41f749fd2ada016e0c0a6c2b233ed13fc8978"
                )
                .unwrap(),
                Network::Dev
            )
            .unwrap()
        );
    }
}
