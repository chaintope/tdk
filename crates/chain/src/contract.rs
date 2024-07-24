use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use tapyrus::PublicKey;

pub type ChangeSet = Vec<Contract>;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate",)
)]
pub struct Contract {
    pub contract_id: String,
    pub contract: Vec<u8>,
    pub payment_base: PublicKey,
    pub spendable: bool,
}
