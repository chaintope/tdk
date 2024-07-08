#![allow(unused)]
use alloc::vec::Vec;
use tapyrus::{
    consensus,
    hashes::{hex::FromHex, Hash},
    Transaction,
};

use crate::BlockId;

pub const RAW_TX_1: &str = "010000000116d6174da7183d70d0a7d4dc314d517a7d135db79ad63515028b293a76f4f9d10000000000feffffff023a21fc8350060000160014531c405e1881ef192294b8813631e258bf98ea7a1027000000000000225120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684cef2e0100";
pub const RAW_TX_2: &str = "0100000001a688607020cfae91a61e7c516b5ef1264d5d77f17200c3866826c6c808ebf1620000000000feffffff021027000000000000225120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c20fd48ff530600001600146886c525e41d4522042bd0b159dfbade2504a6bb3e760100";
pub const RAW_TX_3: &str = "010000000135d67ee47b557e68b8c6223958f597381965ed719f1207ee2b9e20432a24a5dc0100000000feffffff021027000000000000225120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb62215a5055060000160014070df7671dea67a50c4799a744b5c9be8f4bac69ee760100";
pub const RAW_TX_4: &str = "0100000001d00e8f76ed313e19b339ee293c0f52b0325c95e24c8f3966fa353fb2bedbcf580100000000feffffff021027000000000000225120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc9cda55fe53060000160014852b5864b8edd42fab4060c87f818e50780865fff3760100";

pub fn tx_from_hex(s: &str) -> Transaction {
    let raw = Vec::from_hex(s).expect("data must be in hex");
    consensus::deserialize(raw.as_slice()).expect("must deserialize")
}

pub fn new_hash<H: Hash>(s: &str) -> H {
    <H as tapyrus::hashes::Hash>::hash(s.as_bytes())
}

pub fn new_block_id(height: u32, hash: &str) -> BlockId {
    BlockId {
        height,
        hash: new_hash(hash),
    }
}
