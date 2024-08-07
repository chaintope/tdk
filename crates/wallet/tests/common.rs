#![allow(unused)]

use miniscript::ToPublicKey;
use miniscript::{descriptor, Descriptor, DescriptorPublicKey};
use std::str::FromStr;
use tapyrus::hashes::Hash;
use tapyrus::script::color_identifier::{self, ColorIdentifier};
use tapyrus::{
    transaction, Address, Amount, BlockHash, FeeRate, MalFixTxid, Network, OutPoint, PublicKey,
    Transaction, TxIn, TxOut,
};
use tdk_chain::indexed_tx_graph::Indexer;
use tdk_chain::{BlockId, ConfirmationTime, Contract};
use tdk_wallet::{KeychainKind, LocalOutput, Wallet};

/// Return a fake wallet that appears to be funded for testing.
///
/// The funded wallet contains a tx with a 76_000 sats input and two outputs, one spending 25_000
/// to a foreign address and one returning 50_000 back to the wallet. The remaining 1000
/// sats are the transaction fee.
pub fn get_funded_wallet_with_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, tapyrus::MalFixTxid) {
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    let receive_address = wallet.peek_address(KeychainKind::External, 0).address;
    let sendto_address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(76_000),
            script_pubkey: receive_address.script_pubkey(),
        }],
    };

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx0.malfix_txid(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(50_000),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 1_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 2_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid())
}

/// Return a fake wallet that appears to be funded for testing.
///
/// The funded wallet contains a tx with a 76_000 taps input and two outputs,
/// one spending 25_000 to a foreign address, one issuing NFT coin to the wallet,
/// and one returning 50_000 back to the wallet. The remaining 1000
/// taps are the transaction fee.
pub fn get_funded_wallet_with_nft_and_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, tapyrus::MalFixTxid, ColorIdentifier) {
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    let receive_address = wallet.peek_address(KeychainKind::External, 0).address;
    let sendto_address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(76_000),
            script_pubkey: receive_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };
    let color_id = ColorIdentifier::nft(out_point);

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::ONE_TAP,
                script_pubkey: receive_address.script_pubkey().add_color(color_id).unwrap(),
            },
            TxOut {
                value: Amount::from_tap(50_000),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 1_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 2_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid(), color_id)
}

pub fn get_funded_wallet_with_reissuable_and_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, MalFixTxid, ColorIdentifier) {
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    let receive_address = wallet.peek_address(KeychainKind::External, 0).address;
    let sendto_address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(76_000),
            script_pubkey: receive_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };
    let color_id = ColorIdentifier::reissuable(receive_address.script_pubkey().as_script());

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(100),
                script_pubkey: receive_address.script_pubkey().add_color(color_id).unwrap(),
            },
            TxOut {
                value: Amount::from_tap(50_000),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 1_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 2_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid(), color_id)
}

pub fn get_funded_wallet_with_two_colored_coin_and_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, MalFixTxid, ColorIdentifier, ColorIdentifier) {
    let (mut wallet, txid, color_id1) =
        get_funded_wallet_with_reissuable_and_change(descriptor, change);

    let receive_address = wallet.peek_address(KeychainKind::External, 1).address;
    let color_id2 = ColorIdentifier::reissuable(receive_address.script_pubkey().as_script());

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: txid,
                vout: 1,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(45_000),
            script_pubkey: receive_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };
    let color_id = ColorIdentifier::reissuable(receive_address.script_pubkey().as_script());

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(150),
                script_pubkey: receive_address
                    .script_pubkey()
                    .add_color(color_id2)
                    .unwrap(),
            },
            TxOut {
                value: Amount::from_tap(40_000),
                script_pubkey: receive_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 3_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 4_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 3_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 4_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid(), color_id1, color_id2)
}

fn get_p2c_address(wallet: &mut Wallet, color_id: Option<ColorIdentifier>) -> Address {
    let payment_base = get_payment_base(wallet);
    let contract = "metadata".as_bytes().to_vec();
    wallet.store_contract(
        "contract_id".to_string(),
        contract.clone(),
        payment_base,
        false,
    );
    wallet
        .create_pay_to_contract_address(&payment_base, contract.clone(), color_id)
        .unwrap()
}
pub fn get_payment_base(wallet: &Wallet) -> PublicKey {
    let descriptor = wallet.get_descriptor_for_keychain(KeychainKind::External);
    let desc = descriptor_to_public_key(descriptor);
    desc.unwrap()
}
pub fn descriptor_to_public_key(descriptor: &Descriptor<DescriptorPublicKey>) -> Option<PublicKey> {
    match descriptor {
        Descriptor::Pkh(pk) => {
            let inner = pk.as_inner();
            match inner {
                DescriptorPublicKey::Single(single) => {
                    let single_pub_key = single.key.clone();
                    match single_pub_key {
                        descriptor::SinglePubKey::FullKey(pk) => Some(pk),
                        descriptor::SinglePubKey::XOnly(_) => None,
                    }
                }
                DescriptorPublicKey::XPub(xpub) => Some(xpub.xkey.public_key.to_public_key()),
                _ => None,
            }
        }
        // 他のDescriptorの場合、サポートされていない
        _ => None,
    }
}

pub fn get_funded_wallet_with_p2c_and_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, MalFixTxid, Address) {
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    let fund_address = wallet.peek_address(KeychainKind::External, 0).address;
    let sendto_address: Address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(76_000),
            script_pubkey: sendto_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };

    let receive_address = get_p2c_address(&mut wallet, None);

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(50_000),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 1_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 2_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid(), receive_address)
}

pub fn get_funded_wallet_with_colored_p2c_and_change(
    descriptor: &str,
    change: &str,
) -> (Wallet, MalFixTxid, Address, ColorIdentifier) {
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    let fund_address = wallet.peek_address(KeychainKind::External, 0).address;
    let sendto_address: Address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(76_000),
            script_pubkey: fund_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };
    let color_id = ColorIdentifier::reissuable(fund_address.script_pubkey().as_script());
    let receive_address = get_p2c_address(&mut wallet, Some(color_id));
    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(100),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(50_000),
                script_pubkey: fund_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };

    wallet
        .insert_checkpoint(BlockId {
            height: 1_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_checkpoint(BlockId {
            height: 2_000,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    wallet
        .insert_tx(
            tx0,
            ConfirmationTime::Confirmed {
                height: 1_000,
                time: 100,
            },
        )
        .unwrap();
    wallet
        .insert_tx(
            tx1.clone(),
            ConfirmationTime::Confirmed {
                height: 2_000,
                time: 200,
            },
        )
        .unwrap();

    (wallet, tx1.malfix_txid(), receive_address, color_id)
}

pub fn get_p2c_tx(wallet: &mut Wallet, contract: &Contract) -> Vec<tapyrus::Transaction> {
    let payment_base = get_payment_base(wallet);
    let fund_address = wallet.peek_address(KeychainKind::External, 0).address;
    let receive_address = wallet
        .create_pay_to_contract_address(&payment_base, contract.clone().contract, None)
        .unwrap();
    let sendto_address: Address = Address::from_str("msvWktzSViRZ5kiepVr6W8VrgE8a6mbiVu")
        .expect("address")
        .require_network(Network::Dev)
        .unwrap();

    let tx0 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: MalFixTxid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_tap(70_000),
            script_pubkey: fund_address.script_pubkey(),
        }],
    };

    let out_point = OutPoint {
        txid: tx0.malfix_txid(),
        vout: 0,
    };

    let tx1 = Transaction {
        version: transaction::Version::ONE,
        lock_time: tapyrus::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_tap(10_000),
                script_pubkey: fund_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(20_000),
                script_pubkey: receive_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_tap(25_000),
                script_pubkey: sendto_address.script_pubkey(),
            },
        ],
    };
    vec![tx0, tx1]
}
/// Return a fake wallet that appears to be funded for testing.
///
/// The funded wallet contains a tx with a 76_000 sats input and two outputs, one spending 25_000
/// to a foreign address and one returning 50_000 back to the wallet. The remaining 1000
/// sats are the transaction fee.
///
/// Note: the change descriptor will have script type `p2wpkh`. If passing some other script type
/// as argument, make sure you're ok with getting a wallet where the keychains have potentially
/// different script types. Otherwise, use `get_funded_wallet_with_change`.
pub fn get_funded_wallet(descriptor: &str) -> (Wallet, tapyrus::MalFixTxid) {
    let change = get_test_pkh_change();
    get_funded_wallet_with_change(descriptor, change)
}

pub fn get_funded_wallet_pkh() -> (Wallet, tapyrus::MalFixTxid) {
    get_funded_wallet_with_change(get_test_pkh(), get_test_pkh_change())
}

pub fn get_test_pkh() -> &'static str {
    "pkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
}

pub fn get_test_pkh_with_change_desc() -> (&'static str, &'static str) {
    (
        "pkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)",
        get_test_pkh_change(),
    )
}

fn get_test_pkh_change() -> &'static str {
    "pkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/0)"
}

pub fn get_test_single_sig_csv() -> &'static str {
    // and(pk(Alice),older(6))
    "sh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"
}

pub fn get_test_a_or_b_plus_csv() -> &'static str {
    // or(pk(Alice),and(pk(Bob),older(144)))
    "sh(or_d(pk(cRjo6jqfVNP33HhSS76UhXETZsGTZYx8FMFvR9kpbtCSV1PmdZdu),and_v(v:pk(cMnkdebixpXMPfkcNEjjGin7s94hiehAH4mLbYkZoh9KSiNNmqC8),older(144))))"
}

pub fn get_test_single_sig_cltv() -> &'static str {
    // and(pk(Alice),after(100000))
    "sh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))"
}

pub fn get_test_pkh_single_sig() -> &'static str {
    "pkh(cNJmN3fH9DDbDt131fQNkVakkpzawJBSeybCUNmP1BovpmGQ45xG)"
}

pub fn get_test_pkh_single_sig_xprv_with_change_desc() -> (&'static str, &'static str) {
    ("pkh(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/0/*)",
    "pkh(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/1/*)")
}

/// Construct a new [`FeeRate`] from the given raw `sat_vb` feerate. This is
/// useful in cases where we want to create a feerate from a `f64`, as the
/// traditional [`FeeRate::from_tap_per_vb`] method will only accept an integer.
///
/// **Note** this 'quick and dirty' conversion should only be used when the input
/// parameter has units of `satoshis/vbyte` **AND** is not expected to overflow,
/// or else the resulting value will be inaccurate.
pub fn feerate_unchecked(sat_vb: f64) -> FeeRate {
    // 1 sat_vb / 4wu_vb * 1000kwu_wu = 250 sat_kwu
    let sat_kwu = (sat_vb * 250.0).ceil() as u64;
    FeeRate::from_tap_per_kwu(sat_kwu)
}
