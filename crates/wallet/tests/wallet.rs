use std::path::Path;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use assert_matches::assert_matches;
use miniscript::{descriptor, Descriptor, DescriptorPublicKey, ToPublicKey};
use rand::random;
use tapyrus::bip32::{ExtendendPrivKey, ExtendendPubKey};
use tapyrus::hashes::Hash;
use tapyrus::hex::DisplayHex;
use tapyrus::key::Secp256k1;
use tapyrus::script::PushBytesBuf;
use tapyrus::secp256k1::Scalar;
use tapyrus::sighash::EcdsaSighashType;
use tapyrus::{
    absolute, script::color_identifier::ColorIdentifier, transaction, Address, Amount, BlockHash,
    FeeRate, MalFixTxid, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight,
};
use tapyrus::{psbt, AddressType, PublicKey};
use tdk_chain::collections::BTreeMap;
use tdk_chain::{BlockId, ConfirmationTime};
use tdk_chain::{Contract, COINBASE_MATURITY};
use tdk_persist::PersistBackend;
use tdk_sqlite::rusqlite::Connection;
use tdk_wallet::descriptor::{calc_checksum, DescriptorError, IntoWalletDescriptor};
use tdk_wallet::keys::DescriptorSecretKey;
use tdk_wallet::psbt::PsbtUtils;
use tdk_wallet::signer::{SignOptions, SignerError};
use tdk_wallet::wallet::coin_selection::{self, LargestFirstCoinSelection};
use tdk_wallet::wallet::error::CreateTxError;
use tdk_wallet::wallet::tx_builder::AddForeignUtxoError;
use tdk_wallet::wallet::{AddressInfo, Balance, Wallet};
use tdk_wallet::wallet::{CreateContractError, NewError};
use tdk_wallet::KeychainKind;

mod common;
use common::*;

fn receive_output(wallet: &mut Wallet, value: u64, height: ConfirmationTime) -> OutPoint {
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: addr.script_pubkey(),
            value: Amount::from_tap(value),
        }],
    };

    wallet.insert_tx(tx.clone(), height).unwrap();

    OutPoint {
        txid: tx.malfix_txid(),
        vout: 0,
    }
}

fn receive_output_in_latest_block(wallet: &mut Wallet, value: u64) -> OutPoint {
    let latest_cp = wallet.latest_checkpoint();
    let height = latest_cp.height();
    let anchor = if height == 0 {
        ConfirmationTime::Unconfirmed { last_seen: 0 }
    } else {
        ConfirmationTime::Confirmed { height, time: 0 }
    };
    receive_output(wallet, value, anchor)
}

// The satisfaction size of a P2WPKH is 112 WU =
// 1 (elements in witness) + 1 (OP_PUSH) + 33 (pk) + 1 (OP_PUSH) + 72 (signature + sighash) + 1*4 (script len)
// On the witness itself, we have to push once for the pk (33WU) and once for signature + sighash (72WU), for
// a total of 105 WU.
// Here, we push just once for simplicity, so we have to add an extra byte for the missing
// OP_PUSH.
const P2WPKH_FAKE_WITNESS_SIZE: usize = 106;

const P2PKH_FAKE_SCRIPT_SIG_SIZE: usize = 107;

const DB_MAGIC: &[u8] = &[0x21, 0x24, 0x48];

#[test]
fn load_recovers_wallet() -> anyhow::Result<()> {
    fn run<B, FN, FR>(filename: &str, create_new: FN, recover: FR) -> anyhow::Result<()>
    where
        B: PersistBackend<tdk_wallet::wallet::ChangeSet> + Send + Sync + 'static,
        FN: Fn(&Path) -> anyhow::Result<B>,
        FR: Fn(&Path) -> anyhow::Result<B>,
    {
        let temp_dir = tempfile::tempdir().expect("must create tempdir");
        let file_path = temp_dir.path().join(filename);
        let (desc, change_desc) = get_test_pkh_single_sig_xprv_with_change_desc();

        // create new wallet
        let wallet_spk_index = {
            let db = create_new(&file_path).expect("must create db");
            let mut wallet =
                Wallet::new(desc, change_desc, db, Network::Dev).expect("must init wallet");

            wallet.reveal_next_address(KeychainKind::External).unwrap();
            wallet.spk_index().clone()
        };

        // recover wallet
        {
            let db = recover(&file_path).expect("must recover db");
            let wallet = Wallet::load(db).expect("must recover wallet");
            assert_eq!(wallet.network(), Network::Dev);
            assert_eq!(
                wallet.spk_index().keychains().collect::<Vec<_>>(),
                wallet_spk_index.keychains().collect::<Vec<_>>()
            );
            assert_eq!(
                wallet.spk_index().last_revealed_indices(),
                wallet_spk_index.last_revealed_indices()
            );
            let secp = Secp256k1::new();
            assert_eq!(
                *wallet.get_descriptor_for_keychain(KeychainKind::External),
                desc.into_wallet_descriptor(&secp, wallet.network())
                    .unwrap()
                    .0
            );
        }

        // `new` can only be called on empty db
        {
            let db = recover(&file_path).expect("must recover db");
            let result = Wallet::new(desc, change_desc, db, Network::Dev);
            assert!(matches!(result, Err(NewError::NonEmptyDatabase)));
        }

        Ok(())
    }

    run(
        "store.db",
        |path| Ok(tdk_file_store::Store::create_new(DB_MAGIC, path)?),
        |path| Ok(tdk_file_store::Store::open(DB_MAGIC, path)?),
    )?;
    run(
        "store.sqlite",
        |path| Ok(tdk_sqlite::Store::new(Connection::open(path)?)?),
        |path| Ok(tdk_sqlite::Store::new(Connection::open(path)?)?),
    )?;

    Ok(())
}

#[test]
fn new_or_load() -> anyhow::Result<()> {
    fn run<B, F>(filename: &str, new_or_load: F) -> anyhow::Result<()>
    where
        B: PersistBackend<tdk_wallet::wallet::ChangeSet> + Send + Sync + 'static,
        F: Fn(&Path) -> anyhow::Result<B>,
    {
        let temp_dir = tempfile::tempdir().expect("must create tempdir");
        let file_path = temp_dir.path().join(filename);
        let (desc, change_desc) = get_test_pkh_with_change_desc();

        // init wallet when non-existent
        let wallet_keychains: BTreeMap<_, _> = {
            let db = new_or_load(&file_path).expect("must create db");
            let wallet =
                Wallet::new_or_load(desc, change_desc, db, Network::Dev).expect("must init wallet");
            wallet.keychains().map(|(k, v)| (*k, v.clone())).collect()
        };

        // wrong network
        {
            let db = new_or_load(&file_path).expect("must create db");
            let err = Wallet::new_or_load(desc, change_desc, db, Network::Prod)
                .expect_err("wrong network");
            assert!(
                matches!(
                    err,
                    tdk_wallet::wallet::NewOrLoadError::LoadedNetworkDoesNotMatch {
                        got: Some(Network::Dev),
                        expected: Network::Prod
                    }
                ),
                "err: {}",
                err,
            );
        }

        // wrong genesis hash
        {
            let exp_blockhash = BlockHash::all_zeros();
            let got_blockhash = tapyrus::blockdata::constants::mainnet_genesis_block().block_hash();

            let db = new_or_load(&file_path).expect("must open db");
            let err = Wallet::new_or_load_with_genesis_hash(
                desc,
                change_desc,
                db,
                Network::Dev,
                exp_blockhash,
            )
            .expect_err("wrong genesis hash");
            assert!(
                matches!(
                    err,
                    tdk_wallet::wallet::NewOrLoadError::LoadedGenesisDoesNotMatch { got, expected }
                    if got == Some(got_blockhash) && expected == exp_blockhash
                ),
                "err: {}",
                err,
            );
        }

        // wrong external descriptor
        {
            let exp_descriptor = get_test_pkh_single_sig();
            let got_descriptor = desc
                .into_wallet_descriptor(&Secp256k1::new(), Network::Dev)
                .unwrap()
                .0;

            let db = new_or_load(&file_path).expect("must open db");
            let err = Wallet::new_or_load(exp_descriptor, change_desc, db, Network::Dev)
                .expect_err("wrong external descriptor");
            assert!(
                matches!(
                    err,
                    tdk_wallet::wallet::NewOrLoadError::LoadedDescriptorDoesNotMatch { ref got, keychain }
                    if got == &Some(got_descriptor) && keychain == KeychainKind::External
                ),
                "err: {}",
                err,
            );
        }

        // wrong internal descriptor
        {
            let exp_descriptor = get_test_pkh_single_sig();
            let got_descriptor = change_desc
                .into_wallet_descriptor(&Secp256k1::new(), Network::Dev)
                .unwrap()
                .0;

            let db = new_or_load(&file_path).expect("must open db");
            let err = Wallet::new_or_load(desc, exp_descriptor, db, Network::Dev)
                .expect_err("wrong internal descriptor");
            assert!(
                matches!(
                    err,
                    tdk_wallet::wallet::NewOrLoadError::LoadedDescriptorDoesNotMatch { ref got, keychain }
                    if got == &Some(got_descriptor) && keychain == KeychainKind::Internal
                ),
                "err: {}",
                err,
            );
        }

        // all parameters match
        {
            let db = new_or_load(&file_path).expect("must open db");
            let wallet = Wallet::new_or_load(desc, change_desc, db, Network::Dev)
                .expect("must recover wallet");
            assert_eq!(wallet.network(), Network::Dev);
            assert!(wallet
                .keychains()
                .map(|(k, v)| (*k, v.clone()))
                .eq(wallet_keychains));
        }
        Ok(())
    }

    run("store.db", |path| {
        Ok(tdk_file_store::Store::open_or_create_new(DB_MAGIC, path)?)
    })?;
    run("store.sqlite", |path| {
        Ok(tdk_sqlite::Store::new(Connection::open(path)?)?)
    })?;

    Ok(())
}

#[test]
fn test_error_external_and_internal_are_the_same() {
    // identical descriptors should fail to create wallet
    let desc = get_test_pkh();
    let err = Wallet::new_no_persist(desc, desc, Network::Dev);
    assert!(
        matches!(&err, Err(DescriptorError::ExternalAndInternalAreTheSame)),
        "expected same descriptors error, got {:?}",
        err,
    );

    // public + private of same descriptor should fail to create wallet
    let desc = "pkh(tprv8ZgxMBicQKsPdcAqYBpzAFwU5yxBUo88ggoBqu1qPcHUfSbKK1sKMLmC7EAk438btHQrSdu3jGGQa6PA71nvH5nkDexhLteJqkM4dQmWF9g/84'/1'/0'/0/*)";
    let change_desc = "pkh([3c31d632/84'/1'/0']tpubDCYwFkks2cg78N7eoYbBatsFEGje8vW8arSKW4rLwD1AU1s9KJMDRHE32JkvYERuiFjArrsH7qpWSpJATed5ShZbG9KsskA5Rmi6NSYgYN2/0/*)";
    let err = Wallet::new_no_persist(desc, change_desc, Network::Dev);
    assert!(
        matches!(err, Err(DescriptorError::ExternalAndInternalAreTheSame)),
        "expected same descriptors error, got {:?}",
        err,
    );
}

#[test]
fn test_descriptor_checksum() {
    let (wallet, _) = get_funded_wallet_pkh();
    let checksum = wallet.descriptor_checksum(KeychainKind::External);
    assert_eq!(checksum.len(), 8);

    let raw_descriptor = wallet
        .keychains()
        .next()
        .unwrap()
        .1
        .to_string()
        .split_once('#')
        .unwrap()
        .0
        .to_string();
    assert_eq!(calc_checksum(&raw_descriptor).unwrap(), checksum);
}

#[test]
fn test_get_funded_wallet_balance() {
    let (wallet, _) = get_funded_wallet_pkh();

    // The funded wallet contains a tx with a 76_000 sats input and two outputs, one spending 25_000
    // to a foreign address and one returning 50_000 back to the wallet as change. The remaining 1000
    // sats are the transaction fee.
    assert_eq!(
        wallet.balance(ColorIdentifier::default()).confirmed,
        Amount::from_tap(50_000)
    );
}

#[test]
fn test_get_funded_wallet_colored_balance() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (wallet, _, color_id) = get_funded_wallet_with_nft_and_change(get_test_pkh(), change_desc);

    // The funded wallet contains a tx with a 76_000 sats input and three outputs, one spending 25_000
    // to a foreign address, one returning 50_000 back to the wallet as change, and one issuing NFT to the wallet.
    // The remaining 1000 taps are the transaction fee.
    assert_eq!(
        wallet.balance(ColorIdentifier::default()).confirmed,
        Amount::from_tap(50_000)
    );
    assert_eq!(wallet.balance(color_id).confirmed, Amount::ONE_TAP);
}

#[test]
fn test_get_funded_wallet_p2c_balance() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (wallet, _, _, _) = get_funded_wallet_with_p2c_and_change(get_test_pkh(), change_desc);

    assert_eq!(
        wallet.balance(ColorIdentifier::default()).confirmed,
        Amount::from_tap(50_000)
    );
}

#[test]
fn test_get_funded_wallet_colored_p2c_balance() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (wallet, _, _, _, color_id) =
        get_funded_wallet_with_colored_p2c_and_change(get_test_pkh(), change_desc);

    assert_eq!(wallet.balance(color_id).confirmed, Amount::from_tap(100));
    assert_eq!(
        wallet.balance(ColorIdentifier::default()).confirmed,
        Amount::from_tap(50_000)
    );
}

#[test]
fn test_get_funded_wallet_sent_and_received() {
    let (wallet, txid) = get_funded_wallet_pkh();

    let mut tx_amounts: Vec<(MalFixTxid, (Amount, Amount))> = wallet
        .transactions()
        .map(|ct| {
            (
                ct.tx_node.txid,
                wallet.sent_and_received(&ct.tx_node, &ColorIdentifier::default()),
            )
        })
        .collect();
    tx_amounts.sort_by(|a1, a2| a1.0.cmp(&a2.0));

    let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    let (sent, received) = wallet.sent_and_received(&tx, &ColorIdentifier::default());

    // The funded wallet contains a tx with a 76_000 sats input and two outputs, one spending 25_000
    // to a foreign address and one returning 50_000 back to the wallet as change. The remaining 1000
    // sats are the transaction fee.
    assert_eq!(sent.to_tap(), 76_000);
    assert_eq!(received.to_tap(), 50_000);
}

#[test]
fn test_get_funded_wallet_with_color_sent_and_received() {
    let change_desc = "pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)";
    let (wallet, txid, color_id) =
        get_funded_wallet_with_nft_and_change(get_test_pkh(), change_desc);

    let mut tx_amounts: Vec<(MalFixTxid, (Amount, Amount))> = wallet
        .transactions()
        .map(|ct| {
            (
                ct.tx_node.txid,
                wallet.sent_and_received(&ct.tx_node, &color_id),
            )
        })
        .collect();
    tx_amounts.sort_by(|a1, a2| a1.0.cmp(&a2.0));

    let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    let (sent, received) = wallet.sent_and_received(&tx, &color_id);

    assert_eq!(sent.to_tap(), 0);
    assert_eq!(received.to_tap(), 1);
}

#[test]
fn test_get_funded_wallet_with_p2c_sent_and_received() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (wallet, txid, _, _, color_id) =
        get_funded_wallet_with_colored_p2c_and_change(get_test_pkh(), change_desc);

    let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    let (sent, received) = wallet.sent_and_received(&tx, &color_id);
    assert_eq!(sent.to_tap(), 0);
    assert_eq!(received.to_tap(), 100);
}

#[test]
fn test_get_funded_wallet_tx_fees() {
    let (wallet, txid) = get_funded_wallet_pkh();

    let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    let tx_fee = wallet.calculate_fee(&tx).expect("transaction fee");

    // The funded wallet contains a tx with a 76_000 sats input and two outputs, one spending 25_000
    // to a foreign address and one returning 50_000 back to the wallet as change. The remaining 1000
    // sats are the transaction fee.
    assert_eq!(tx_fee, Amount::from_tap(1000))
}

#[test]
fn test_get_funded_wallet_tx_fee_rate() {
    let (wallet, txid) = get_funded_wallet_pkh();

    let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    let tx_fee_rate = wallet
        .calculate_fee_rate(&tx)
        .expect("transaction fee rate");

    // The funded wallet contains a tx with a 76_000 taps input and two outputs, one spending 25_000
    // to a foreign address and one returning 50_000 back to the wallet as change. The remaining 1000
    // taps are the transaction fee.

    // tx weight = 476 wu, as vbytes = (476 + 3) / 4 = 119
    // fee_rate (sats per kwu) = fee / weight = 1000tap / 0.476kwu = 2100
    // fee_rate (sats per vbyte ceil) = fee / vsize = 1000tap / 119vb = 9
    assert_eq!(tx_fee_rate.to_tap_per_kwu(), 2100);
    assert_eq!(tx_fee_rate.to_tap_per_vb_ceil(), 9);
}

#[test]
fn test_list_output() {
    let (wallet, txid) = get_funded_wallet_pkh();
    let txos = wallet
        .list_output()
        .map(|op| (op.outpoint, op))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(txos.len(), 2);
    for (op, txo) in txos {
        if op.txid == txid {
            assert_eq!(txo.txout.value.to_tap(), 50_000);
            assert!(!txo.is_spent);
        } else {
            assert_eq!(txo.txout.value.to_tap(), 76_000);
            assert!(txo.is_spent);
        }
    }
}

macro_rules! assert_fee_rate {
    ($psbt:expr, $fees:expr, $fee_rate:expr $( ,@dust_change $( $dust_change:expr )* )* $( ,@add_signature $( $add_signature:expr )* )* ) => ({
        let psbt = $psbt.clone();
        #[allow(unused_mut)]
        let mut tx = $psbt.clone().extract_tx().expect("failed to extract tx");
        $(
            $( $add_signature )*
                for txin in &mut tx.input {
                    txin.script_sig = ScriptBuf::from_bytes(vec![0x00; P2PKH_FAKE_SCRIPT_SIG_SIZE]);
                }
        )*

            #[allow(unused_mut)]
        #[allow(unused_assignments)]
        let mut dust_change = false;
        $(
            $( $dust_change )*
                dust_change = true;
        )*

            let fee_amount = psbt
            .inputs
            .iter()
            .enumerate()
            .fold(Amount::ZERO, |acc, (index, input)| {
              let txin = &psbt.unsigned_tx.input[index];
              let vout = txin.previous_output.vout as usize;
              acc + input.non_witness_utxo.as_ref().unwrap().output[vout].value
            })
            - psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Amount::ZERO, |acc, o| acc + o.value);

        assert_eq!(fee_amount, $fees);

        let tx_fee_rate = (fee_amount / tx.weight())
            .to_tap_per_kwu();
        let fee_rate = $fee_rate.to_tap_per_kwu();
        let half_default = FeeRate::BROADCAST_MIN.checked_div(2)
            .unwrap()
            .to_tap_per_kwu();

        if !dust_change {
            assert!(tx_fee_rate >= fee_rate && tx_fee_rate - fee_rate < half_default, "Expected fee rate of {:?}, the tx has {:?}", fee_rate, tx_fee_rate);
        } else {
            assert!(tx_fee_rate >= fee_rate, "Expected fee rate of at least {:?}, the tx has {:?}", fee_rate, tx_fee_rate);
        }
    });
}

macro_rules! from_str {
    ($e:expr, $t:ty) => {{
        use core::str::FromStr;
        <$t>::from_str($e).unwrap()
    }};

    ($e:expr) => {
        from_str!($e, _)
    };
}

#[test]
#[should_panic(expected = "NoRecipients")]
fn test_create_tx_empty_recipients() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    wallet.build_tx().finish().unwrap();
}

#[test]
#[should_panic(expected = "NoUtxosSelected")]
fn test_create_tx_manually_selected_empty_utxos() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .manually_selected_only();
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_version_0() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .version(0);
    assert!(matches!(builder.finish(), Err(CreateTxError::Version0)));
}

#[test]
fn test_create_tx_version_1_csv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .version(1);
    assert!(matches!(builder.finish(), Err(CreateTxError::Version1Csv)));
}

#[test]
fn test_create_tx_custom_version() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .version(42);
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.version.0, 42);
}

#[test]
fn test_create_tx_default_locktime_is_last_sync_height() {
    let (mut wallet, _) = get_funded_wallet_pkh();

    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    // Since we never synced the wallet we don't have a last_sync_height
    // we could use to try to prevent fee sniping. We default to 0.
    assert_eq!(psbt.unsigned_tx.lock_time.to_consensus_u32(), 2_000);
}

#[test]
fn test_create_tx_fee_sniping_locktime_last_sync() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));

    let psbt = builder.finish().unwrap();

    // If there's no current_height we're left with using the last sync height
    assert_eq!(
        psbt.unsigned_tx.lock_time.to_consensus_u32(),
        wallet.latest_checkpoint().height()
    );
}

#[test]
fn test_create_tx_default_locktime_cltv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.lock_time.to_consensus_u32(), 100_000);
}

#[test]
fn test_create_tx_custom_locktime() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .current_height(630_001)
        .nlocktime(absolute::LockTime::from_height(630_000).unwrap());
    let psbt = builder.finish().unwrap();

    // When we explicitly specify a nlocktime
    // we don't try any fee sniping prevention trick
    // (we ignore the current_height)
    assert_eq!(psbt.unsigned_tx.lock_time.to_consensus_u32(), 630_000);
}

#[test]
fn test_create_tx_custom_locktime_compatible_with_cltv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .nlocktime(absolute::LockTime::from_height(630_000).unwrap());
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.lock_time.to_consensus_u32(), 630_000);
}

#[test]
fn test_create_tx_custom_locktime_incompatible_with_cltv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .nlocktime(absolute::LockTime::from_height(50000).unwrap());
    assert!(matches!(builder.finish(),
        Err(CreateTxError::LockTime { requested, required })
        if requested.to_consensus_u32() == 50_000 && required.to_consensus_u32() == 100_000));
}

#[test]
fn test_create_tx_no_rbf_csv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(6));
}

#[test]
fn test_create_tx_with_default_rbf_csv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    // When CSV is enabled it takes precedence over the rbf value (unless forced by the user).
    // It will be set to the OP_CSV value, in this case 6
    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(6));
}

#[test]
fn test_create_tx_with_custom_rbf_csv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf_with_sequence(Sequence(3));
    assert!(matches!(builder.finish(),
        Err(CreateTxError::RbfSequenceCsv { rbf, csv })
        if rbf.to_consensus_u32() == 3 && csv.to_consensus_u32() == 6));
}

#[test]
fn test_create_tx_no_rbf_cltv() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(0xFFFFFFFE));
}

#[test]
fn test_create_tx_invalid_rbf_sequence() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf_with_sequence(Sequence(0xFFFFFFFE));
    assert!(matches!(builder.finish(), Err(CreateTxError::RbfSequence)));
}

#[test]
fn test_create_tx_custom_rbf_sequence() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf_with_sequence(Sequence(0xDEADBEEF));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(0xDEADBEEF));
}

#[test]
fn test_create_tx_change_policy() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .do_not_spend_change();
    assert!(builder.finish().is_ok());

    // wallet has no change, so setting `only_spend_change`
    // should cause tx building to fail
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .only_spend_change();
    assert!(matches!(
        builder.finish(),
        Err(CreateTxError::CoinSelection(
            coin_selection::Error::InsufficientFunds { .. }
        )),
    ));
}

#[test]
fn test_create_tx_default_sequence() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(0xFFFFFFFE));
}

macro_rules! check_fee {
    ($wallet:expr, $psbt: expr) => {{
        let tx = $psbt.clone().extract_tx().expect("failed to extract tx");
        let tx_fee = $wallet.calculate_fee(&tx).ok();
        assert_eq!(tx_fee, $psbt.fee_amount());
        tx_fee
    }};
}

#[test]
fn test_create_tx_drain_wallet_and_drain_to() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_tap(50_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
fn test_create_tx_drain_wallet_and_drain_to_and_with_recipient() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt")
        .unwrap()
        .assume_checked();
    let drain_addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(20_000))
        .drain_to(drain_addr.script_pubkey())
        .drain_wallet();
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);
    let outputs = psbt.unsigned_tx.output;

    assert_eq!(outputs.len(), 2);
    let main_output = outputs
        .iter()
        .find(|x| x.script_pubkey == addr.script_pubkey())
        .unwrap();
    let drain_output = outputs
        .iter()
        .find(|x| x.script_pubkey == drain_addr.script_pubkey())
        .unwrap();
    assert_eq!(main_output.value, Amount::from_tap(20_000));
    assert_eq!(
        drain_output.value,
        Amount::from_tap(30_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
fn test_create_tx_drain_to_and_utxos() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let utxos: Vec<_> = wallet.list_unspent().map(|u| u.outpoint).collect();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxos(&utxos)
        .unwrap();
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_tap(50_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
#[should_panic(expected = "NoRecipients")]
fn test_create_tx_drain_to_no_drain_wallet_no_utxos() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let drain_addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(drain_addr.script_pubkey());
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_default_fee_rate() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::BROADCAST_MIN, @add_signature);
}

#[test]
fn test_create_tx_custom_fee_rate() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(5));
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::from_tap_per_vb_unchecked(5), @add_signature);
}

#[test]
fn test_create_tx_absolute_fee() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(Amount::from_tap(100));
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(100));
    assert_eq!(psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_tap(50_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
fn test_create_tx_absolute_zero_fee() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(Amount::ZERO);
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::ZERO);
    assert_eq!(psbt.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_tap(50_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_absolute_high_fee() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(Amount::from_tap(60_000));
    let _ = builder.finish().unwrap();
}

#[test]
fn test_create_tx_add_change() {
    use tdk_wallet::wallet::tx_builder::TxOrdering;

    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .ordering(TxOrdering::Untouched);
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.unsigned_tx.output.len(), 2);
    assert_eq!(psbt.unsigned_tx.output[0].value, Amount::from_tap(25_000));
    assert_eq!(
        psbt.unsigned_tx.output[1].value,
        Amount::from_tap(25_000) - fee.unwrap_or(Amount::ZERO)
    );
}

#[test]
fn test_create_tx_skip_change_dust() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(49_800));
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.unsigned_tx.output.len(), 1);
    assert_eq!(psbt.unsigned_tx.output[0].value.to_tap(), 49_800);
    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(200));
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_drain_to_dust_amount() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    // very high fee rate, so that the only output would be below dust
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(454));
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_ordering_respected() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .add_recipient(addr.script_pubkey(), Amount::from_tap(10_000))
        .ordering(tdk_wallet::wallet::tx_builder::TxOrdering::Bip69Lexicographic);
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.unsigned_tx.output.len(), 3);
    assert_eq!(
        psbt.unsigned_tx.output[0].value,
        Amount::from_tap(10_000) - fee.unwrap_or(Amount::ZERO)
    );
    assert_eq!(psbt.unsigned_tx.output[1].value, Amount::from_tap(10_000));
    assert_eq!(psbt.unsigned_tx.output[2].value, Amount::from_tap(30_000));
}

#[test]
fn test_create_tx_default_sighash() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(30_000));
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.inputs[0].sighash_type, None);
}

#[test]
fn test_create_tx_custom_sighash() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .sighash(EcdsaSighashType::Single.into());
    let psbt = builder.finish().unwrap();

    assert_eq!(
        psbt.inputs[0].sighash_type,
        Some(EcdsaSighashType::Single.into())
    );
}

#[test]
fn test_create_tx_input_hd_keypaths() {
    use core::str::FromStr;
    use tapyrus::bip32::{DerivationPath, Fingerprint};

    let (mut wallet, _) = get_funded_wallet("pkh([d34db33f/44'/0'/0']tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 1);
    assert_eq!(
        psbt.inputs[0].bip32_derivation.values().next().unwrap(),
        &(
            Fingerprint::from_str("d34db33f").unwrap(),
            DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap()
        )
    );
}

#[test]
fn test_create_tx_output_hd_keypaths() {
    use core::str::FromStr;
    use tapyrus::bip32::{DerivationPath, Fingerprint};

    let (mut wallet, _) = get_funded_wallet("pkh([d34db33f/44'/0'/0']tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)");

    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.outputs[0].bip32_derivation.len(), 1);
    let expected_derivation_path = format!("m/44'/0'/0'/0/{}", addr.index);
    assert_eq!(
        psbt.outputs[0].bip32_derivation.values().next().unwrap(),
        &(
            Fingerprint::from_str("d34db33f").unwrap(),
            DerivationPath::from_str(&expected_derivation_path).unwrap()
        )
    );
}

#[test]
fn test_create_tx_set_redeem_script_p2sh() {
    use tapyrus::hex::FromHex;

    let (mut wallet, _) =
        get_funded_wallet("sh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();

    assert_eq!(
        psbt.inputs[0].redeem_script,
        Some(ScriptBuf::from(
            Vec::<u8>::from_hex(
                "21032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3ac"
            )
            .unwrap()
        ))
    );
    assert_eq!(psbt.inputs[0].witness_script, None);
}

#[test]
fn test_create_tx_non_witness_utxo() {
    let (mut wallet, _) =
        get_funded_wallet("sh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();

    assert!(psbt.inputs[0].non_witness_utxo.is_some());
    assert!(psbt.inputs[0].witness_utxo.is_none());
}

#[test]
fn test_create_tx_only_has_non_witness_utxo_default() {
    let (mut wallet, _) =
        get_funded_wallet("sh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let psbt = builder.finish().unwrap();

    assert!(psbt.inputs[0].non_witness_utxo.is_some());
    assert!(psbt.inputs[0].witness_utxo.is_none());
}

#[test]
fn test_create_tx_add_utxo() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let small_output_tx = Transaction {
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
        version: transaction::Version::non_standard(0),
        lock_time: absolute::LockTime::ZERO,
    };
    wallet
        .insert_tx(
            small_output_tx.clone(),
            ConfirmationTime::Unconfirmed { last_seen: 0 },
        )
        .unwrap();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .add_utxo(OutPoint {
            txid: small_output_tx.malfix_txid(),
            vout: 0,
        })
        .unwrap();
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );

    assert_eq!(
        psbt.unsigned_tx.input.len(),
        2,
        "should add an additional input since 25_000 < 30_000"
    );
    assert_eq!(
        sent_received.0,
        Amount::from_tap(75_000),
        "total should be sum of both inputs"
    );
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_manually_selected_insufficient() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let small_output_tx = Transaction {
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
        version: transaction::Version::non_standard(0),
        lock_time: absolute::LockTime::ZERO,
    };

    wallet
        .insert_tx(
            small_output_tx.clone(),
            ConfirmationTime::Unconfirmed { last_seen: 0 },
        )
        .unwrap();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .add_utxo(OutPoint {
            txid: small_output_tx.malfix_txid(),
            vout: 0,
        })
        .unwrap()
        .manually_selected_only();
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "SpendingPolicyRequired(External)")]
fn test_create_tx_policy_path_required() {
    let (mut wallet, _) = get_funded_wallet(get_test_a_or_b_plus_csv());

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(10_000));
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_policy_path_no_csv() {
    let (desc, change_desc) = get_test_pkh_with_change_desc();
    let mut wallet = Wallet::new_no_persist(desc, change_desc, Network::Dev).unwrap();

    let tx = Transaction {
        version: transaction::Version::non_standard(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(50_000),
        }],
    };
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let external_policy = wallet.policies(KeychainKind::External).unwrap().unwrap();
    let root_id = external_policy.id;
    // child #0 is just the key "A"
    let path = vec![(root_id, vec![0])].into_iter().collect();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .policy_path(path, KeychainKind::External);
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(0xFFFFFFFF));
}

#[test]
fn test_create_tx_policy_path_use_csv() {
    let (mut wallet, _) = get_funded_wallet(get_test_a_or_b_plus_csv());

    let external_policy = wallet.policies(KeychainKind::External).unwrap().unwrap();
    let root_id = external_policy.id;
    // child #1 is or(pk(B),older(144))
    let path = vec![(root_id, vec![1])].into_iter().collect();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .policy_path(path, KeychainKind::External);
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(144));
}

#[test]
fn test_create_tx_policy_path_ignored_subtree_with_csv() {
    let (mut wallet, _) = get_funded_wallet("sh(or_d(pk(cRjo6jqfVNP33HhSS76UhXETZsGTZYx8FMFvR9kpbtCSV1PmdZdu),or_i(and_v(v:pkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(30)),and_v(v:pkh(cMnkdebixpXMPfkcNEjjGin7s94hiehAH4mLbYkZoh9KSiNNmqC8),older(90)))))");

    let external_policy = wallet.policies(KeychainKind::External).unwrap().unwrap();
    let root_id = external_policy.id;
    // child #0 is pk(cRjo6jqfVNP33HhSS76UhXETZsGTZYx8FMFvR9kpbtCSV1PmdZdu)
    let path = vec![(root_id, vec![0])].into_iter().collect();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(30_000))
        .policy_path(path, KeychainKind::External);
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.unsigned_tx.input[0].sequence, Sequence(0xFFFFFFFE));
}

#[test]
fn test_create_tx_with_nft() {
    let change_desc = "pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)";
    let (mut wallet, _, color_id) =
        get_funded_wallet_with_nft_and_change(get_test_pkh(), change_desc);
    let mut builder = wallet.build_tx();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .add_recipient_with_color(addr.script_pubkey(), Amount::from_tap(1), color_id);
    let psbt = builder.finish().unwrap();

    let fee = check_fee!(wallet, psbt);
    let fee_rate = FeeRate::from_tap_per_kwu(250); // 1 tap/vb
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), fee_rate, @add_signature);

    assert_eq!(psbt.unsigned_tx.output.len(), 3);
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &color_id,
    );
    assert_eq!(sent_received, (Amount::from_tap(1), Amount::from_tap(0)));
}

#[test]
fn test_create_tx_with_reissuable() {
    let change_desc = "pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)";
    let (mut wallet, _, color_id) =
        get_funded_wallet_with_reissuable_and_change(get_test_pkh(), change_desc);
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .add_recipient_with_color(addr.script_pubkey(), Amount::from_tap(98), color_id);
    let psbt = builder.finish().unwrap();

    let fee = check_fee!(wallet, psbt);
    let fee_rate = FeeRate::from_tap_per_kwu(250); // 1 tap/vb
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), fee_rate, @add_signature);

    assert_eq!(psbt.unsigned_tx.output.len(), 4);

    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &color_id,
    );
    assert_eq!(sent_received, (Amount::from_tap(100), Amount::from_tap(2)));
}

#[test]
fn test_create_tx_with_contract() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (mut wallet, txid, address, contract) =
        get_funded_wallet_with_p2c_and_change(get_test_pkh(), change_desc);
    let mut contracts = BTreeMap::new();
    contracts.insert(contract.clone().contract_id, contract.clone());

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(48_000))
        .add_contract_utxo(OutPoint { txid, vout: 0 });
    let mut psbt = builder.finish().unwrap();
    check_fee!(wallet, psbt);
    assert_eq!(psbt.unsigned_tx.output.len(), 2);
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    assert_eq!(
        sent_received,
        (
            Amount::from_tap(50_000),
            Amount::from_tap(2_000) - psbt.fee_amount().unwrap()
        )
    );

    let finished = wallet.sign(
        &mut psbt,
        SignOptions {
            contracts,
            trust_witness_utxo: true,
            ..Default::default()
        },
    );

    let ret = finished.unwrap();
    assert!(ret, "transaction should be signed");
}

#[test]
fn test_create_tx_with_contract_unspendable() {
    let change_desc = "pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/1)";
    let (mut wallet, txid, address, contract) =
        get_funded_wallet_with_p2c_and_change(get_test_pkh(), change_desc);
    let contract_id = contract.clone().contract_id;
    let mut contracts = BTreeMap::new();
    contracts.insert(contract_id.clone(), contract.clone());

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();

    // make contract unspendable
    wallet.update_contract(contract_id.clone(), false);
    {
        // Can use as contract utxo
        let mut builder = wallet.build_tx();
        builder
            .add_recipient(addr.script_pubkey(), Amount::from_tap(48_000))
            .add_contract_utxo(OutPoint { txid, vout: 0 });

        let mut psbt = builder.finish().unwrap();
        let finished = wallet.sign(
            &mut psbt,
            SignOptions {
                contracts: contracts.clone(),
                trust_witness_utxo: true,
                ..Default::default()
            },
        );

        let ret = finished.unwrap();
        assert!(ret, "can spend contract utxo");
    }
    {
        // Can not use as ordinal utxo
        let mut builder = wallet.build_tx();
        builder.add_recipient(addr.script_pubkey(), Amount::from_tap(48_000));

        let ret = builder.finish();
        assert!(ret.is_err(), "can spend as ordinal utxo");
    }

    // make contract spendable
    wallet.update_contract(contract_id.clone(), true);

    {
        // Can use as contract utxo
        let mut builder = wallet.build_tx();
        builder
            .add_recipient(addr.script_pubkey(), Amount::from_tap(48_000))
            .add_contract_utxo(OutPoint { txid, vout: 0 });

        let mut psbt = builder.finish().unwrap();
        let finished = wallet.sign(
            &mut psbt,
            SignOptions {
                contracts: contracts.clone(),
                trust_witness_utxo: true,
                ..Default::default()
            },
        );

        let ret = finished.unwrap();
        println!("test_create_tx_with_contract_unspendable: {:?}", ret);
        assert!(ret, "can spend as contract");
    }

    {
        // Can use as ordinal utxo
        let mut builder = wallet.build_tx();
        builder.add_recipient(addr.script_pubkey(), Amount::from_tap(48_000));

        let mut psbt = builder.finish().unwrap();
        let finished = wallet.sign(
            &mut psbt,
            SignOptions {
                contracts: contracts.clone(),
                trust_witness_utxo: true,
                ..Default::default()
            },
        );

        let ret = finished.unwrap();
        assert!(ret, "can spend as ordinal utxo");
    }
}

// TODO: Fix this test
#[test]
fn test_create_tx_multi_colored_coin_recipients() {
    let change_desc = "pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)";
    let (mut wallet, _, color_id) =
        get_funded_wallet_with_reissuable_and_change(get_test_pkh(), change_desc);
    let addr1 = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let addr2 = Address::from_str("16wow9KqkSfdLL4bjP83N5wa5cUU48HwQM")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient_with_color(addr1.script_pubkey(), Amount::from_tap(10), color_id)
        .add_recipient_with_color(addr2.script_pubkey(), Amount::from_tap(25), color_id)
        .add_recipient_with_color(addr2.script_pubkey(), Amount::from_tap(15), color_id);
    let psbt = builder.finish().unwrap();

    let fee = check_fee!(wallet, psbt);
    let feerate = FeeRate::from_tap_per_kwu(250); // 1 sat/vb
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), feerate, @add_signature);

    assert_eq!(psbt.unsigned_tx.output.len(), 5);

    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &color_id,
    );
    assert_eq!(sent_received, (Amount::from_tap(100), Amount::from_tap(50)));
}

#[test]
fn test_create_tx_multi_color_id() {
    let (desc, change) = get_test_pkh_single_sig_xprv_with_change_desc();
    let (mut wallet, _, color_id1, color_id2) =
        get_funded_wallet_with_two_colored_coin_and_change(desc, change);

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient_with_color(addr.script_pubkey(), Amount::from_tap(10), color_id1)
        .add_recipient_with_color(addr.script_pubkey(), Amount::from_tap(20), color_id2);
    let psbt = builder.finish().unwrap();

    let fee = check_fee!(wallet, psbt);
    let feerate = FeeRate::from_tap_per_kwu(250); // 1 sat/vb
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), feerate, @add_signature);

    assert_eq!(psbt.unsigned_tx.output.len(), 5);

    let sent_received1 = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &color_id1,
    );
    assert_eq!(
        sent_received1,
        (Amount::from_tap(100), Amount::from_tap(90))
    );

    let sent_received2 = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &color_id2,
    );
    assert_eq!(
        sent_received2,
        (Amount::from_tap(150), Amount::from_tap(130))
    );
}

#[test]
fn test_create_tx_global_xpubs_with_origin() {
    use tapyrus::bip32;
    use tapyrus::hex::FromHex;

    let (mut wallet, _) = get_funded_wallet("pkh([73756c7f/48'/0'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .add_global_xpubs();
    let psbt = builder.finish().unwrap();

    let key = bip32::Xpub::from_str("tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3").unwrap();
    let fingerprint = bip32::Fingerprint::from_hex("73756c7f").unwrap();
    let path = bip32::DerivationPath::from_str("m/48'/0'/0'/2'").unwrap();

    assert_eq!(psbt.xpub.len(), 2);
    assert_eq!(psbt.xpub.get(&key), Some(&(fingerprint, path)));
}

#[test]
fn test_add_foreign_utxo() {
    let (mut wallet1, _) = get_funded_wallet_pkh();
    let (wallet2, _) =
        get_funded_wallet("pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let utxo = wallet2.list_unspent().next().expect("must take!");
    let tx = wallet2.get_tx(utxo.outpoint.txid).unwrap().tx_node.tx;
    let foreign_utxo_satisfaction = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_weight_to_satisfy()
        .unwrap();

    let psbt_input = psbt::Input {
        non_witness_utxo: Some((*tx).clone()),
        ..Default::default()
    };

    let mut builder: tdk_wallet::TxBuilder<coin_selection::BranchAndBoundCoinSelection> =
        wallet1.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(60_000))
        .add_foreign_utxo(utxo.outpoint, psbt_input, foreign_utxo_satisfaction)
        .unwrap();
    let mut psbt = builder.finish().unwrap();
    wallet1.insert_txout(utxo.outpoint, utxo.txout);
    let fee = check_fee!(wallet1, psbt);
    let sent_received = wallet1.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );

    assert_eq!(
        (sent_received.0 - sent_received.1),
        Amount::from_tap(10_000) + fee.unwrap_or(Amount::ZERO),
        "we should have only net spent ~10_000"
    );

    assert!(
        psbt.unsigned_tx
            .input
            .iter()
            .any(|input| input.previous_output == utxo.outpoint),
        "foreign_utxo should be in there"
    );

    let finished = wallet1
        .sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )
        .unwrap();

    assert!(
        !finished,
        "only one of the inputs should have been signed so far"
    );

    let finished = wallet2
        .sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(finished, "all the inputs should have been signed now");
}

#[test]
#[should_panic(
    expected = "MissingTxOut([OutPoint { txid: 0x08149b04bc4860243f99a9b2732d8c6ae9cfd162166e49bbed1eb456d3ea07ac, vout: 0 }])"
)]
fn test_calculate_fee_with_missing_foreign_utxo() {
    let (mut wallet1, _) = get_funded_wallet_pkh();
    let (wallet2, _) =
        get_funded_wallet("pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let utxo = wallet2.list_unspent().next().expect("must take!");
    let foreign_utxo_satisfaction = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_weight_to_satisfy()
        .unwrap();

    let psbt_input = psbt::Input {
        non_witness_utxo: Some(
            wallet2
                .get_tx(utxo.outpoint.txid)
                .unwrap()
                .tx_node
                .tx
                .as_ref()
                .clone(),
        ),
        ..Default::default()
    };

    let mut builder = wallet1.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(60_000))
        .add_foreign_utxo(utxo.outpoint, psbt_input, foreign_utxo_satisfaction)
        .unwrap();
    let psbt = builder.finish().unwrap();
    let tx = psbt.extract_tx().expect("failed to extract tx");
    wallet1.calculate_fee(&tx).unwrap();
}

#[test]
fn test_add_foreign_utxo_invalid_psbt_input() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let outpoint = wallet.list_unspent().next().expect("must exist").outpoint;
    let foreign_utxo_satisfaction = wallet
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_weight_to_satisfy()
        .unwrap();

    let mut builder = wallet.build_tx();
    let result =
        builder.add_foreign_utxo(outpoint, psbt::Input::default(), foreign_utxo_satisfaction);
    assert!(matches!(result, Err(AddForeignUtxoError::MissingUtxo)));
}

#[test]
fn test_add_foreign_utxo_where_outpoint_doesnt_match_psbt_input() {
    let (mut wallet1, txid1) = get_funded_wallet_pkh();
    let (wallet2, txid2) =
        get_funded_wallet("pkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");

    let utxo2 = wallet2.list_unspent().next().unwrap();
    let tx1 = wallet1.get_tx(txid1).unwrap().tx_node.tx.clone();
    let tx2 = wallet2.get_tx(txid2).unwrap().tx_node.tx.clone();

    let satisfaction_weight = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_weight_to_satisfy()
        .unwrap();

    let mut builder = wallet1.build_tx();
    assert!(
        builder
            .add_foreign_utxo(
                utxo2.outpoint,
                psbt::Input {
                    non_witness_utxo: Some(tx1.as_ref().clone()),
                    ..Default::default()
                },
                satisfaction_weight
            )
            .is_err(),
        "should fail when outpoint doesn't match psbt_input"
    );
    assert!(
        builder
            .add_foreign_utxo(
                utxo2.outpoint,
                psbt::Input {
                    non_witness_utxo: Some(tx2.as_ref().clone()),
                    ..Default::default()
                },
                satisfaction_weight
            )
            .is_ok(),
        "should be ok when outpoint does match psbt_input"
    );
}

#[test]
fn test_get_psbt_input() {
    // this should grab a known good utxo and set the input
    let (wallet, _) = get_funded_wallet_pkh();
    for utxo in wallet.list_unspent() {
        let psbt_input = wallet.get_psbt_input(utxo, None, false).unwrap();
        assert!(psbt_input.witness_utxo.is_some() || psbt_input.non_witness_utxo.is_some());
    }
}

#[test]
#[should_panic(
    expected = "MissingKeyOrigin(\"tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3\")"
)]
fn test_create_tx_global_xpubs_origin_missing() {
    let (mut wallet, _) = get_funded_wallet("pkh(tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .add_global_xpubs();
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_global_xpubs_master_without_origin() {
    use tapyrus::bip32;
    use tapyrus::hex::FromHex;

    let (mut wallet, _) = get_funded_wallet("pkh(tpubD6NzVbkrYhZ4Y55A58Gv9RSNF5hy84b5AJqYy7sCcjFrkcLpPre8kmgfit6kY1Zs3BLgeypTDBZJM222guPpdz7Cup5yzaMu62u7mYGbwFL/0/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .add_global_xpubs();
    let psbt = builder.finish().unwrap();

    let key = bip32::Xpub::from_str("tpubD6NzVbkrYhZ4Y55A58Gv9RSNF5hy84b5AJqYy7sCcjFrkcLpPre8kmgfit6kY1Zs3BLgeypTDBZJM222guPpdz7Cup5yzaMu62u7mYGbwFL").unwrap();
    let fingerprint = bip32::Fingerprint::from_hex("997a323b").unwrap();

    assert_eq!(psbt.xpub.len(), 2);
    assert_eq!(
        psbt.xpub.get(&key),
        Some(&(fingerprint, bip32::DerivationPath::default()))
    );
}

#[test]
#[should_panic(expected = "IrreplaceableTransaction")]
fn test_bump_fee_irreplaceable_tx() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();
    wallet.build_fee_bump(txid).unwrap().finish().unwrap();
}

#[test]
#[should_panic(expected = "TransactionConfirmed")]
fn test_bump_fee_confirmed_tx() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let psbt = builder.finish().unwrap();

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();

    wallet
        .insert_tx(
            tx,
            ConfirmationTime::Confirmed {
                height: 42,
                time: 42_000,
            },
        )
        .unwrap();

    wallet.build_fee_bump(txid).unwrap().finish().unwrap();
}

#[test]
fn test_bump_fee_low_fee_rate() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let feerate = psbt.fee_rate().unwrap();

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();

    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::BROADCAST_MIN);
    let res = builder.finish();
    assert_matches!(
        res,
        Err(CreateTxError::FeeRateTooLow { .. }),
        "expected FeeRateTooLow error"
    );

    let required = feerate.to_tap_per_kwu() + 250; // +1 sat/vb
    let sat_vb = required as f64 / 250.0;
    let expect = format!("Fee rate too low: required {} sat/vb", sat_vb);
    assert_eq!(res.unwrap_err().to_string(), expect);
}

#[test]
#[should_panic(expected = "FeeTooLow")]
fn test_bump_fee_low_abs() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();

    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(Amount::from_tap(10));
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "FeeTooLow")]
fn test_bump_fee_zero_abs() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(Amount::ZERO);
    builder.finish().unwrap();
}

#[test]
fn test_bump_fee_reduce_change() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(25_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let original_sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let original_fee = check_fee!(wallet, psbt);

    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    for txin in &mut tx.input {
        txin.script_sig = ScriptBuf::from_bytes(vec![0x00; P2PKH_FAKE_SCRIPT_SIG_SIZE]);
    }
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let feerate = FeeRate::from_tap_per_kwu(625); // 2.5 sat/vb
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(feerate).enable_rbf();
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(sent_received.0, original_sent_received.0);
    assert_eq!(
        sent_received.1 + fee.unwrap_or(Amount::ZERO),
        original_sent_received.1 + original_fee.unwrap_or(Amount::ZERO)
    );
    assert!(fee.unwrap_or(Amount::ZERO) > original_fee.unwrap_or(Amount::ZERO));

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(25_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), feerate, @add_signature);

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(Amount::from_tap(225));
    builder.enable_rbf();
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(sent_received.0, original_sent_received.0);
    assert_eq!(
        sent_received.1 + fee.unwrap_or(Amount::ZERO),
        original_sent_received.1 + original_fee.unwrap_or(Amount::ZERO)
    );
    assert!(
        fee.unwrap_or(Amount::ZERO) > original_fee.unwrap_or(Amount::ZERO),
        "{} > {}",
        fee.unwrap_or(Amount::ZERO),
        original_fee.unwrap_or(Amount::ZERO)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(25_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(225));
}

#[test]
fn test_bump_fee_reduce_single_recipient() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let mut tx = psbt.clone().extract_tx().expect("failed to extract tx");
    for txin in &mut tx.input {
        txin.script_sig = ScriptBuf::from_bytes(vec![0x00; P2PKH_FAKE_SCRIPT_SIG_SIZE]);
    }
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let original_fee = check_fee!(wallet, psbt);
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let feerate = FeeRate::from_tap_per_kwu(625); // 2.5 sat/vb
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .fee_rate(feerate)
        // remove original tx drain_to address and amount
        .set_recipients(Vec::new())
        // set back original drain_to address
        .drain_to(addr.script_pubkey())
        // drain wallet output amount will be re-calculated with new fee rate
        .drain_wallet();
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(sent_received.0, original_sent_received.0);
    assert!(fee.unwrap_or(Amount::ZERO) > original_fee.unwrap_or(Amount::ZERO));

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output[0].value + fee.unwrap_or(Amount::ZERO),
        sent_received.0
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), feerate, @add_signature);
}

#[test]
fn test_bump_fee_absolute_reduce_single_recipient() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let original_fee = check_fee!(wallet, psbt);
    let tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .fee_absolute(Amount::from_tap(300))
        // remove original tx drain_to address and amount
        .set_recipients(Vec::new())
        // set back original drain_to address
        .drain_to(addr.script_pubkey())
        // drain wallet output amount will be re-calculated with new fee rate
        .drain_wallet();
    let psbt = builder.finish().unwrap();
    let tx = &psbt.unsigned_tx;
    let sent_received = wallet.sent_and_received(tx, &ColorIdentifier::default());
    let fee = check_fee!(wallet, psbt);

    assert_eq!(sent_received.0, original_sent_received.0);
    assert!(fee.unwrap_or(Amount::ZERO) > original_fee.unwrap_or(Amount::ZERO));

    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output[0].value + fee.unwrap_or(Amount::ZERO),
        sent_received.0
    );

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(300));
}

#[test]
fn test_bump_fee_drain_wallet() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    // receive an extra tx so that our wallet has two utxos.
    let tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
    };
    wallet
        .insert_tx(
            tx.clone(),
            ConfirmationTime::Confirmed {
                height: wallet.latest_checkpoint().height(),
                time: 42_000,
            },
        )
        .unwrap();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();

    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(OutPoint {
            txid: tx.malfix_txid(),
            vout: 0,
        })
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());

    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();
    assert_eq!(original_sent_received.0, Amount::from_tap(25_000));

    // for the new feerate, it should be enough to reduce the output, but since we specify
    // `drain_wallet` we expect to spend everything
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .drain_wallet()
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(5));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );

    assert_eq!(sent_received.0, Amount::from_tap(75_000));
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_bump_fee_remove_output_manually_selected_only() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    // receive an extra tx so that our wallet has two utxos. then we manually pick only one of
    // them, and make sure that `bump_fee` doesn't try to add more. This fails because we've
    // told the wallet it's not allowed to add more inputs AND it can't reduce the value of the
    // existing output. In other words, bump_fee + manually_selected_only is always an error
    // unless there is a change output.
    let init_tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
    };
    wallet
        .insert_tx(
            init_tx.clone(),
            wallet
                .transactions()
                .last()
                .unwrap()
                .chain_position
                .cloned()
                .into(),
        )
        .unwrap();
    let outpoint = OutPoint {
        txid: init_tx.malfix_txid(),
        vout: 0,
    };
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(outpoint)
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();
    assert_eq!(original_sent_received.0, Amount::from_tap(25_000));

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .manually_selected_only()
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(255));
    builder.finish().unwrap();
}

#[test]
fn test_bump_fee_add_input() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let init_tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
    };
    let pos = wallet
        .transactions()
        .last()
        .unwrap()
        .chain_position
        .cloned()
        .into();
    wallet.insert_tx(init_tx, pos).unwrap();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(45_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let tx = psbt.extract_tx().expect("failed to extract tx");
    let original_details = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_tap_per_vb_unchecked(50));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);
    assert_eq!(
        sent_received.0,
        original_details.0 + Amount::from_tap(25_000)
    );
    assert_eq!(
        fee.unwrap_or(Amount::ZERO) + sent_received.1,
        Amount::from_tap(30_000)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(45_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::from_tap_per_vb_unchecked(50), @add_signature);
}

#[test]
fn test_bump_fee_absolute_add_input() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    receive_output_in_latest_block(&mut wallet, 25_000);
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(45_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(Amount::from_tap(6_000));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(
        sent_received.0,
        original_sent_received.0 + Amount::from_tap(25_000)
    );
    assert_eq!(
        fee.unwrap_or(Amount::ZERO) + sent_received.1,
        Amount::from_tap(30_000)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(45_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(6_000));
}

#[test]
fn test_bump_fee_no_change_add_input_and_change() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let op = receive_output_in_latest_block(&mut wallet, 25_000);

    // initially make a tx without change by using `drain_to`
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(op)
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let original_sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let original_fee = check_fee!(wallet, psbt);

    let tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    // Now bump the fees, the wallet should add an extra input and a change output, and leave
    // the original output untouched.
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_tap_per_vb_unchecked(50));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    let original_send_all_amount = original_sent_received.0 - original_fee.unwrap_or(Amount::ZERO);
    assert_eq!(
        sent_received.0,
        original_sent_received.0 + Amount::from_tap(50_000)
    );
    assert_eq!(
        sent_received.1,
        Amount::from_tap(75_000) - original_send_all_amount - fee.unwrap_or(Amount::ZERO)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        original_send_all_amount
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(75_000) - original_send_all_amount - fee.unwrap_or(Amount::ZERO)
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::from_tap_per_vb_unchecked(50), @add_signature);
}

#[test]
fn test_bump_fee_add_input_change_dust() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    receive_output_in_latest_block(&mut wallet, 25_000);
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(45_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let original_sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let original_fee = check_fee!(wallet, psbt);

    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    for txin in &mut tx.input {
        txin.script_sig = ScriptBuf::from_bytes(vec![0x00; P2PKH_FAKE_SCRIPT_SIG_SIZE]);
    }
    let original_tx_weight = tx.weight();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);
    let txid = tx.malfix_txid();
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    // We set a fee high enough that during rbf we are forced to add
    // a new input and also that we have to remove the change
    // that we had previously

    // We calculate the new weight as:
    //   original weight
    // + extra input weight: 592 WU = (32 (prevout) + 4 (vout) + 1 (script len) + 107 (script_sig) + 4 (nsequence)) * 4
    // - change output weight: 136 WU = (8 (value) + 1 (script len) + 25 (script)) * 4
    let new_tx_weight = original_tx_weight + Weight::from_wu(592) - Weight::from_wu(136);

    // two inputs (50k, 25k) and one output (45k) - epsilon
    // We use epsilon here to avoid asking for a slightly too high feerate
    let fee_abs = 50_000 + 25_000 - 45_000 - 10;
    builder.fee_rate(Amount::from_tap(fee_abs) / new_tx_weight);
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(
        original_sent_received.1,
        Amount::from_tap(5_000) - original_fee.unwrap_or(Amount::ZERO)
    );

    assert_eq!(
        sent_received.0,
        original_sent_received.0 + Amount::from_tap(25_000)
    );
    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(30_000));
    assert_eq!(sent_received.1, Amount::ZERO);

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(45_000)
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::from_tap_per_vb_unchecked(88), @dust_change, @add_signature);
}

#[test]
fn test_bump_fee_force_add_input() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let incoming_op = receive_output_in_latest_block(&mut wallet, 25_000);

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(45_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; P2WPKH_FAKE_WITNESS_SIZE]); // fake signature
    }
    wallet
        .insert_tx(tx.clone(), ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();
    // the new fee_rate is low enough that just reducing the change would be fine, but we force
    // the addition of an extra input with `add_utxo()`
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .add_utxo(incoming_op)
        .unwrap()
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(5));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(
        sent_received.0,
        original_sent_received.0 + Amount::from_tap(25_000)
    );
    assert_eq!(
        fee.unwrap_or(Amount::ZERO) + sent_received.1,
        Amount::from_tap(30_000)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(45_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), FeeRate::from_tap_per_vb_unchecked(5), @add_signature);
}

#[test]
fn test_bump_fee_absolute_force_add_input() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let incoming_op = receive_output_in_latest_block(&mut wallet, 25_000);

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(addr.script_pubkey(), Amount::from_tap(45_000))
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    let original_sent_received = wallet.sent_and_received(&tx, &ColorIdentifier::default());
    let txid = tx.malfix_txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; P2WPKH_FAKE_WITNESS_SIZE]); // fake signature
    }
    wallet
        .insert_tx(tx.clone(), ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    // the new fee_rate is low enough that just reducing the change would be fine, but we force
    // the addition of an extra input with `add_utxo()`
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .add_utxo(incoming_op)
        .unwrap()
        .fee_absolute(Amount::from_tap(250));
    let psbt = builder.finish().unwrap();
    let sent_received = wallet.sent_and_received(
        &psbt.clone().extract_tx().expect("failed to extract tx"),
        &ColorIdentifier::default(),
    );
    let fee = check_fee!(wallet, psbt);

    assert_eq!(
        sent_received.0,
        original_sent_received.0 + Amount::from_tap(25_000)
    );
    assert_eq!(
        fee.unwrap_or(Amount::ZERO) + sent_received.1,
        Amount::from_tap(30_000)
    );

    let tx = &psbt.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        Amount::from_tap(45_000)
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        sent_received.1
    );

    assert_eq!(fee.unwrap_or(Amount::ZERO), Amount::from_tap(250));
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_bump_fee_unconfirmed_inputs_only() {
    // We try to bump the fee, but:
    // - We can't reduce the change, as we have no change
    // - All our UTXOs are unconfirmed
    // So, we fail with "InsufficientFunds", as per RBF rule 2:
    // The replacement transaction may only include an unconfirmed input
    // if that input was included in one of the original transactions.
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(addr.script_pubkey())
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    // Now we receive one transaction with 0 confirmations. We won't be able to use that for
    // fee bumping, as it's still unconfirmed!
    receive_output(
        &mut wallet,
        25_000,
        ConfirmationTime::Unconfirmed { last_seen: 0 },
    );
    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; P2WPKH_FAKE_WITNESS_SIZE]); // fake signature
    }
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_tap_per_vb_unchecked(25));
    builder.finish().unwrap();
}

#[test]
fn test_bump_fee_unconfirmed_input() {
    // We create a tx draining the wallet and spending one confirmed
    // and one unconfirmed UTXO. We check that we can fee bump normally
    // (BIP125 rule 2 only apply to newly added unconfirmed input, you can
    // always fee bump with an unconfirmed input if it was included in the
    // original transaction)
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    // We receive a tx with 0 confirmations, which will be used as an input
    // in the drain tx.
    receive_output(&mut wallet, 25_000, ConfirmationTime::unconfirmed(0));
    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(addr.script_pubkey())
        .enable_rbf();
    let psbt = builder.finish().unwrap();
    let mut tx = psbt.extract_tx().expect("failed to extract tx");
    let txid = tx.malfix_txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; P2WPKH_FAKE_WITNESS_SIZE]); // fake signature
    }
    wallet
        .insert_tx(tx, ConfirmationTime::Unconfirmed { last_seen: 0 })
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .fee_rate(FeeRate::from_tap_per_vb_unchecked(15))
        // remove original tx drain_to address and amount
        .set_recipients(Vec::new())
        // set back original drain_to address
        .drain_to(addr.script_pubkey())
        // drain wallet output amount will be re-calculated with new fee rate
        .drain_wallet();
    builder.finish().unwrap();
}

#[test]
fn test_fee_amount_negative_drain_val() {
    // While building the transaction, bdk would calculate the drain_value
    // as
    // current_delta - fee_amount - drain_fee
    // using saturating_sub, meaning that if the result would end up negative,
    // it'll remain to zero instead.
    // This caused a bug in master where we would calculate the wrong fee
    // for a transaction.
    // See https://github.com/bitcoindevkit/bdk/issues/660
    let (mut wallet, _) = get_funded_wallet_pkh();
    let send_to = Address::from_str("1QJaAMwHycAcFF3hx9NA5rLPgu7BmhAhRF")
        .unwrap()
        .assume_checked();
    let fee_rate = FeeRate::from_tap_per_kwu(500);
    let incoming_op = receive_output_in_latest_block(&mut wallet, 8859);

    let mut builder = wallet.build_tx();

    // 8475 = 8859 - 192(tx bytes) * 2(tap/vbytes; fee rate)
    builder
        .add_recipient(send_to.script_pubkey(), Amount::from_tap(8475))
        .add_utxo(incoming_op)
        .unwrap()
        .enable_rbf()
        .fee_rate(fee_rate);
    let psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    assert_eq!(psbt.inputs.len(), 1);
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), fee_rate, @add_signature);
}

#[test]
fn test_sign_single_xprv() {
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let mut psbt = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(extracted.input[0].script_sig.len(), 106);
}

#[test]
fn test_sign_single_xprv_with_master_fingerprint_and_path() {
    let (mut wallet, _) = get_funded_wallet("pkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let mut psbt = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(extracted.input[0].script_sig.len(), 106);
}

#[test]
fn test_sign_single_xprv_bip44_path() {
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/44'/0'/0'/0/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let mut psbt = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(extracted.input[0].script_sig.len(), 106);
}

#[test]
fn test_sign_single_wif() {
    let (mut wallet, _) =
        get_funded_wallet("pkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let mut psbt = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(extracted.input[0].witness.len(), 0);
    assert_eq!(extracted.input[0].script_sig.len(), 106);
}

#[test]
fn test_sign_single_xprv_no_hd_keypaths() {
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let mut psbt = builder.finish().unwrap();

    psbt.inputs[0].bip32_derivation.clear();
    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 0);

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(extracted.input[0].witness.len(), 0);
    assert_eq!(extracted.input[0].script_sig.len(), 106);
}

#[test]
fn test_signing_only_one_of_multiple_inputs() {
    let (mut wallet, _) = get_funded_wallet_pkh();
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(55_000));

    // add another input to the psbt that is at least passable.
    let (wallet2, txid) = get_funded_wallet(
        "pkh(025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357)",
    );
    let utxo = wallet2.list_unspent().next().expect("must take!");
    let tx = wallet2.get_tx(txid).expect("transaction").tx_node.tx;
    let foreign_utxo_satisfaction = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_weight_to_satisfy()
        .unwrap();
    let dud_input = tapyrus::psbt::Input {
        non_witness_utxo: Some((*tx).clone()),
        ..Default::default()
    };

    builder
        .add_foreign_utxo(utxo.outpoint, dud_input, foreign_utxo_satisfaction)
        .unwrap();

    let mut psbt = builder.finish().unwrap();
    let is_final = wallet.sign(&mut psbt, SignOptions::default()).unwrap();
    assert!(
        !is_final,
        "shouldn't be final since we can't sign one of the inputs"
    );

    let input = psbt
        .inputs
        .iter()
        .find(|input| input.non_witness_utxo.as_ref().unwrap().malfix_txid() != utxo.outpoint.txid)
        .unwrap();

    assert!(
        input.final_script_witness.as_ref().unwrap().len() == 0,
        "should not finalized input it signed witness"
    );
    assert!(
        input.final_script_sig.as_ref().unwrap().len() == 106,
        "should finalized input it signed"
    );
}

#[test]
fn test_remove_partial_sigs_after_finalize_sign_option() {
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");

    for remove_partial_sigs in &[true, false] {
        let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
        let mut builder = wallet.build_tx();
        builder.drain_to(addr.script_pubkey()).drain_wallet();
        let mut psbt = builder.finish().unwrap();

        assert!(wallet
            .sign(
                &mut psbt,
                SignOptions {
                    remove_partial_sigs: *remove_partial_sigs,
                    ..Default::default()
                },
            )
            .unwrap());

        psbt.inputs.iter().for_each(|input| {
            if *remove_partial_sigs {
                assert!(input.partial_sigs.is_empty())
            } else {
                assert!(!input.partial_sigs.is_empty())
            }
        });
    }
}

#[test]
fn test_try_finalize_sign_option() {
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");

    for try_finalize in &[true, false] {
        let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
        let mut builder = wallet.build_tx();
        builder.drain_to(addr.script_pubkey()).drain_wallet();
        let mut psbt = builder.finish().unwrap();

        let finalized = wallet
            .sign(
                &mut psbt,
                SignOptions {
                    try_finalize: *try_finalize,
                    ..Default::default()
                },
            )
            .unwrap();

        psbt.inputs.iter().for_each(|input| {
            if *try_finalize {
                assert!(finalized);
                assert!(input.final_script_sig.is_some());
                assert!(input.final_script_witness.is_some());
            } else {
                assert!(!finalized);
                assert!(input.final_script_sig.is_none());
                assert!(input.final_script_witness.is_none());
            }
        });
    }
}

#[test]
fn test_sign_nonstandard_sighash() {
    let sighash = EcdsaSighashType::NonePlusAnyoneCanPay;

    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .sighash(sighash.into())
        .drain_wallet();
    let mut psbt = builder.finish().unwrap();

    let result = wallet.sign(&mut psbt, Default::default());
    assert!(
        result.is_err(),
        "Signing should have failed because the TX uses non-standard sighashes"
    );
    assert_matches!(
        result,
        Err(SignerError::NonStandardSighash),
        "Signing failed with the wrong error type"
    );

    // try again after opting-in
    let result = wallet.sign(
        &mut psbt,
        SignOptions {
            allow_all_sighashes: true,
            ..Default::default()
        },
    );
    assert!(result.is_ok(), "Signing should have worked");
    assert!(
        result.unwrap(),
        "Should finalize the input since we can produce signatures"
    );

    let extracted = psbt.extract_tx().expect("failed to extract tx");
    assert_eq!(
        extracted.input[0].script_sig.as_bytes()[71],
        sighash.to_u32() as u8,
        "The signature should have been made with the right sighash"
    );
}

#[test]
fn test_unused_address() {
    let desc = "pkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)";
    let change_desc = get_test_pkh();
    let mut wallet = Wallet::new_no_persist(desc, change_desc, Network::Dev).unwrap();

    // `list_unused_addresses` should be empty if we haven't revealed any
    assert!(wallet
        .list_unused_addresses(KeychainKind::External)
        .next()
        .is_none());

    assert_eq!(
        wallet
            .next_unused_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );
    assert_eq!(
        wallet
            .list_unused_addresses(KeychainKind::External)
            .next()
            .unwrap()
            .to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );
}

#[test]
fn test_create_pay_to_contract_address() {
    let desc = "pkh(xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX)";
    let change_desc = get_test_pkh();
    let wallet = Wallet::new_no_persist(desc, change_desc, Network::Prod).unwrap();

    let payment_base = xprv_to_public_key("xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX");
    let contract = vec![0x00, 0x01, 0x02, 0x03];

    let address = wallet
        .create_pay_to_contract_address(&payment_base, contract.clone(), None)
        .unwrap();
    assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);

    let address = wallet
        .create_pay_to_contract_address(
            &payment_base,
            contract.clone(),
            Some(ColorIdentifier::default()),
        )
        .unwrap();
    assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);

    let out_point = OutPoint::default();
    let address = wallet
        .create_pay_to_contract_address(
            &payment_base,
            contract,
            Some(ColorIdentifier::nft(out_point)),
        )
        .unwrap();
    assert_eq!(address.address_type().unwrap(), AddressType::Cp2pkh);
}

#[test]
fn test_create_pay_to_contract_address_error() {
    let desc = "pkh(xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX)";
    let change_desc = get_test_pkh();
    let wallet = Wallet::new_no_persist(desc, change_desc, Network::Prod).unwrap();
    let payment_base = xprv_to_public_key("xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX");

    let result = wallet.create_pay_to_contract_address(&payment_base, Vec::new(), None);
    assert!(result.is_err());

    let vec: Vec<u8> = vec![0; 256];
    let result = wallet.create_pay_to_contract_address(&payment_base, vec, None);
    assert!(result.is_ok());

    let vec: Vec<u8> = vec![0; 257];
    let result = wallet.create_pay_to_contract_address(&payment_base, vec, None);
    assert!(result.is_err());
}

#[test]
fn test_pay_to_contract_key() {
    let desc = "pkh(xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX)";
    let change_desc = get_test_pkh();
    let wallet = Wallet::new_no_persist(desc, change_desc, Network::Prod).unwrap();

    let contract = "metadata".as_bytes().to_vec();

    let payment_base = xprv_to_public_key("xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX");
    let key = wallet.pay_to_contract_key(&payment_base, contract.clone());
    assert!(key.is_ok());
    assert_eq!(
        key.unwrap(),
        PublicKey::from_str("0393caf4389ac699d42284c5031b95e21c6648e8f3fed561ca04fe6289c9199c37")
            .unwrap()
    )
}

fn xprv_to_public_key(xprv_str: &str) -> PublicKey {
    let secp = Secp256k1::new();

    let xprv = ExtendendPrivKey::from_str(xprv_str).unwrap();

    let xpub = ExtendendPubKey::from_priv(&secp, &xprv);
    xpub.public_key.to_public_key()
}

#[test]
fn test_create_pay_to_contract_commitment() {
    let desc = "pkh(xprv9s21ZrQH143K4EXURwMHuLS469fFzZyXk7UUpdKfQwhoHcAiYTakpe8pMU2RiEdvrU9McyuE7YDoKcXkoAwEGoK53WBDnKKv2zZbb9BzttX)";
    let change_desc = get_test_pkh();
    let wallet = Wallet::new_no_persist(desc, change_desc, Network::Prod).unwrap();

    let payment_base =
        PublicKey::from_str("02046e89be90d26872e1318feb7d5ca7a6f588118e76f4906cf5b8ef262b63ab49")
            .unwrap();
    let contract = "metadata".as_bytes().to_vec();
    let commitment = Contract::create_pay_to_contract_commitment(&payment_base, contract);
    let expected = [
        0xb3, 0x09, 0x1b, 0x18, 0x71, 0x39, 0xe7, 0xd1, 0xfc, 0x66, 0x1b, 0x25, 0xf3, 0xc0, 0x5c,
        0x07, 0x78, 0x11, 0xbb, 0x8c, 0xb2, 0x8e, 0x49, 0xc1, 0xda, 0xba, 0x16, 0x6b, 0xf6, 0x5e,
        0x90, 0xf7,
    ];
    assert_eq!(commitment.to_be_bytes(), expected);
}

#[test]
fn test_bytes_to_scalar() {
    let bytes = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let scalar = Contract::scalar_from(&bytes);
    /// 0xFFFFF.... - Scalar::MAX
    let expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xB7, 0x5F, 0xC4, 0x40, 0x2D, 0xA1, 0x73, 0x2F, 0xC9,
        0xBE, 0xBE,
    ];
    assert_eq!(scalar.to_be_bytes(), expected);
}

// TODO: Fix this test
#[test]
fn test_next_unused_address() {
    let descriptor = "pkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)";
    let change = get_test_pkh();
    let mut wallet = Wallet::new_no_persist(descriptor, change, Network::Dev).unwrap();
    assert_eq!(wallet.derivation_index(KeychainKind::External), None);

    assert_eq!(
        wallet
            .next_unused_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );
    assert_eq!(wallet.derivation_index(KeychainKind::External), Some(0));
    // calling next_unused again gives same address
    assert_eq!(
        wallet
            .next_unused_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );
    assert_eq!(wallet.derivation_index(KeychainKind::External), Some(0));

    // test mark used / unused
    assert!(wallet.mark_used(KeychainKind::External, 0));
    let next_unused_addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    assert_eq!(next_unused_addr.index, 1);

    assert!(wallet.unmark_used(KeychainKind::External, 0));
    let next_unused_addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    assert_eq!(next_unused_addr.index, 0);

    // use the above address
    receive_output_in_latest_block(&mut wallet, 25_000);

    assert_eq!(
        wallet
            .next_unused_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );
    assert_eq!(wallet.derivation_index(KeychainKind::External), Some(1));

    // trying to mark index 0 unused should return false
    assert!(!wallet.unmark_used(KeychainKind::External, 0));
}

#[test]
fn test_peek_address_at_index() {
    let desc = "pkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)";
    let change_desc = get_test_pkh();
    let mut wallet = Wallet::new_no_persist(desc, change_desc, Network::Dev).unwrap();

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 1).to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 0).to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 2).to_string(),
        "mhR8sRfov8dvFRZNXKJk4FJrh2W8mfj3RZ"
    );

    // current new address is not affected
    assert_eq!(
        wallet
            .reveal_next_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw"
    );

    assert_eq!(
        wallet
            .reveal_next_address(KeychainKind::External)
            .unwrap()
            .to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );
}

#[test]
fn test_peek_address_at_index_not_derivable() {
    let wallet = Wallet::new_no_persist("pkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/1)",
                                 get_test_pkh(), Network::Dev).unwrap();

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 1).to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 0).to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 2).to_string(),
        "mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr"
    );
}

#[test]
fn test_returns_index_and_address() {
    let mut wallet = Wallet::new_no_persist("pkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
                                 get_test_pkh(), Network::Dev).unwrap();

    // new index 0
    assert_eq!(
        wallet.reveal_next_address(KeychainKind::External).unwrap(),
        AddressInfo {
            index: 0,
            address: Address::from_str("mzas3vVDrqRT6ygjyadD6JxEbrGBz9Ytiw")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::External,
        }
    );

    // new index 1
    assert_eq!(
        wallet.reveal_next_address(KeychainKind::External).unwrap(),
        AddressInfo {
            index: 1,
            address: Address::from_str("mwQU2QZBYimzd3KGxdMUb6avuTCwxj6nMr")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::External,
        }
    );

    // peek index 25
    assert_eq!(
        wallet.peek_address(KeychainKind::External, 25),
        AddressInfo {
            index: 25,
            address: Address::from_str("msEKQ9QT8xG38HZJmbag4SFyjQonzjMS7B")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::External,
        }
    );

    // new index 2
    assert_eq!(
        wallet.reveal_next_address(KeychainKind::External).unwrap(),
        AddressInfo {
            index: 2,
            address: Address::from_str("mhR8sRfov8dvFRZNXKJk4FJrh2W8mfj3RZ")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::External,
        }
    );
}

#[test]
fn test_get_address() {
    use tdk_wallet::descriptor::template::Bip44;
    let key = tapyrus::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
    let wallet = Wallet::new_no_persist(
        Bip44(key, KeychainKind::External),
        Bip44(key, KeychainKind::Internal),
        Network::Dev,
    )
    .unwrap();

    assert_eq!(
        wallet.peek_address(KeychainKind::External, 0),
        AddressInfo {
            index: 0,
            address: Address::from_str("mqmr4eHUvvb3eBvtL3UV3mQNHosbbbVAjU")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::External,
        }
    );

    assert_eq!(
        wallet.peek_address(KeychainKind::Internal, 0),
        AddressInfo {
            index: 0,
            address: Address::from_str("mosoUbUvjEdsh97nQk6AS7c8YdzzwEZWhc")
                .unwrap()
                .assume_checked(),
            keychain: KeychainKind::Internal,
        }
    );
}

#[test]
fn test_reveal_addresses() {
    let (desc, change_desc) = get_test_pkh_single_sig_xprv_with_change_desc();
    let mut wallet = Wallet::new_no_persist(desc, change_desc, Network::Dev).unwrap();
    let keychain = KeychainKind::External;

    let last_revealed_addr = wallet
        .reveal_addresses_to(keychain, 9)
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(wallet.derivation_index(keychain), Some(9));

    let unused_addrs = wallet.list_unused_addresses(keychain).collect::<Vec<_>>();
    assert_eq!(unused_addrs.len(), 10);
    assert_eq!(unused_addrs.last().unwrap(), &last_revealed_addr);

    // revealing to an already revealed index returns nothing
    let mut already_revealed = wallet.reveal_addresses_to(keychain, 9).unwrap();
    assert!(already_revealed.next().is_none());
}

#[test]
fn test_get_address_no_reuse() {
    use std::collections::HashSet;
    use tdk_wallet::descriptor::template::Bip44;

    let key = tapyrus::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
    let mut wallet = Wallet::new_no_persist(
        Bip44(key, KeychainKind::External),
        Bip44(key, KeychainKind::Internal),
        Network::Dev,
    )
    .unwrap();

    let mut used_set = HashSet::new();

    (0..3).for_each(|_| {
        let external_addr = wallet
            .reveal_next_address(KeychainKind::External)
            .unwrap()
            .address;
        assert!(used_set.insert(external_addr));

        let internal_addr = wallet
            .reveal_next_address(KeychainKind::Internal)
            .unwrap()
            .address;
        assert!(used_set.insert(internal_addr));
    });
}

fn test_spend_from_wallet(mut wallet: Wallet) {
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();

    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), Amount::from_tap(25_000));
    let mut psbt = builder.finish().unwrap();

    assert!(
        wallet.sign(&mut psbt, Default::default()).unwrap(),
        "Unable to finalize tx"
    );
}

#[test]
fn test_spend_coinbase() {
    let (desc, change_desc) = get_test_pkh_with_change_desc();
    let mut wallet = Wallet::new_no_persist(desc, change_desc, Network::Dev).unwrap();

    let confirmation_height = 5;
    wallet
        .insert_checkpoint(BlockId {
            height: confirmation_height,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    let coinbase_tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..Default::default()
        }],
        output: vec![TxOut {
            script_pubkey: wallet
                .next_unused_address(KeychainKind::External)
                .unwrap()
                .script_pubkey(),
            value: Amount::from_tap(25_000),
        }],
    };
    wallet
        .insert_tx(
            coinbase_tx,
            ConfirmationTime::Confirmed {
                height: confirmation_height,
                time: 30_000,
            },
        )
        .unwrap();

    let not_yet_mature_time = confirmation_height + COINBASE_MATURITY - 1;
    let maturity_time = confirmation_height + COINBASE_MATURITY;

    let balance = wallet.balance(ColorIdentifier::default());
    assert_eq!(
        balance,
        Balance {
            immature: Amount::from_tap(25_000),
            trusted_pending: Amount::ZERO,
            untrusted_pending: Amount::ZERO,
            confirmed: Amount::ZERO
        }
    );

    // We try to create a transaction, only to notice that all
    // our funds are unspendable
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX")
        .unwrap()
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), balance.immature / 2)
        .current_height(confirmation_height);
    assert!(matches!(
        builder.finish(),
        Err(CreateTxError::CoinSelection(
            coin_selection::Error::InsufficientFunds {
                needed: _,
                available: 0
            }
        ))
    ));

    // Still unspendable...
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), balance.immature / 2)
        .current_height(not_yet_mature_time);
    assert_matches!(
        builder.finish(),
        Err(CreateTxError::CoinSelection(
            coin_selection::Error::InsufficientFunds {
                needed: _,
                available: 0
            }
        ))
    );

    wallet
        .insert_checkpoint(BlockId {
            height: maturity_time,
            hash: BlockHash::all_zeros(),
        })
        .unwrap();
    let balance = wallet.balance(ColorIdentifier::default());
    assert_eq!(
        balance,
        Balance {
            immature: Amount::ZERO,
            trusted_pending: Amount::ZERO,
            untrusted_pending: Amount::ZERO,
            confirmed: Amount::from_tap(25_000)
        }
    );
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), balance.confirmed / 2)
        .current_height(maturity_time);
    builder.finish().unwrap();
}

#[test]
fn test_allow_dust_limit() {
    let (mut wallet, _) = get_funded_wallet(get_test_single_sig_cltv());

    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();

    let mut builder = wallet.build_tx();

    builder.add_recipient(addr.script_pubkey(), Amount::ZERO);

    assert_matches!(
        builder.finish(),
        Err(CreateTxError::OutputBelowDustLimit(0))
    );

    let mut builder = wallet.build_tx();

    builder
        .allow_dust(true)
        .add_recipient(addr.script_pubkey(), Amount::ZERO);

    assert!(builder.finish().is_ok());
}

#[test]
fn test_fee_rate_sign_no_grinding_high_r() {
    // Our goal is to obtain a transaction with a signature with high-R (71 bytes
    // instead of 70). We then check that our fee rate and fee calculation is
    // alright.
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let fee_rate = FeeRate::from_tap_per_vb_unchecked(1);
    let mut builder = wallet.build_tx();
    let mut data = PushBytesBuf::try_from(vec![0]).unwrap();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_rate(fee_rate)
        .add_data(&data);
    let mut psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);
    let (op_return_vout, _) = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_n, i)| i.script_pubkey.is_op_return())
        .unwrap();

    let mut sig_len: usize = 0;
    // We try to sign many different times until we find a longer signature (71 bytes)
    while sig_len < 71 {
        // Changing the OP_RETURN data will make the signature change (but not the fee, until
        // data[0] is small enough)
        data.as_mut_bytes()[0] += 1;
        psbt.unsigned_tx.output[op_return_vout].script_pubkey = ScriptBuf::new_op_return(&data);
        // Clearing the previous signature
        psbt.inputs[0].partial_sigs.clear();
        // Signing
        wallet
            .sign(
                &mut psbt,
                SignOptions {
                    remove_partial_sigs: false,
                    try_finalize: false,
                    allow_grinding: false,
                    ..Default::default()
                },
            )
            .unwrap();
        // We only have one key in the partial_sigs map, this is a trick to retrieve it
        let key = psbt.inputs[0].partial_sigs.keys().next().unwrap();
        sig_len = psbt.inputs[0].partial_sigs[key].sig.serialize_der().len();
    }
    // Actually finalizing the transaction...
    wallet
        .sign(
            &mut psbt,
            SignOptions {
                remove_partial_sigs: false,
                allow_grinding: false,
                ..Default::default()
            },
        )
        .unwrap();
    // ...and checking that everything is fine
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), fee_rate);
}

#[test]
fn test_fee_rate_sign_grinding_low_r() {
    // Our goal is to obtain a transaction with a signature with low-R (70 bytes)
    // by setting the `allow_grinding` signing option as true.
    // We then check that our fee rate and fee calculation is alright and that our
    // signature is 70 bytes.
    let (mut wallet, _) = get_funded_wallet("pkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.next_unused_address(KeychainKind::External).unwrap();
    let fee_rate = FeeRate::from_tap_per_vb_unchecked(1);
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_rate(fee_rate);
    let mut psbt = builder.finish().unwrap();
    let fee = check_fee!(wallet, psbt);

    wallet
        .sign(
            &mut psbt,
            SignOptions {
                remove_partial_sigs: false,
                allow_grinding: true,
                ..Default::default()
            },
        )
        .unwrap();

    let key = psbt.inputs[0].partial_sigs.keys().next().unwrap();
    let sig_len = psbt.inputs[0].partial_sigs[key].sig.serialize_der().len();
    assert_eq!(sig_len, 70);
    assert_fee_rate!(psbt, fee.unwrap_or(Amount::ZERO), fee_rate);
}

#[test]
/// The wallet should re-use previously allocated change addresses when the tx using them is cancelled
fn test_tx_cancellation() {
    macro_rules! new_tx {
        ($wallet:expr) => {{
            let addr = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt")
                .unwrap()
                .assume_checked();
            let mut builder = $wallet.build_tx();
            builder.add_recipient(addr.script_pubkey(), Amount::from_tap(10_000));

            let psbt = builder.finish().unwrap();

            psbt
        }};
    }

    let (desc, change) = get_test_pkh_single_sig_xprv_with_change_desc();
    let (mut wallet, _) = get_funded_wallet_with_change(desc, change);

    let psbt1 = new_tx!(wallet);
    let change_derivation_1 = psbt1
        .unsigned_tx
        .output
        .iter()
        .find_map(|txout| wallet.derivation_of_spk(&txout.script_pubkey))
        .unwrap();
    assert_eq!(change_derivation_1, (KeychainKind::Internal, 0));

    let psbt2 = new_tx!(wallet);

    let change_derivation_2 = psbt2
        .unsigned_tx
        .output
        .iter()
        .find_map(|txout| wallet.derivation_of_spk(&txout.script_pubkey))
        .unwrap();
    assert_eq!(change_derivation_2, (KeychainKind::Internal, 1));

    wallet.cancel_tx(&psbt1.extract_tx().expect("failed to extract tx"));

    let psbt3 = new_tx!(wallet);
    let change_derivation_3 = psbt3
        .unsigned_tx
        .output
        .iter()
        .find_map(|txout| wallet.derivation_of_spk(&txout.script_pubkey))
        .unwrap();
    assert_eq!(change_derivation_3, (KeychainKind::Internal, 0));

    let psbt3 = new_tx!(wallet);
    let change_derivation_3 = psbt3
        .unsigned_tx
        .output
        .iter()
        .find_map(|txout| wallet.derivation_of_spk(&txout.script_pubkey))
        .unwrap();
    assert_eq!(change_derivation_3, (KeychainKind::Internal, 2));

    wallet.cancel_tx(&psbt3.extract_tx().expect("failed to extract tx"));

    let psbt3 = new_tx!(wallet);
    let change_derivation_4 = psbt3
        .unsigned_tx
        .output
        .iter()
        .find_map(|txout| wallet.derivation_of_spk(&txout.script_pubkey))
        .unwrap();
    assert_eq!(change_derivation_4, (KeychainKind::Internal, 2));
}

#[test]
fn test_thread_safety() {
    fn thread_safe<T: Send + Sync>() {}
    thread_safe::<Wallet>(); // compiles only if true
}

#[test]
fn test_store_contract() {
    let (desc, change_desc) = get_test_pkh_with_change_desc();
    let temp_dir = tempfile::tempdir().expect("must create tempdir");
    let file_path = temp_dir.path().join("sqlite3.db");
    let db = tdk_file_store::Store::create_new(DB_MAGIC, file_path).expect("must create db");
    let mut wallet = Wallet::new(desc, change_desc, db, Network::Dev).expect("must init wallet");
    let descriptor = wallet.get_descriptor_for_keychain(KeychainKind::External);
    let payment_base = descriptor_to_public_key(descriptor).unwrap();

    let result = wallet.store_contract(
        "contract_id".to_string(),
        vec![0x00, 0x01, 0x02, 0x03],
        payment_base.clone(),
        true,
    );
    assert!(result.is_ok());

    let result = wallet.store_contract(
        "contract_id".to_string(),
        vec![0x00, 0x01, 0x02, 0x03, 0x04],
        payment_base.clone(),
        true,
    );
    assert!(result.is_err());

    let result = wallet.update_contract("contract_id".to_string(), false);
    assert!(result.is_ok());

    let result = wallet.update_contract("invalid_id".to_string(), false);
    assert!(result.is_err());
}

#[test]
fn test_store_contract_invalid_payment_base() {
    let (desc, change_desc) = get_test_pkh_with_change_desc();
    let temp_dir = tempfile::tempdir().expect("must create tempdir");
    let file_path = temp_dir.path().join("sqlite3.db");
    let db = tdk_file_store::Store::create_new(DB_MAGIC, file_path).expect("must create db");
    let mut wallet = Wallet::new(desc, change_desc, db, Network::Dev).expect("must init wallet");

    let payment_base =
        PublicKey::from_str("02046e89be90d26872e1318feb7d5ca7a6f588118e76f4906cf5b8ef262b63ab49")
            .unwrap();
    let result = wallet.store_contract(
        "contract_id".to_string(),
        vec![0x00, 0x01, 0x02, 0x03],
        payment_base,
        true,
    );
    assert!(result.is_err());
}

#[test]
fn test_restore_contract_from_db_wallet() {
    let temp_dir = tempfile::tempdir().expect("must create tempdir");
    let file_path = temp_dir.path().join("store.sqlite");
    let (desc, change_desc) = get_test_pkh_with_change_desc();

    // create new wallet
    let (wallet_spk_index, txs) = {
        let db =
            tdk_sqlite::Store::new(Connection::open(file_path.clone()).expect("connect error"))
                .expect("must create db");
        let mut wallet =
            Wallet::new(desc, change_desc, db, Network::Dev).expect("must init wallet");

        let _ = wallet.next_unused_address(KeychainKind::External);
        let payment_base = get_payment_base(&wallet);
        let ret = wallet.store_contract(
            "id".to_string(),
            vec![0x00, 0x01, 0x02],
            payment_base,
            false,
        );
        assert!(ret.is_ok());

        // create p2c transaction
        let txs = get_p2c_tx(&mut wallet, &ret.unwrap());
        (wallet.spk_index().clone(), txs)
    };

    // recover wallet
    {
        let db = tdk_sqlite::Store::new(Connection::open(file_path).expect("connect error"))
            .expect("must recover db");
        let mut wallet = Wallet::load(db).expect("must recover wallet");

        let payment_base = get_payment_base(&wallet);

        // error when storing contract agian
        let ret =
            wallet.store_contract("id".to_string(), vec![0x00, 0x01, 0x02], payment_base, true);
        assert!(ret.is_err());

        // can update
        let ret = wallet.update_contract("id".to_string(), true);
        assert!(ret.is_ok());

        let balance = wallet.balance(ColorIdentifier::default());
        assert_eq!(
            balance,
            Balance {
                immature: Amount::ZERO,
                trusted_pending: Amount::ZERO,
                untrusted_pending: Amount::ZERO,
                confirmed: Amount::ZERO
            }
        );

        // index tx after recovering
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
                txs[0].clone(),
                ConfirmationTime::Confirmed {
                    height: 1_000,
                    time: 100,
                },
            )
            .unwrap();
        wallet
            .insert_tx(
                txs[1].clone(),
                ConfirmationTime::Confirmed {
                    height: 2_000,
                    time: 100,
                },
            )
            .unwrap();

        let balance = wallet.balance(ColorIdentifier::default());
        assert_eq!(
            balance,
            Balance {
                immature: Amount::ZERO,
                trusted_pending: Amount::ZERO,
                untrusted_pending: Amount::ZERO,
                confirmed: Amount::from_tap(30_000),
            }
        );
    }
}
