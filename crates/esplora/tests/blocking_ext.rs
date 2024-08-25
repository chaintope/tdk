use esplora_client::{self, BlockingClient, Builder};
use tdk_chain::tapyrus::address::{NetworkChecked, NetworkUnchecked};
use tdk_chain::tapyrus::consensus::encode::serialize_hex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::str::FromStr;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use tdk_chain::spk_client::{FullScanRequest, SyncRequest};
use tdk_esplora::EsploraExt;

use tdk_chain::tapyrus::{Address, Amount, MalFixTxid, Script};
use tdk_testenv::{anyhow, tapyruscore_rpc::RpcApi, TestEnv};

#[test]
pub fn test_update_tx_graph_without_keychain() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    let client = Builder::new(base_url.as_str()).build_blocking();

    let receive_address0 =
        Address::from_str("msPwSfjZLCc9iqwrik87k2HDe9tHwmeA1z")?.assume_checked();
    let receive_address1 =
        Address::from_str("mqcWNTwGXxUXPqbnSoVEv3u4R9GarTjuWu")?.assume_checked();

    let misc_spks = [
        receive_address0.script_pubkey(),
        receive_address1.script_pubkey(),
    ];

    let _block_hashes = env.mine_blocks(101, None)?;
    let txid1 = env.tapyrusd.client.send_to_address(
        &receive_address1,
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let txid2 = env.tapyrusd.client.send_to_address(
        &receive_address0,
        Amount::from_tap(20000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let _block_hashes = env.mine_blocks(1, None)?;
    while client.get_height().unwrap() < 102 {
        sleep(Duration::from_millis(10))
    }

    // use a full checkpoint linked list (since this is not what we are testing)
    let cp_tip = env.make_checkpoint_tip();

    let sync_update = {
        let request = SyncRequest::from_chain_tip(cp_tip.clone()).set_spks(misc_spks);
        client.sync(request, 1)?
    };

    assert!(
        {
            let update_cps = sync_update
                .chain_update
                .iter()
                .map(|cp| cp.block_id())
                .collect::<BTreeSet<_>>();
            let superset_cps = cp_tip
                .iter()
                .map(|cp| cp.block_id())
                .collect::<BTreeSet<_>>();
            superset_cps.is_superset(&update_cps)
        },
        "update should not alter original checkpoint tip since we already started with all checkpoints",
    );

    let graph_update = sync_update.graph_update;
    // Check to see if we have the floating txouts available from our two created transactions'
    // previous outputs in order to calculate transaction fees.
    for tx in graph_update.full_txs() {
        // Retrieve the calculated fee from `TxGraph`, which will panic if we do not have the
        // floating txouts available from the transactions' previous outputs.
        let fee = graph_update.calculate_fee(&tx.tx).expect("Fee must exist");

        // Retrieve the fee in the transaction data from `tapyrusd`.
        let tx_fee = env
            .tapyrusd
            .client
            .get_transaction(&tx.malfix_txid(), None)
            .expect("Tx must exist")
            .fee
            .expect("Fee must exist")
            .abs()
            .to_unsigned()
            .expect("valid `Amount`");

        // Check that the calculated fee matches the fee from the transaction data.
        assert_eq!(fee, tx_fee);
    }

    let mut graph_update_txids: Vec<MalFixTxid> = graph_update
        .full_txs()
        .map(|tx| tx.tx.malfix_txid())
        .collect();
    graph_update_txids.sort();
    let mut expected_txids: Vec<MalFixTxid> = vec![txid1, txid2];
    expected_txids.sort();
    assert_eq!(graph_update_txids, expected_txids);

    Ok(())
}

/// Test the bounds of the address scan depending on the `stop_gap`.
#[test]
pub fn test_update_tx_graph_stop_gap() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    let client = Builder::new(base_url.as_str()).build_blocking();
    let _block_hashes = env.mine_blocks(101, None)?;

    // Now let's test the gap limit. First of all get a chain of 10 addresses.
    let addresses = [
        "moJFccx4ytWRb3hxYo1P4osHjWYX4Y3dnp",
        "msPwSfjZLCc9iqwrik87k2HDe9tHwmeA1z",
        "mqcWNTwGXxUXPqbnSoVEv3u4R9GarTjuWu",
        "mr841zpk9Em1yXfobiGouX6XersQMH5EvC",
        "n44KCWj1Ky2LhHXtaNJvJWnusZmQjU5qS3",
        "n1uRT3pj5Yg84sQ6An1VviperzU3HvYWUb",
        "my4sjgY6n8dQP4YephfRJasNrwxq4NaFHM",
        "mxHWh829yfR2aF6mQpMUmTXLccyKkbwLxo",
        "mnLQL4BqzrM3hQWYpRGKgJkibKwUk9DoTn",
        "mtywH6R52Vhs14QRJCBkxubyGvC3kBp5fi",
    ];
    let addresses: Vec<_> = addresses
        .into_iter()
        .map(|s| Address::from_str(s).unwrap().assume_checked())
        .collect();
    let spks: Vec<_> = addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| (i as u32, addr.script_pubkey()))
        .collect();

    // Then receive coins on the 4th address.
    let txid_4th_addr = env.tapyrusd.client.send_to_address(
        &addresses[3],
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let _block_hashes = env.mine_blocks(1, None)?;
    while client.get_height().unwrap() < 103 {
        sleep(Duration::from_millis(10))
    }

    // use a full checkpoint linked list (since this is not what we are testing)
    let cp_tip = env.make_checkpoint_tip();

    // A scan with a stop_gap of 3 won't find the transaction, but a scan with a gap limit of 4
    // will.
    let full_scan_update = {
        let request =
            FullScanRequest::from_chain_tip(cp_tip.clone()).set_spks_for_keychain(0, spks.clone());
        client.full_scan(request, 3, 1)?
    };
    assert!(full_scan_update.graph_update.full_txs().next().is_none());
    assert!(full_scan_update.last_active_indices.is_empty());
    let full_scan_update = {
        let request =
            FullScanRequest::from_chain_tip(cp_tip.clone()).set_spks_for_keychain(0, spks.clone());
        client.full_scan(request, 4, 1)?
    };
    assert_eq!(
        full_scan_update
            .graph_update
            .full_txs()
            .next()
            .unwrap()
            .malfix_txid(),
        txid_4th_addr
    );
    assert_eq!(full_scan_update.last_active_indices[&0], 3);

    // Now receive a coin on the last address.
    let txid_last_addr = env.tapyrusd.client.send_to_address(
        &addresses[addresses.len() - 1],
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let _block_hashes = env.mine_blocks(1, None)?;
    while client.get_height().unwrap() < 104 {
        sleep(Duration::from_millis(10))
    }

    // A scan with gap limit 5 won't find the second transaction, but a scan with gap limit 6 will.
    // The last active indice won't be updated in the first case but will in the second one.
    let full_scan_update = {
        let request =
            FullScanRequest::from_chain_tip(cp_tip.clone()).set_spks_for_keychain(0, spks.clone());
        client.full_scan(request, 5, 1)?
    };
    let txs: HashSet<MalFixTxid> = full_scan_update
        .graph_update
        .full_txs()
        .map(|tx| tx.malfix_txid())
        .collect();
    assert_eq!(txs.len(), 1);
    assert!(txs.contains::<MalFixTxid>(&txid_4th_addr));
    assert_eq!(full_scan_update.last_active_indices[&0], 3);
    let full_scan_update = {
        let request =
            FullScanRequest::from_chain_tip(cp_tip.clone()).set_spks_for_keychain(0, spks.clone());
        client.full_scan(request, 6, 1)?
    };
    let txs: HashSet<MalFixTxid> = full_scan_update
        .graph_update
        .full_txs()
        .map(|tx| tx.malfix_txid())
        .collect();
    assert_eq!(txs.len(), 2);
    assert!(
        txs.contains::<MalFixTxid>(&txid_4th_addr) && txs.contains::<MalFixTxid>(&txid_last_addr)
    );
    assert_eq!(full_scan_update.last_active_indices[&0], 9);

    Ok(())
}

use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::{fs, io};
use tdk_esplora::esplora_client::deserialize;
use tdk_sqlite::{rusqlite::Connection, Store};
use tdk_wallet::descriptor::Descriptor;
use tdk_wallet::tapyrus::bip32::Xpriv;
use tdk_wallet::tapyrus::consensus::serialize;
use tdk_wallet::tapyrus::hex::{DisplayHex, FromHex};
use tdk_wallet::tapyrus::script::color_identifier::ColorIdentifier;
use tdk_wallet::tapyrus::secp256k1::rand::Rng;
use tdk_wallet::tapyrus::{secp256k1, BlockHash, PublicKey};
use tdk_wallet::tapyrus::{OutPoint, Transaction};
use tdk_wallet::template::Bip44;
use tdk_wallet::wallet::tx_builder::AddUtxoError;
use tdk_wallet::wallet::NewOrLoadError;
use tdk_wallet::{tapyrus, KeychainKind, SignOptions, Wallet};

#[derive(PartialEq, Clone, Debug)]
pub(crate) enum Network {
    Prod,
    Dev,
}

impl From<Network> for tapyrus::network::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Prod => tapyrus::network::Network::Prod,
            Network::Dev => tapyrus::network::Network::Dev,
        }
    }
}

impl From<tapyrus::network::Network> for Network {
    fn from(network: tapyrus::network::Network) -> Self {
        match network {
            tapyrus::network::Network::Prod => Network::Prod,
            tapyrus::network::Network::Dev => Network::Dev,
            _ => panic!("Unsupported network"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub network_mode: Network,
    pub network_id: u32,
    pub genesis_hash: String,
    pub esplora_url: String,
    pub esplora_user: Option<String>,
    pub esplora_password: Option<String>,
    pub master_key_path: Option<String>,
    pub db_file_path: Option<String>,
}

impl Config {
    /// Create a new Config instance.
    pub fn new(
        network_mode: Network,
        network_id: u32,
        genesis_hash: String,
        esplora_url: String,
        esplora_user: Option<String>,
        esplora_password: Option<String>,
        master_key_path: Option<String>,
        db_file_path: Option<String>,
    ) -> Self {
        Config {
            network_mode,
            network_id,
            genesis_hash,
            esplora_url,
            esplora_user,
            esplora_password,
            master_key_path,
            db_file_path,
        }
    }
}

pub(crate) struct HdWallet {
    network: tapyrus::network::Network,
    wallet: Mutex<Wallet>,
    esplora_url: String,
}

pub(crate) struct TransferParams {
    pub amount: u64,
    pub to_address: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TxOut {
    pub txid: String,
    pub index: u32,
    pub amount: u64,
    pub color_id: Option<String>,
    pub address: String,
    pub unspent: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Contract {
    pub contract_id: String,
    pub contract: String,
    pub payment_base: String,
    pub payable: bool,
}

impl From<tdk_wallet::chain::Contract> for Contract {
    fn from(contract: tdk_wallet::chain::Contract) -> Self {
        Contract {
            contract_id: contract.contract_id,
            contract: String::from_utf8(contract.contract).unwrap(),
            payment_base: contract.payment_base.to_string(),
            payable: contract.spendable,
        }
    }
}

pub(crate) struct GetNewAddressResult {
    pub address: String,
    pub public_key: String,
}

const SYNC_PARALLEL_REQUESTS: usize = 1;
const STOP_GAP: usize = 25;

// Error type for the wallet
#[derive(Debug)]
pub(crate) enum NewError {
    LoadMasterKeyError,
    LoadWalletDBError {
        cause: String,
    },
    ParseGenesisHashError,
    LoadedGenesisDoesNotMatch {
        /// The expected genesis block hash.
        expected: String,
        /// The block hash loaded from persistence.
        got: Option<String>,
    },
    LoadedNetworkDoesNotMatch {
        /// The expected network type.
        expected: Network,
        /// The network type loaded from persistence.
        got: Option<Network>,
    },
    NotInitialized,
}

impl Display for NewError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NewError::LoadMasterKeyError => write!(f, "Failed to load master key"),
            NewError::LoadWalletDBError { cause: e } => {
                write!(f, "Failed to load wallet db: {}", e)
            }
            NewError::ParseGenesisHashError => write!(f, "Failed to parse genesis hash"),
            NewError::LoadedGenesisDoesNotMatch { expected, got } => write!(
                f,
                "Loaded genesis block hash does not match. Expected: {:?}, Got: {:?}",
                expected, got
            ),
            NewError::LoadedNetworkDoesNotMatch { expected, got } => write!(
                f,
                "Loaded network does not match. Expected: {:?}, Got: {:?}",
                expected, got
            ),
            NewError::NotInitialized => {
                write!(f, "Wallet is not initialized")
            }
        }
    }
}

impl std::error::Error for NewError {}

#[derive(Debug)]
pub(crate) enum SyncError {
    EsploraClientError { cause: String },
    UpdateWalletError { cause: String },
}

impl Display for SyncError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::EsploraClientError { cause: e } => write!(f, "Esplora client error: {}", e),
            SyncError::UpdateWalletError { cause: e } => {
                write!(f, "Failed to update wallet: {}", e)
            }
        }
    }
}

impl std::error::Error for SyncError {}

#[derive(Debug)]
pub(crate) enum GetNewAddressError {
    InvalidColorId,
}

impl Display for GetNewAddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GetNewAddressError::InvalidColorId => write!(f, "Invalid color id"),
        }
    }
}

impl std::error::Error for GetNewAddressError {}

#[derive(Debug)]
pub(crate) enum BalanceError {
    InvalidColorId,
}

impl Display for BalanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceError::InvalidColorId => write!(f, "Invalid color id"),
        }
    }
}

impl std::error::Error for BalanceError {}

#[derive(Debug)]
pub(crate) enum TransferError {
    InsufficientFund,
    EsploraClient { cause: String },
    FailedToParseAddress { address: String },
    WrongNetworkAddress { address: String },
    FailedToParseTxid { txid: String },
    InvalidTransferAmount { cause: String },
    UnknownUtxo { utxo: TxOut },
    FailedToCreateTransaction { cause: String },
}

impl Display for TransferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::InsufficientFund => write!(f, "Insufficient fund"),
            TransferError::EsploraClient { cause: e } => write!(f, "Esplora client error: {}", e),
            TransferError::FailedToParseAddress { address: e } => {
                write!(f, "Failed to parse address: {}", e)
            }
            TransferError::WrongNetworkAddress { address: e } => {
                write!(f, "Wrong network address: {}", e)
            }
            TransferError::FailedToParseTxid { txid: e } => {
                write!(f, "Failed to parse txid: {}", e)
            }
            TransferError::InvalidTransferAmount { cause: e } => {
                write!(f, "Invalid transfer amount: {}", e)
            }
            TransferError::UnknownUtxo { utxo: e } => write!(f, "Unknown utxo: {:?}", e),
            TransferError::FailedToCreateTransaction { cause: e } => {
                write!(f, "Failed to create transaction: {}", e)
            }
        }
    }
}

impl std::error::Error for TransferError {}

#[derive(Debug)]
pub(crate) enum GetTransactionError {
    FailedToParseTxid { txid: String },
    EsploraClientError { cause: String },
    UnknownTxid,
}

impl Display for GetTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GetTransactionError::FailedToParseTxid { txid: e } => {
                write!(f, "Failed to parse txid: {}", e)
            }
            GetTransactionError::EsploraClientError { cause: e } => {
                write!(f, "Esplora client error: {}", e)
            }
            GetTransactionError::UnknownTxid => write!(f, "Unknown txid"),
        }
    }
}

impl std::error::Error for GetTransactionError {}

#[derive(Debug)]
pub(crate) enum GetTxOutByAddressError {
    FailedToParseTxHex,
    FailedToParseAddress {
        address: String,
    },
    EsploraClientError {
        cause: String,
    },
    /// The transaction is not found in Esplora.
    UnknownTransaction,
}

impl Display for GetTxOutByAddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GetTxOutByAddressError::FailedToParseTxHex => write!(f, "Failed to parse tx hex"),
            GetTxOutByAddressError::FailedToParseAddress { address: e } => {
                write!(f, "Failed to parse address: {}", e)
            }
            GetTxOutByAddressError::EsploraClientError { cause: e } => {
                write!(f, "Esplora client error: {}", e)
            }
            GetTxOutByAddressError::UnknownTransaction => write!(f, "Unknown transaction"),
        }
    }
}

impl std::error::Error for GetTxOutByAddressError {}

#[derive(Debug)]
pub(crate) enum CalcPayToContractAddressError {
    FailedToParsePublicKey,
    InvalidColorId,
    ContractError { cause: String },
}

impl Display for CalcPayToContractAddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CalcPayToContractAddressError::FailedToParsePublicKey => {
                write!(f, "Failed to parse public key")
            }
            CalcPayToContractAddressError::InvalidColorId => write!(f, "Invalid color id"),
            CalcPayToContractAddressError::ContractError { cause: e } => {
                write!(f, "Contract error: {}", e)
            }
        }
    }
}

impl std::error::Error for CalcPayToContractAddressError {}

#[derive(Debug)]
pub(crate) enum StoreContractError {
    ContractError { cause: String },
    FailedToParsePublicKey,
}

impl Display for StoreContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreContractError::ContractError { cause: e } => write!(f, "Contract error: {}", e),
            StoreContractError::FailedToParsePublicKey => {
                write!(f, "Failed to parse public key")
            }
        }
    }
}

impl std::error::Error for StoreContractError {}

#[derive(Debug)]
pub(crate) enum UpdateContractError {
    ContractError { cause: String },
}

impl Display for UpdateContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateContractError::ContractError { cause: e } => write!(f, "Contract error: {}", e),
        }
    }
}

impl std::error::Error for UpdateContractError {}

impl HdWallet {
    pub fn new(config: Arc<Config>) -> Result<Self, NewError> {
        let Config {
            network_mode,
            network_id,
            genesis_hash,
            esplora_url,
            esplora_user,
            esplora_password,
            master_key_path,
            db_file_path,
        } = config.as_ref();

        let network: tapyrus::network::Network = network_mode.clone().into();

        let master_key_path = master_key_path
            .clone()
            .unwrap_or_else(|| "master_key".to_string());
        let master_key = initialize_or_load_master_key(&master_key_path, network)
            .map_err(|_| NewError::LoadMasterKeyError)?;

        let db_path = db_file_path
            .clone()
            .unwrap_or_else(|| "tapyrus-wallet.sqlite".to_string());
        let conn = Connection::open(&db_path).map_err(|e| NewError::LoadWalletDBError {
            cause: e.to_string(),
        })?;
        let db = Store::new(conn).map_err(|e| NewError::LoadWalletDBError {
            cause: e.to_string(),
        })?;

        let genesis_hash =
            BlockHash::from_str(genesis_hash).map_err(|_| NewError::ParseGenesisHashError)?;

        let wallet = Wallet::new_or_load_with_genesis_hash(
            Bip44(master_key, KeychainKind::External),
            Bip44(master_key, KeychainKind::Internal),
            db,
            network,
            genesis_hash,
        )
        .map_err(|e| match e {
            NewOrLoadError::Persist(e) => NewError::LoadWalletDBError {
                cause: e.to_string(),
            },
            NewOrLoadError::NotInitialized => NewError::NotInitialized,
            NewOrLoadError::LoadedGenesisDoesNotMatch { expected, got } => {
                NewError::LoadedGenesisDoesNotMatch {
                    expected: expected.to_string(),
                    got: got.map(|h| h.to_string()),
                }
            }
            NewOrLoadError::LoadedNetworkDoesNotMatch { expected, got } => {
                println!("LoadedNetworkDoesNotMatch: {:?}, {:?}", expected, got);
                NewError::LoadedNetworkDoesNotMatch {
                    expected: expected.into(),
                    got: got.map(|n| n.into()),
                }
            }
            _ => {
                panic!("Unexpected error: {:?}", e)
            }
        })?;

        Ok(HdWallet {
            network,
            wallet: Mutex::new(wallet),
            esplora_url: esplora_url.clone(),
        })
    }

    pub fn sync(&self, client: &BlockingClient) -> Result<(), SyncError> {
        let mut wallet = self.get_wallet();
        // let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();

        let request = wallet.start_sync_with_revealed_spks();
        let update = client.sync(request, SYNC_PARALLEL_REQUESTS).map_err(|e| {
            SyncError::EsploraClientError {
                cause: e.to_string(),
            }
        })?;

        wallet
            .apply_update(update)
            .map_err(|e| SyncError::UpdateWalletError {
                cause: e.to_string(),
            })?;
        Ok(())
    }

    // pub fn get_client(&self) -> BlockingClient {
    //     let env = TestEnv::new().unwrap();
    //     let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    //     let client = Builder::new(base_url.as_str()).build_blocking();
    //     assert!(client.get_height().is_ok(), "get_height failed");
    //     // let env = TestEnv::new().unwrap();
    //     // let esplora_cookie = "__cookie__:2bc1754bea8cce8293f5270c7615db3d74539c221e9da221cf6532261905a2ce";
    //     // let base_url = format!("http://{}@{}", esplora_cookie, &env.electrsd.esplora_url.clone().unwrap());
    //     // let client = Builder::new(base_url.as_str()).build_blocking();
    //     client
    // }

    pub fn full_sync(&self, client: &BlockingClient) -> Result<(), SyncError> {
        let mut wallet = self.get_wallet();
        let request = wallet.start_full_scan();
        let update = client
            .full_scan(request, STOP_GAP, SYNC_PARALLEL_REQUESTS)
            .map_err(|e| SyncError::EsploraClientError {
                cause: e.to_string(),
            })?;

        wallet
            .apply_update(update)
            .map_err(|e| SyncError::UpdateWalletError {
                cause: e.to_string(),
            })?;
        Ok(())
    }

    fn get_wallet(&self) -> MutexGuard<Wallet> {
        self.wallet.lock().expect("Failed to lock wallet")
    }

    pub fn get_new_address(
        &self,
        color_id: Option<String>,
    ) -> Result<GetNewAddressResult, GetNewAddressError> {
        let mut wallet = self.get_wallet();
        let keychain = KeychainKind::External;
        let address_info = wallet.reveal_next_address(keychain).unwrap();

        let descriptor = wallet.get_descriptor_for_keychain(keychain);
        let secp = secp256k1::Secp256k1::verification_only();
        let derived_descriptor = descriptor
            .derived_descriptor(&secp, address_info.index)
            .unwrap();
        let public_key = match derived_descriptor {
            Descriptor::Pkh(a) => a.into_inner(),
            _ => {
                panic!("get_new_address() doesn't support Bare and Sh descriptor")
            }
        };

        let address = if let Some(color_id) = color_id {
            let color_id = ColorIdentifier::from_str(&color_id)
                .map_err(|_| GetNewAddressError::InvalidColorId)?;
            let script = address_info.script_pubkey().add_color(color_id).unwrap();
            Address::from_script(&script, self.network).unwrap()
        } else {
            address_info.address
        };

        Ok(GetNewAddressResult {
            address: address.to_string(),
            public_key: public_key.to_string(),
        })
    }

    pub fn balance(&self, color_id: Option<String>) -> Result<u64, BalanceError> {
        let color_id = if let Some(color_id) = color_id {
            ColorIdentifier::from_str(&color_id).map_err(|_| BalanceError::InvalidColorId)?
        } else {
            ColorIdentifier::default()
        };
        let balance = self.get_wallet().balance(color_id);
        Ok(balance.total().to_tap())
    }

    pub fn transfer(
        &self,
        params: Vec<TransferParams>,
        outpoints: Vec<OutPoint>,
        contracts: BTreeMap<String, tdk_chain::Contract>,
        client: &BlockingClient,
    ) -> Result<String, TransferError> {
        println!("TRANSFER===================================================");
        println!("outpoints: {:?}", outpoints);
        println!("contracts: {:?}", contracts);
        let mut wallet = self.get_wallet();
        //let client = self.get_client();
        // let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();

        let mut tx_builder = wallet.build_tx();
        params.iter().try_for_each(|param| {
            let address = Address::from_str(&param.to_address).map_err(|_| {
                TransferError::FailedToParseAddress {
                    address: (&param.to_address).clone(),
                }
            })?;
            let address = address.require_network(self.network).map_err(|_| {
                TransferError::WrongNetworkAddress {
                    address: (&param.to_address).clone(),
                }
            })?;

            let script = address.script_pubkey();
            if script.is_colored() {
                let color_id = script.color_id().unwrap();
                let non_colored_script = script.remove_color();
                tx_builder.add_recipient_with_color(
                    non_colored_script,
                    Amount::from_tap(param.amount),
                    color_id,
                );
            } else {
                tx_builder.add_recipient(script, Amount::from_tap(param.amount));
            }
            Ok(())
        })?;

        if !outpoints.is_empty() {
            for op in outpoints.iter() {
                tx_builder.add_contract_utxo(op.clone());
            }
        }

        let mut psbt =
            tx_builder
                .finish()
                .map_err(|e| TransferError::FailedToCreateTransaction {
                    cause: e.to_string(),
                })?;
        let options = SignOptions::default();
        wallet
            .sign(&mut psbt, options)
            .map_err(|e| TransferError::FailedToCreateTransaction {
                cause: e.to_string(),
            })?;
        println!("=========");
        println!("psbt inputs {:?}", psbt.inputs);
        let tx = psbt
            .extract_tx()
            .map_err(|e| TransferError::FailedToCreateTransaction {
                cause: e.to_string(),
            })?;
        println!("=========");
        println!("tx: {:?}", serialize_hex(&tx));
        println!("tx inputs: {:#?}", tx.input.clone());
        client
            .broadcast(&tx)
            .map_err(|e| TransferError::EsploraClient {
                cause: e.to_string(),
            })?;

        Ok(tx.malfix_txid().to_string())
    }

    pub fn get_transaction(&self, txid: String, client: &BlockingClient,) -> Result<String, GetTransactionError> {
        // let client = self.get_client();
        // let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();
        let txid = txid
            .parse::<MalFixTxid>()
            .map_err(|_| GetTransactionError::FailedToParseTxid { txid })?;
        let tx = client
            .get_tx(&txid)
            .map_err(|e| GetTransactionError::EsploraClientError {
                cause: e.to_string(),
            })?;
        match tx {
            Some(tx) => Ok(serialize(&tx).to_lower_hex_string()),
            None => Err(GetTransactionError::UnknownTxid),
        }
    }

    pub fn get_tx_out_by_address(
        &self,
        tx: String,
        address: String,
        client: &BlockingClient,
    ) -> Result<Vec<TxOut>, GetTxOutByAddressError> {
        let raw = Vec::from_hex(&tx).map_err(|_| GetTxOutByAddressError::FailedToParseTxHex)?;
        let tx: Transaction =
            deserialize(raw.as_slice()).map_err(|_| GetTxOutByAddressError::FailedToParseTxHex)?;
        let script_pubkey = Address::from_str(&address)
            .map_err(|_| GetTxOutByAddressError::FailedToParseAddress {
                address: address.clone(),
            })?
            .require_network(self.network)
            .map_err(|_| GetTxOutByAddressError::FailedToParseAddress {
                address: address.clone(),
            })?
            .script_pubkey();
        // let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();

        tx.output
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut acc, (i, o)| {
                if o.script_pubkey == script_pubkey {
                    let status = client
                        .get_output_status(&tx.malfix_txid(), i as u64)
                        .map_err(|e| GetTxOutByAddressError::EsploraClientError {
                            cause: e.to_string(),
                        })?;

                    let status = match status {
                        Some(status) => status,
                        None => return Err(GetTxOutByAddressError::UnknownTransaction),
                    };

                    let txout = TxOut {
                        txid: tx.malfix_txid().to_string(),
                        index: i as u32,
                        amount: o.value.to_tap(),
                        color_id: o.script_pubkey.color_id().map(|id| id.to_string()),
                        address: Address::from_script(&o.script_pubkey, self.network)
                            .unwrap()
                            .to_string(),
                        unspent: !status.spent,
                    };
                    acc.push(txout);
                }

                Ok(acc)
            })
    }

    pub fn calc_p2c_address(
        &self,
        public_key: String,
        contract: String,
        color_id: Option<String>,
    ) -> Result<String, CalcPayToContractAddressError> {
        let wallet = self.get_wallet();
        let payment_base = PublicKey::from_str(&public_key)
            .map_err(|_| CalcPayToContractAddressError::FailedToParsePublicKey)?;
        let contract = contract.as_bytes().to_vec();
        let color_id = match color_id {
            Some(id) => Some(
                ColorIdentifier::from_str(&id)
                    .map_err(|_| CalcPayToContractAddressError::InvalidColorId)?,
            ),
            None => None,
        };
        let address = wallet
            .create_pay_to_contract_address(&payment_base, contract, color_id)
            .map_err(|e| CalcPayToContractAddressError::ContractError {
                cause: e.to_string(),
            })?;
        Ok(address.to_string())
    }

    pub fn store_contract(&self, contract: Contract) -> Result<Contract, StoreContractError> {
        let mut wallet = self.get_wallet();
        let payment_base = PublicKey::from_str(&contract.payment_base)
            .map_err(|_| StoreContractError::FailedToParsePublicKey)?;
        let contract = wallet
            .store_contract(
                contract.contract_id,
                contract.contract.as_bytes().to_vec(),
                payment_base,
                contract.payable,
            )
            .map_err(|e| StoreContractError::ContractError {
                cause: e.to_string(),
            })?;
        Ok(contract.into())
    }

    pub fn update_contract(
        &self,
        contract_id: String,
        payable: bool,
    ) -> Result<(), UpdateContractError> {
        let mut wallet = self.get_wallet();
        wallet.update_contract(contract_id, payable).map_err(|e| {
            UpdateContractError::ContractError {
                cause: e.to_string(),
            }
        })?;
        Ok(())
    }
}

fn initialize_or_load_master_key(file_path: &str, network: tapyrus::Network) -> io::Result<Xpriv> {
    println!("initialize_or_load_master_key: {}", network);
    if fs::metadata(file_path).is_ok() {
        // File exists, read the private key
        let mut file = File::open(file_path)?;
        let mut xpriv_str = String::new();
        file.read_to_string(&mut xpriv_str)?;
        let xpriv = Xpriv::from_str(&xpriv_str).expect("Failed to parse Xpriv from file");
        Ok(xpriv)
    } else {
        // File doesn't exist, generate Xpriv and persist
        let seed: [u8; 32] = secp256k1::rand::thread_rng().gen();
        let xpriv = Xpriv::new_master(network, &seed).unwrap();
        let xpriv_str = xpriv.to_string();
        let mut file = File::create(file_path)?;
        file.write_all(xpriv_str.as_bytes())?;
        Ok(xpriv)
    }
}

// uniffi::include_scaffolding!("wallet");

fn get_wallet(env: &TestEnv) -> HdWallet {
    //let env = TestEnv::new().unwrap();
    println!("env.electrsd.esplora_url: {:?}", env.electrsd.esplora_url);
    let url = env.electrsd.esplora_url.clone();
    let config = Config {
        network_mode: Network::Dev,
        network_id: 1905960821,
        genesis_hash: "aa71d030ac96eafa5cd4cb6dcbd8e8845c03b1a60641bf816c85e97bcf6bb8ea"
            .to_string(),
        esplora_url: url.unwrap(),
        esplora_user: None,
        esplora_password: None,
        master_key_path: Some("tests/master_key".to_string()),
        db_file_path: Some("tests/tapyrus-wallet.sqlite".to_string()),
    };
    HdWallet::new(Arc::new(config)).unwrap()
}

#[test]
fn test_p2c_transfer() -> anyhow::Result<()>{
    // remove sqlite file
    let _ = fs::remove_file("tests/tapyrus-wallet.sqlite");

    let env = TestEnv::new().unwrap();
    let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    let client = Builder::new(base_url.as_str()).build_blocking();
    
    let wallet = get_wallet(&env);
    // Transfer colored coin to own Pay to contract address
    let GetNewAddressResult {
        address,
        public_key,
    } = wallet.get_new_address(None).unwrap();
    let address: Address<NetworkChecked> = Address::from_str(&address).unwrap().assume_checked();

    let _block_hashes = env.mine_blocks(101, None)?;
    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let txid2 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(20000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let _block_hashes = env.mine_blocks(1, None)?;
    while client.get_height().unwrap() < 102 {
        sleep(Duration::from_millis(10))
    }
    
    wallet.full_sync(&client).expect("Failed to sync");

    let color_id = ColorIdentifier::from_str(
        "c26db5bcd5d8102f65065a8f790643f05d27ce94b26753a1f6063eba6111ac6021",
    )
    .unwrap();
    let balance = wallet.balance(None).unwrap();
    println!("balance: {}", balance);
    // assert_eq!(balance, 100, "Balance should be 100");

    println!("generated address: {}", address);
    println!("generated public key: {}", public_key);

    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    ).unwrap();

    println!("{:?}", txid1);

    let balance = wallet.balance(None).unwrap();
    println!("balance: {}", balance);
    

    let p2c_address = wallet
        .calc_p2c_address(
            public_key.clone(),
            "content".to_string(),
            None,
        )
        .expect("Failed to calculate P2C address");
    println!("p2c_address: {}", p2c_address);

    let txid = wallet
        .transfer(
            vec![TransferParams {
                amount: 1000,
                to_address: p2c_address.clone(),
            }],
            Vec::new(),
            BTreeMap::new(),
            &client,
        )
        .expect("Failed to transfer");

    // wait for transaction to be indexed
    let tx = loop {
        match wallet.get_transaction(txid.clone(), &client) {
            Ok(tx) => break tx,
            Err(_) => thread::sleep(std::time::Duration::from_secs(1)),
        }
    };
    wallet
        .store_contract(Contract {
            contract_id: "contract_id6".to_string(),
            contract: "content".to_string(),
            payment_base: public_key.to_string(),
            payable: true,
        })
        .expect("Failed to store contract");

    wallet.sync(&client).expect("Failed to sync");
    println!("txid: {}", txid);
    println!("tx: {}", tx);
    let real_tx: Transaction = deserialize(&Vec::<u8>::from_hex(&tx).unwrap()).unwrap();
    let mut index = 0;
    let (i, output) = real_tx.output.iter().find_map(|o| {
        if (Address::from_script(&o.script_pubkey, tapyrus::Network::Dev).unwrap().to_string() == p2c_address.clone()) {
            Some((index, o))
        } else {
            index += 1;
            None
        }
    }).unwrap();
    let outpoint = OutPoint { txid: MalFixTxid::from_str(&txid).unwrap(), vout: index };

    /*assert_eq!(
        wallet.balance(Some(color_id.to_string())).unwrap(),
        90,
        "Balance should be 90"
    );*/
    println!("balance: {}", wallet.balance(None).unwrap());

    // wallet
    //     .store_contract(Contract {
    //         contract_id: "contract_id6".to_string(),
    //         contract: "content".to_string(),
    //         payment_base: public_key.to_string(),
    //         payable: true,
    //     })
    //     .expect("Failed to store contract");

    wallet.sync(&client).expect("Failed to sync");
    println!("balance: {}", wallet.balance(None).unwrap());

    /*assert_eq!(
        wallet.balance(Some(color_id.to_string())).unwrap(),
        100,
        "Balance should be 100"
    );*/

    let txout = wallet
        .get_tx_out_by_address(tx, p2c_address.clone(), &client)
        .unwrap();

    let another_address = wallet
        .get_new_address(None)
        .unwrap()
        .address;
    let mut contracts: BTreeMap<_, _> = BTreeMap::new();
    contracts.insert("contract_id6".to_string(), tdk_chain::Contract {
        contract_id: "contract_id6".to_string(),
        contract: "content".as_bytes().to_vec(),
        payment_base: PublicKey::from_str(&public_key).unwrap(),
        spendable: true,
    });
    println!("TRANSFER");
    //let wallet = get_wallet(&env);
    let ret = wallet
        .transfer(
            vec![TransferParams {
                amount: 1000,
                to_address: another_address.clone(),
            }],
            vec![outpoint],
            contracts.clone(),
            &client,
        );
    assert!(ret.is_err());

    // reload 
    let wallet = get_wallet(&env);
    let ret = wallet
        .transfer(
            vec![TransferParams {
                amount: 1000,
                to_address: another_address.clone(),
            }],
            vec![outpoint],
            contracts.clone(),
            &client,
        );
        assert!(ret.is_ok());
    Ok(())
}
