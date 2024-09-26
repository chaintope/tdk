extern crate serde;
extern crate serde_derive;
extern crate serde_json;

use esplora_client::{self, BlockingClient, Builder, ScriptBuf};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use tdk_chain::serde::{Deserialize, Serialize};
use tdk_chain::spk_client::{FullScanRequest, SyncRequest};
use tdk_chain::tapyrus::address::{NetworkChecked, NetworkUnchecked};
use tdk_chain::tapyrus::consensus::encode::serialize_hex;
use tdk_chain::tapyrus::script::color_identifier;
use tdk_chain::Contract;
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

pub struct GetNewAddressResult {
    pub address: Address,
    pub public_key: PublicKey,
}

const SYNC_PARALLEL_REQUESTS: usize = 1;
const STOP_GAP: usize = 25;

impl HdWallet {
    pub fn new(config: Arc<Config>) -> anyhow::Result<Self> {
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
        let master_key = initialize_or_load_master_key(&master_key_path, network)?;

        let db_path = db_file_path
            .clone()
            .unwrap_or_else(|| "tapyrus-wallet.sqlite".to_string());
        let conn = Connection::open(&db_path)?;
        let db = Store::new(conn)?;

        let genesis_hash = BlockHash::from_str(genesis_hash)?;

        let wallet = Wallet::new_or_load_with_genesis_hash(
            Bip44(master_key, KeychainKind::External),
            Bip44(master_key, KeychainKind::Internal),
            db,
            network,
            genesis_hash,
        )?;

        Ok(HdWallet {
            network,
            wallet: Mutex::new(wallet),
            esplora_url: esplora_url.clone(),
        })
    }

    pub fn sync(&self, client: &BlockingClient) -> anyhow::Result<()> {
        let mut wallet = self.get_wallet();
        let request = wallet.start_sync_with_revealed_spks();
        let update = client.sync(request, SYNC_PARALLEL_REQUESTS)?;
        wallet.apply_update(update)?;
        Ok(())
    }

    pub fn full_sync(&self, client: &BlockingClient) -> anyhow::Result<()> {
        let mut wallet = self.get_wallet();
        let request = wallet.start_full_scan();
        let update = client.full_scan(request, STOP_GAP, SYNC_PARALLEL_REQUESTS)?;

        wallet.apply_update(update)?;
        Ok(())
    }

    fn get_wallet(&self) -> MutexGuard<Wallet> {
        self.wallet.lock().expect("Failed to lock wallet")
    }

    pub fn get_new_address(
        &self,
        color_id: Option<ColorIdentifier>,
    ) -> anyhow::Result<GetNewAddressResult> {
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
            let script = address_info.script_pubkey().add_color(color_id).unwrap();
            Address::from_script(&script, self.network).unwrap()
        } else {
            address_info.address
        };

        Ok(GetNewAddressResult {
            address: address,
            public_key: public_key,
        })
    }

    pub fn balance(&self, color_id: Option<ColorIdentifier>) -> anyhow::Result<u64> {
        let color_id = color_id.unwrap_or_default();
        let balance = self.get_wallet().balance(color_id);
        Ok(balance.total().to_tap())
    }

    pub fn transfer(
        &self,
        params: Vec<TransferParams>,
        outpoints: Vec<OutPoint>,
        client: &BlockingClient,
    ) -> anyhow::Result<String> {
        let mut wallet = self.get_wallet();
        let mut tx_builder = wallet.build_tx();
        let ret: anyhow::Result<()> = params.iter().try_for_each(|param| {
            let address = Address::from_str(&param.to_address)?;
            let address = address.require_network(self.network)?;

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
        });

        if !outpoints.is_empty() {
            for op in outpoints.iter() {
                tx_builder.add_utxo(op.clone());
            }
        }

        let mut psbt = tx_builder.finish()?;
        let options = SignOptions::default();
        wallet.sign(&mut psbt, options)?;
        let tx = psbt.extract_tx()?;
        client.broadcast(&tx)?;

        Ok(tx.malfix_txid().to_string())
    }

    pub fn get_transaction(
        &self,
        txid: &MalFixTxid,
        client: &BlockingClient,
    ) -> anyhow::Result<String> {
        if let Some(tx) = client.get_tx(txid)? {
            Ok(serialize(&tx).to_lower_hex_string())
        } else {
            Err(anyhow::Error::msg("cannnot get transaction"))
        }
    }

    pub fn get_tx_out_by_address(
        &self,
        tx: String,
        address: Address<NetworkChecked>,
        client: &BlockingClient,
    ) -> anyhow::Result<Vec<TxOut>> {
        let raw = Vec::from_hex(&tx)?;
        let tx: Transaction = deserialize(raw.as_slice())?;
        let script_pubkey = address.script_pubkey();

        tx.output
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut acc, (i, o)| {
                if o.script_pubkey == script_pubkey {
                    let status = client.get_output_status(&tx.malfix_txid(), i as u64)?;

                    let status = match status {
                        Some(status) => status,
                        None => return Ok(vec![]),
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
        payment_base: PublicKey,
        contract: String,
        color_id: Option<ColorIdentifier>,
    ) -> anyhow::Result<Address<NetworkChecked>> {
        let wallet = self.get_wallet();
        let contract = contract.as_bytes().to_vec();
        let address: Address =
            wallet.create_pay_to_contract_address(&payment_base, contract, color_id)?;
        Ok(address)
    }

    pub fn store_contract(&self, contract: Contract) -> anyhow::Result<Contract> {
        let mut wallet = self.get_wallet();
        let contract = wallet.store_contract(
            contract.contract_id,
            contract.contract.clone(),
            contract.payment_base.clone(),
            contract.spendable,
        )?;
        Ok(contract)
    }

    pub fn update_contract(&self, contract_id: String, spendable: bool) -> anyhow::Result<()> {
        let mut wallet = self.get_wallet();
        wallet.update_contract(contract_id, spendable)?;
        Ok(())
    }
}

fn initialize_or_load_master_key(file_path: &str, network: tapyrus::Network) -> io::Result<Xpriv> {
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

fn get_wallet(env: &TestEnv) -> HdWallet {
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

fn wait_for_confirmation(
    env: &TestEnv,
    client: &BlockingClient,
    count: usize,
) -> anyhow::Result<()> {
    let height = client.get_height().unwrap();
    let _block_hashes = env.mine_blocks(count, None)?;
    while client.get_height().unwrap() < height + (count as u32) {
        sleep(Duration::from_millis(100))
    }
    Ok(())
}

#[test]
fn test_p2c_transfer() -> anyhow::Result<()> {
    // remove sqlite file
    let _ = fs::remove_file("tests/tapyrus-wallet.sqlite");

    let env = TestEnv::new().unwrap();
    let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    let client = Builder::new(base_url.as_str()).build_blocking();

    let address: String = env.tapyrusd.client.call("getnewaddress", &[]).unwrap();

    let address: Address = Address::from_str(&address).unwrap().assume_checked();
    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(30000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    wait_for_confirmation(&env, &client, 101);

    let wallet = get_wallet(&env);
    wallet.full_sync(&client).expect("Failed to sync");
    let ret: f64 = env
        .tapyrusd
        .client
        .call("getbalance", &[false.into()])
        .unwrap();
    let balance = wallet.balance(None).unwrap();
    assert_eq!(balance, 0);

    let GetNewAddressResult {
        address,
        public_key,
    } = wallet.get_new_address(None).unwrap();
    // send to non p2c address from tapyrus core wallet.
    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(20000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;

    wait_for_confirmation(&env, &client, 1);

    wallet.full_sync(&client).expect("Failed to sync");
    let balance = wallet.balance(None).unwrap();
    assert_eq!(balance, 20000);

    let p2c_address = wallet
        .calc_p2c_address(public_key.clone(), "content".to_string(), None)
        .expect("Failed to calculate P2C address");

    // Transfer tpc to pay to contract address from other wallet
    let txid = env.tapyrusd.client.send_to_address(
        &p2c_address,
        Amount::from_tap(10000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    let contract = tdk_chain::Contract {
        contract_id: "contract_id6".to_string(),
        contract: "content".as_bytes().to_vec(),
        payment_base: public_key,
        spendable: false,
    };
    wallet
        .store_contract(contract.clone())
        .expect("Failed to store contract");

    wait_for_confirmation(&env, &client, 1);
    wallet.sync(&client).expect("Failed to sync");

    let outpoint = OutPoint {
        txid: txid,
        vout: 0,
    };
    let another_address: String = env.tapyrusd.client.call("getnewaddress", &[]).unwrap();
    let mut contracts: BTreeMap<_, _> = BTreeMap::new();
    contracts.insert("contract_id6".to_string(), contract);
    let ret = wallet.transfer(
        vec![TransferParams {
            amount: 5000,
            to_address: another_address.clone(),
        }],
        vec![outpoint],
        &client,
    );
    assert!(ret.is_ok());

    wait_for_confirmation(&env, &client, 1);
    wallet.sync(&client).expect("Failed to sync");
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct IssueResponse {
    color: String,
    txids: Vec<MalFixTxid>,
}

#[test]
fn test_colored_p2c_transfer() -> anyhow::Result<()> {
    // remove sqlite file
    let _ = fs::remove_file("tests/tapyrus-wallet.sqlite");

    let env = TestEnv::new().unwrap();
    let base_url = format!("http://{}", &env.electrsd.esplora_url.clone().unwrap());
    let client = Builder::new(base_url.as_str()).build_blocking();

    let address: String = env.tapyrusd.client.call("getnewaddress", &[]).unwrap();
    let address: Address = Address::from_str(&address).unwrap().assume_checked();
    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(30000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    wait_for_confirmation(&env, &client, 101);

    // Issue to core wallet
    let issue_spk = address.script_pubkey();
    let ret: IssueResponse = env
        .tapyrusd
        .client
        .call(
            "issuetoken",
            &[1.into(), 1000.into(), issue_spk.to_hex_string().into()],
        )
        .unwrap();
    let color_id = ColorIdentifier::from_str(&ret.color)?;

    wait_for_confirmation(&env, &client, 1);

    let wallet = get_wallet(&env);
    wallet.full_sync(&client).expect("Failed to sync");
    let balance = wallet.balance(None).unwrap();
    assert_eq!(balance, 0);

    let GetNewAddressResult {
        address,
        public_key,
    } = wallet.get_new_address(None).unwrap();
    // send to non p2c address from tapyrus core wallet.
    let txid1 = env.tapyrusd.client.send_to_address(
        &address,
        Amount::from_tap(20000),
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )?;
    wait_for_confirmation(&env, &client, 1);

    wallet.sync(&client).expect("Failed to sync");
    let balance = wallet.balance(None).unwrap();
    assert_eq!(balance, 20000);

    // create cp2pkh address
    let GetNewAddressResult { public_key, .. } = wallet.get_new_address(Some(color_id))?;
    let p2c_address = wallet.calc_p2c_address(
        public_key.clone(),
        "content".to_string(),
        Some(color_id.clone()),
    )?;

    //send p2c token from tapyrus core wallet.
    let txid: MalFixTxid = env.tapyrusd.client.call(
        "transfertoken",
        &[p2c_address.to_string().into(), 400.into()],
    )?;

    let contract = tdk_chain::Contract {
        contract_id: "contract_id".to_string(),
        contract: "content".as_bytes().to_vec(),
        payment_base: public_key,
        spendable: false,
    };
    wallet
        .store_contract(contract.clone())
        .expect("Failed to store contract");

    wait_for_confirmation(&env, &client, 1);
    wallet.sync(&client).expect("Failed to sync");
    let balance = wallet.balance(Some(color_id.clone())).unwrap();
    assert_eq!(balance, 400);

    let outpoint = OutPoint {
        txid: txid,
        vout: 0,
    };
    let another_address: String = env
        .tapyrusd
        .client
        .call("getnewaddress", &["".into(), color_id.to_string().into()])
        .unwrap();

    let mut contracts: BTreeMap<_, _> = BTreeMap::new();
    contracts.insert("contract_id6".to_string(), contract);
    let ret = wallet.transfer(
        vec![TransferParams {
            amount: 300,
            to_address: another_address.clone(),
        }],
        vec![outpoint],
        &client,
    );

    assert!(ret.is_ok());

    wait_for_confirmation(&env, &client, 1);
    wallet.sync(&client).expect("Failed to sync");
    assert_eq!(wallet.balance(Some(color_id.clone())).unwrap(), 100);
    Ok(())
}
