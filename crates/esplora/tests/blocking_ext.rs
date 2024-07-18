use esplora_client::{self, Builder};
use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tdk_chain::spk_client::{FullScanRequest, SyncRequest};
use tdk_esplora::EsploraExt;

use tdk_chain::tapyrus::{Address, Amount, MalFixTxid};
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
