use bdk_electrum::BdkElectrumClient;
use tdk_chain::{
    bitcoin::{hashes::Hash, Address, Amount, ScriptBuf, WScriptHash},
    keychain::Balance,
    local_chain::LocalChain,
    spk_client::SyncRequest,
    tapyrus::script::color_identifier::ColorIdentifier,
    ConfirmationTimeHeightAnchor, IndexedTxGraph, SpkTxOutIndex,
};
use tdk_testenv::{anyhow, bitcoincore_rpc::RpcApi, TestEnv};

fn get_balance(
    recv_chain: &LocalChain,
    recv_graph: &IndexedTxGraph<ConfirmationTimeHeightAnchor, SpkTxOutIndex<()>>,
    color_id: ColorIdentifier,
) -> anyhow::Result<Balance> {
    let chain_tip = recv_chain.tip().block_id();
    let outpoints = recv_graph.index.outpoints().clone();
    let balances = recv_graph
        .graph()
        .balance(recv_chain, chain_tip, outpoints, |_, _| true);
    let balance = balances.get(&color_id).unwrap().to_owned();
    Ok(balance)
}

/// Ensure that [`ElectrumExt`] can sync properly.
///
/// 1. Mine 101 blocks.
/// 2. Send a tx.
/// 3. Mine extra block to confirm sent tx.
/// 4. Check [`Balance`] to ensure tx is confirmed.
#[test]
fn scan_detects_confirmed_tx() -> anyhow::Result<()> {
    const SEND_AMOUNT: Amount = Amount::from_sat(10_000);

    let env = TestEnv::new()?;
    let electrum_client = electrum_client::Client::new(env.electrsd.electrum_url.as_str())?;
    let client = BdkElectrumClient::new(electrum_client);

    // Setup addresses.
    let addr_to_mine = env
        .bitcoind
        .client
        .get_new_address(None, None)?
        .assume_checked();
    let spk_to_track = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
    let addr_to_track = Address::from_script(&spk_to_track, tdk_chain::bitcoin::Network::Regtest)?;

    // Setup receiver.
    let (mut recv_chain, _) = LocalChain::from_genesis_hash(env.bitcoind.client.get_block_hash(0)?);
    let mut recv_graph = IndexedTxGraph::<ConfirmationTimeHeightAnchor, _>::new({
        let mut recv_index = SpkTxOutIndex::default();
        recv_index.insert_spk((), spk_to_track.clone());
        recv_index
    });

    // Mine some blocks.
    env.mine_blocks(101, Some(addr_to_mine))?;

    // Create transaction that is tracked by our receiver.
    env.send(&addr_to_track, SEND_AMOUNT)?;

    // Mine a block to confirm sent tx.
    env.mine_blocks(1, None)?;

    // Sync up to tip.
    env.wait_until_electrum_sees_block()?;
    let update = client
        .sync(
            SyncRequest::from_chain_tip(recv_chain.tip())
                .chain_spks(core::iter::once(spk_to_track)),
            5,
            true,
        )?
        .with_confirmation_time_height_anchor(&client)?;

    let _ = recv_chain
        .apply_update(update.chain_update)
        .map_err(|err| anyhow::anyhow!("LocalChain update error: {:?}", err))?;
    let _ = recv_graph.apply_update(update.graph_update);

    // Check to see if tx is confirmed.
    assert_eq!(
        get_balance(&recv_chain, &recv_graph, ColorIdentifier::default())?,
        Balance {
            confirmed: SEND_AMOUNT,
            ..Balance::default()
        },
    );

    for tx in recv_graph.graph().full_txs() {
        // Retrieve the calculated fee from `TxGraph`, which will panic if we do not have the
        // floating txouts available from the transaction's previous outputs.
        let fee = recv_graph
            .graph()
            .calculate_fee(&tx.tx)
            .expect("fee must exist");

        // Retrieve the fee in the transaction data from `bitcoind`.
        let tx_fee = env
            .bitcoind
            .client
            .get_transaction(&tx.txid, None)
            .expect("Tx must exist")
            .fee
            .expect("Fee must exist")
            .abs()
            .to_unsigned()
            .expect("valid `SignedAmount`");

        // Check that the calculated fee matches the fee from the transaction data.
        assert_eq!(fee, tx_fee);
    }

    Ok(())
}

/// Ensure that confirmed txs that are reorged become unconfirmed.
///
/// 1. Mine 101 blocks.
/// 2. Mine 8 blocks with a confirmed tx in each.
/// 3. Perform 8 separate reorgs on each block with a confirmed tx.
/// 4. Check [`Balance`] after each reorg to ensure unconfirmed amount is correct.
#[test]
fn tx_can_become_unconfirmed_after_reorg() -> anyhow::Result<()> {
    const REORG_COUNT: usize = 8;
    const SEND_AMOUNT: Amount = Amount::from_sat(10_000);

    let env = TestEnv::new()?;
    let electrum_client = electrum_client::Client::new(env.electrsd.electrum_url.as_str())?;
    let client = BdkElectrumClient::new(electrum_client);

    // Setup addresses.
    let addr_to_mine = env
        .bitcoind
        .client
        .get_new_address(None, None)?
        .assume_checked();
    let spk_to_track = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
    let addr_to_track = Address::from_script(&spk_to_track, tdk_chain::bitcoin::Network::Regtest)?;

    // Setup receiver.
    let (mut recv_chain, _) = LocalChain::from_genesis_hash(env.bitcoind.client.get_block_hash(0)?);
    let mut recv_graph = IndexedTxGraph::<ConfirmationTimeHeightAnchor, _>::new({
        let mut recv_index = SpkTxOutIndex::default();
        recv_index.insert_spk((), spk_to_track.clone());
        recv_index
    });

    // Mine some blocks.
    env.mine_blocks(101, Some(addr_to_mine))?;

    // Create transactions that are tracked by our receiver.
    for _ in 0..REORG_COUNT {
        env.send(&addr_to_track, SEND_AMOUNT)?;
        env.mine_blocks(1, None)?;
    }

    // Sync up to tip.
    env.wait_until_electrum_sees_block()?;
    let update = client
        .sync(
            SyncRequest::from_chain_tip(recv_chain.tip()).chain_spks([spk_to_track.clone()]),
            5,
            false,
        )?
        .with_confirmation_time_height_anchor(&client)?;

    let _ = recv_chain
        .apply_update(update.chain_update)
        .map_err(|err| anyhow::anyhow!("LocalChain update error: {:?}", err))?;
    let _ = recv_graph.apply_update(update.graph_update.clone());

    // Retain a snapshot of all anchors before reorg process.
    let initial_anchors = update.graph_update.all_anchors();

    // Check if initial balance is correct.
    assert_eq!(
        get_balance(&recv_chain, &recv_graph, ColorIdentifier::default())?,
        Balance {
            confirmed: SEND_AMOUNT * REORG_COUNT as u64,
            ..Balance::default()
        },
        "initial balance must be correct",
    );

    // Perform reorgs with different depths.
    for depth in 1..=REORG_COUNT {
        env.reorg_empty_blocks(depth)?;

        env.wait_until_electrum_sees_block()?;
        let update = client
            .sync(
                SyncRequest::from_chain_tip(recv_chain.tip()).chain_spks([spk_to_track.clone()]),
                5,
                false,
            )?
            .with_confirmation_time_height_anchor(&client)?;

        let _ = recv_chain
            .apply_update(update.chain_update)
            .map_err(|err| anyhow::anyhow!("LocalChain update error: {:?}", err))?;

        // Check to see if a new anchor is added during current reorg.
        if !initial_anchors.is_superset(update.graph_update.all_anchors()) {
            println!("New anchor added at reorg depth {}", depth);
        }
        let _ = recv_graph.apply_update(update.graph_update);

        assert_eq!(
            get_balance(&recv_chain, &recv_graph, ColorIdentifier::default())?,
            Balance {
                confirmed: SEND_AMOUNT * (REORG_COUNT - depth) as u64,
                trusted_pending: SEND_AMOUNT * depth as u64,
                ..Balance::default()
            },
            "reorg_count: {}",
            depth,
        );
    }

    Ok(())
}
