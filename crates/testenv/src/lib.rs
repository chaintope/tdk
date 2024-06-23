use tapyruscore_rpc::{
    tapyruscore_rpc_json::{GetBlockTemplateModes, GetBlockTemplateRules},
    RpcApi,
};
pub use electrsd;
pub use electrsd::tapyrusd;
pub use electrsd::tapyrusd::anyhow;
pub use electrsd::tapyrusd::tapyruscore_rpc;
pub use electrsd::electrum_client;
use electrsd::electrum_client::ElectrumApi;
use std::time::Duration;
use tdk_chain::{
    tapyrus::{
        address::NetworkChecked, block::Header, hash_types::TxMerkleNode, hashes::Hash,
        secp256k1::rand::random, transaction, Address, Amount, Block, BlockHash,
        ScriptBuf, ScriptHash, Transaction, TxIn, TxOut, Txid,
        block::XField
    },
    local_chain::CheckPoint,
    BlockId,
};

/// Struct for running a regtest environment with a single `tapyrusd` node with an `electrs`
/// instance connected to it.
pub struct TestEnv {
    pub tapyrusd: electrsd::tapyrusd::TapyrusD,
    pub electrsd: electrsd::ElectrsD,
}

impl TestEnv {
    /// Construct a new [`TestEnv`] instance with default configurations.
    pub fn new() -> anyhow::Result<Self> {
        let tapyrusd = match std::env::var_os("TAPYRUSD_EXE") {
            Some(tapyrusd_path) => electrsd::tapyrusd::TapyrusD::new(tapyrusd_path),
            None => {
                let tapyrusd_exe = electrsd::tapyrusd::downloaded_exe_path()
                    .expect(
                "you need to provide an env var TAPYRUSD_EXE or specify a tapyrsud version feature",
                );
                electrsd::tapyrusd::TapyrusD::with_conf(
                    tapyrusd_exe,
                    &electrsd::tapyrusd::Conf::default(),
                )
            }
        }?;

        let mut electrsd_conf = electrsd::Conf::default();
        electrsd_conf.http_enabled = true;
        let electrsd = match std::env::var_os("ELECTRS_EXE") {
            Some(env_electrs_exe) => {
                electrsd::ElectrsD::with_conf(env_electrs_exe, &tapyrusd, &electrsd_conf)
            }
            None => {
                let electrs_exe = electrsd::downloaded_exe_path()
                    .expect("electrs version feature must be enabled");
                electrsd::ElectrsD::with_conf(electrs_exe, &tapyrusd, &electrsd_conf)
            }
        }?;

        Ok(Self { tapyrusd, electrsd })
    }

    /// Exposes the [`ElectrumApi`] calls from the Electrum client.
    pub fn electrum_client(&self) -> &impl ElectrumApi {
        &self.electrsd.client
    }

    /// Exposes the [`RpcApi`] calls from [`tapyruscore_rpc`].
    pub fn rpc_client(&self) -> &impl RpcApi {
        &self.tapyrusd.client
    }

    // Reset `electrsd` so that new blocks can be seen.
    pub fn reset_electrsd(mut self) -> anyhow::Result<Self> {
        let mut electrsd_conf = electrsd::Conf::default();
        electrsd_conf.http_enabled = true;
        let electrsd = match std::env::var_os("ELECTRS_EXE") {
            Some(env_electrs_exe) => {
                electrsd::ElectrsD::with_conf(env_electrs_exe, &self.tapyrusd, &electrsd_conf)
            }
            None => {
                let electrs_exe = electrsd::downloaded_exe_path()
                    .expect("electrs version feature must be enabled");
                electrsd::ElectrsD::with_conf(electrs_exe, &self.tapyrusd, &electrsd_conf)
            }
        }?;
        self.electrsd = electrsd;
        Ok(self)
    }

    /// Mine a number of blocks of a given size `count`, which may be specified to a given coinbase
    /// `address`.
    pub fn mine_blocks(
        &self,
        count: usize,
        address: Option<Address>,
    ) -> anyhow::Result<Vec<BlockHash>> {
        let coinbase_address = match address {
            Some(address) => address,
            None => self
                .tapyrusd
                .client
                .get_new_address(None)?
                .assume_checked(),
        };
        let block_hashes = self
            .tapyrusd
            .client
            .generate_to_address(count as _, &coinbase_address, tapyrusd::get_private_key())?;
        Ok(block_hashes)
    }

    /// Mine a block that is guaranteed to be empty even with transactions in the mempool.
    pub fn mine_empty_block(&self) -> anyhow::Result<(usize, BlockHash)> {
        let bt = self.tapyrusd.client.get_block_template(
            GetBlockTemplateModes::Template,
            &[GetBlockTemplateRules::SegWit],
            &[],
        )?;

        let txdata = vec![Transaction {
            version: transaction::Version::ONE,
            lock_time: tdk_chain::tapyrus::absolute::LockTime::from_height(0)?,
            input: vec![TxIn {
                previous_output: tdk_chain::tapyrus::OutPoint::default(),
                script_sig: ScriptBuf::builder()
                    .push_int(bt.height as _)
                    // randomn number so that re-mining creates unique block
                    .push_int(random())
                    .into_script(),
                sequence: tdk_chain::tapyrus::Sequence::default(),
                witness: tdk_chain::tapyrus::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
            }],
        }];

        let mut block = Block {
            header: Header {
                version: tdk_chain::tapyrus::block::Version::default(),
                prev_blockhash: bt.previous_block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                im_merkle_root: TxMerkleNode::all_zeros(),
                time: Ord::max(bt.min_time, std::time::UNIX_EPOCH.elapsed()?.as_secs()) as u32,
                xfield: XField::None,
                proof: None,
            },
            txdata,
        };

        block.header.merkle_root = block.compute_merkle_root().expect("must compute");
        self.tapyrusd.client.submit_block(&block)?;
        Ok((bt.height as usize, block.block_hash()))
    }

    /// This method waits for the Electrum notification indicating that a new block has been mined.
    pub fn wait_until_electrum_sees_block(&self) -> anyhow::Result<()> {
        self.electrsd.client.block_headers_subscribe()?;
        let mut delay = Duration::from_millis(64);

        loop {
            self.electrsd.trigger()?;
            self.electrsd.client.ping()?;
            if self.electrsd.client.block_headers_pop()?.is_some() {
                return Ok(());
            }

            if delay.as_millis() < 512 {
                delay = delay.mul_f32(2.0);
            }
            std::thread::sleep(delay);
        }
    }

    /// Invalidate a number of blocks of a given size `count`.
    pub fn invalidate_blocks(&self, count: usize) -> anyhow::Result<()> {
        let mut hash = self.tapyrusd.client.get_best_block_hash()?;
        for _ in 0..count {
            let prev_hash = self
                .tapyrusd
                .client
                .get_block_info(&hash)?
                .previousblockhash;
            self.tapyrusd.client.invalidate_block(&hash)?;
            match prev_hash {
                Some(prev_hash) => hash = prev_hash,
                None => break,
            }
        }
        Ok(())
    }

    /// Reorg a number of blocks of a given size `count`.
    /// Refer to [`TestEnv::mine_empty_block`] for more information.
    pub fn reorg(&self, count: usize) -> anyhow::Result<Vec<BlockHash>> {
        let start_height = self.tapyrusd.client.get_block_count()?;
        self.invalidate_blocks(count)?;

        let res = self.mine_blocks(count, None);
        assert_eq!(
            self.tapyrusd.client.get_block_count()?,
            start_height,
            "reorg should not result in height change"
        );
        res
    }

    /// Reorg with a number of empty blocks of a given size `count`.
    pub fn reorg_empty_blocks(&self, count: usize) -> anyhow::Result<Vec<(usize, BlockHash)>> {
        let start_height = self.tapyrusd.client.get_block_count()?;
        self.invalidate_blocks(count)?;

        let res = (0..count)
            .map(|_| self.mine_empty_block())
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            self.tapyrusd.client.get_block_count()?,
            start_height,
            "reorg should not result in height change"
        );
        Ok(res)
    }

    /// Send a tx of a given `amount` to a given `address`.
    pub fn send(&self, address: &Address<NetworkChecked>, amount: Amount) -> anyhow::Result<Txid> {
        let txid = self
            .tapyrusd
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)?;
        Ok(Txid::from_slice(&txid[..]).unwrap())
        // Ok(txid)
    }

    /// Create a checkpoint linked list of all the blocks in the chain.
    pub fn make_checkpoint_tip(&self) -> CheckPoint {
        CheckPoint::from_block_ids((0_u32..).map_while(|height| {
            self.tapyrusd
                .client
                .get_block_hash(height as u64)
                .ok()
                .map(|hash| BlockId { height, hash })
        }))
        .expect("must craft tip")
    }

    /// Get the genesis hash of the blockchain.
    pub fn genesis_hash(&self) -> anyhow::Result<BlockHash> {
        let hash = self.tapyrusd.client.get_block_hash(0)?;
        Ok(hash)
    }
}

#[cfg(test)]
mod test {
    use crate::TestEnv;
    use electrsd::tapyrusd::{anyhow::Result, tapyruscore_rpc::RpcApi};

    /// This checks that reorgs initiated by `tapyrusd` is detected by our `electrsd` instance.
    #[test]
    fn test_reorg_is_detected_in_electrsd() -> Result<()> {
        let env = TestEnv::new()?;

        // Mine some blocks.
        env.mine_blocks(101, None)?;
        env.wait_until_electrum_sees_block()?;
        let height = env.tapyrusd.client.get_block_count()?;
        let blocks = (0..=height)
            .map(|i| env.tapyrusd.client.get_block_hash(i))
            .collect::<Result<Vec<_>, _>>()?;

        // Perform reorg on six blocks.
        env.reorg(6)?;
        env.wait_until_electrum_sees_block()?;
        let reorged_height = env.tapyrusd.client.get_block_count()?;
        let reorged_blocks = (0..=height)
            .map(|i| env.tapyrusd.client.get_block_hash(i))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(height, reorged_height);

        // Block hashes should not be equal on the six reorged blocks.
        for (i, (block, reorged_block)) in blocks.iter().zip(reorged_blocks.iter()).enumerate() {
            match i <= height as usize - 6 {
                true => assert_eq!(block, reorged_block),
                false => assert_ne!(block, reorged_block),
            }
        }

        Ok(())
    }
}
