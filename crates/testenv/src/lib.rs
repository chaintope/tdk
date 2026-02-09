pub use electrsd;
pub use electrsd::electrum_client;
use electrsd::electrum_client::ElectrumApi;
pub use electrsd::tapyrusd;
pub use electrsd::tapyrusd::anyhow;
pub use electrsd::tapyrusd::tapyruscore_rpc;
use std::time::Duration;
use tapyruscore_rpc::RpcApi;
use tdk_chain::{
    local_chain::CheckPoint,
    tapyrus::{address::NetworkChecked, hashes::Hash, Address, Amount, BlockHash, MalFixTxid},
    BlockId,
};

/// Compute a Schnorr signature for a Tapyrus block.
///
/// Uses `tapyrus::schnorr::Signature::sign()` to produce the block proof.
/// Returns the signature as a 128-character hex string (64 bytes: r_x || sigma).
fn schnorr_sign_block(private_key_wif: &str, block_hex: &str) -> anyhow::Result<String> {
    use tdk_chain::tapyrus::consensus::deserialize;
    use tdk_chain::tapyrus::hashes::hex::FromHex;
    use tdk_chain::tapyrus::hex::DisplayHex;
    use tdk_chain::tapyrus::{Block, PrivateKey};

    let privkey = PrivateKey::from_wif(private_key_wif)
        .map_err(|e| anyhow::anyhow!("invalid WIF key: {}", e))?;
    let block_bytes =
        Vec::<u8>::from_hex(block_hex).map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
    let block: Block = deserialize(&block_bytes)?;
    let sig_hash = block.header.signature_hash();
    let message: [u8; 32] = sig_hash.to_byte_array();

    let sig = tdk_chain::tapyrus::schnorr::Signature::sign(&privkey, &message)
        .map_err(|e| anyhow::anyhow!("schnorr sign failed: {}", e))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r_x);
    sig_bytes[32..].copy_from_slice(&sig.sigma);
    Ok(sig_bytes.to_lower_hex_string())
}

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
            None => self.tapyrusd.client.get_new_address(None)?.assume_checked(),
        };
        let block_hashes = self.tapyrusd.client.generate_to_address(
            count as _,
            &coinbase_address,
            tapyrusd::get_private_key(),
        )?;
        Ok(block_hashes)
    }

    /// Mine a block that is guaranteed to be empty even with transactions in the mempool.
    ///
    /// Uses `getnewblock` with a large `required_age` to exclude mempool transactions,
    /// then signs the block with a Schnorr signature and submits it.
    pub fn mine_empty_block(&self) -> anyhow::Result<(usize, BlockHash)> {
        use tapyruscore_rpc::jsonrpc::serde_json;
        use tdk_chain::tapyrus::consensus::{deserialize, serialize};
        use tdk_chain::tapyrus::hashes::hex::FromHex;
        use tdk_chain::tapyrus::hex::DisplayHex;

        let address = self.tapyrusd.client.get_new_address(None)?.assume_checked();

        // Get an unsigned block that excludes recent mempool transactions.
        let block_hex: String = self.tapyrusd.client.call(
            "getnewblock",
            &[
                serde_json::json!(address.to_string()),
                serde_json::json!(9_999_999),
            ],
        )?;

        // Deserialize the block, strip non-coinbase transactions, fix coinbase value,
        // and recompute merkle roots.
        let block_bytes = Vec::<u8>::from_hex(&block_hex)
            .map_err(|e| anyhow::anyhow!("invalid block hex: {}", e))?;
        let mut block: tdk_chain::tapyrus::Block = deserialize(&block_bytes)?;

        if block.txdata.len() > 1 {
            block.txdata.truncate(1); // Keep only coinbase

            // Fix coinbase output value: remove fees from stripped transactions.
            // Block subsidy = 50 TPC >> halvings. At test heights (<210000) it is 50 TPC.
            let current_height = self.tapyrusd.client.get_block_count()?;
            let next_height = current_height + 1;
            let halvings = next_height / 210_000;
            let subsidy = if halvings >= 64 {
                0
            } else {
                50_0000_0000u64 >> halvings
            };
            block.txdata[0].output[0].value = Amount::from_tap(subsidy);

            block.header.merkle_root = block
                .compute_merkle_root()
                .ok_or_else(|| anyhow::anyhow!("failed to compute merkle root"))?;
            block.header.im_merkle_root = block
                .immutable_merkle_root()
                .ok_or_else(|| anyhow::anyhow!("failed to compute im_merkle_root"))?;
        }

        let modified_block_hex = serialize(&block).to_lower_hex_string();

        // Sign the block with the aggregate private key.
        let private_key = tapyrusd::get_private_key();
        let signature_hex = schnorr_sign_block(&private_key, &modified_block_hex)?;

        // Combine the signature with the block.
        let combine_result: serde_json::Value = self.tapyrusd.client.call(
            "combineblocksigs",
            &[
                serde_json::json!(modified_block_hex),
                serde_json::json!(signature_hex),
            ],
        )?;

        let signed_hex = combine_result["hex"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("combineblocksigs: missing hex in response"))?;

        // Submit the signed block.
        self.tapyrusd.client.submit_block_hex(signed_hex)?;

        let height = self.tapyrusd.client.get_block_count()? as usize;
        let hash = self.tapyrusd.client.get_best_block_hash()?;
        Ok((height, hash))
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
    pub fn send(
        &self,
        address: &Address<NetworkChecked>,
        amount: Amount,
    ) -> anyhow::Result<MalFixTxid> {
        let txid = self
            .tapyrusd
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)?;
        Ok(MalFixTxid::from_slice(&txid[..]).unwrap())
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
