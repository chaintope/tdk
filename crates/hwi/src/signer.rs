use tdk_wallet::bitcoin::bip32::Fingerprint;
use tdk_wallet::bitcoin::secp256k1::{All, Secp256k1};
use tdk_wallet::bitcoin::Psbt;

use hwi::error::Error;
use hwi::types::{HWIChain, HWIDevice};
use hwi::HWIClient;

use tdk_wallet::signer::{SignerCommon, SignerError, SignerId, TransactionSigner};

#[derive(Debug)]
/// Custom signer for Hardware Wallets
///
/// This ignores `sign_options` and leaves the decisions up to the hardware wallet.
pub struct HWISigner {
    fingerprint: Fingerprint,
    client: HWIClient,
}

impl HWISigner {
    /// Create a instance from the specified device and chain
    pub fn from_device(device: &HWIDevice, chain: HWIChain) -> Result<HWISigner, Error> {
        let client = HWIClient::get_client(device, false, chain)?;
        Ok(HWISigner {
            fingerprint: device.fingerprint,
            client,
        })
    }
}

impl SignerCommon for HWISigner {
    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        SignerId::Fingerprint(self.fingerprint)
    }
}

impl TransactionSigner for HWISigner {
    fn sign_transaction(
        &self,
        psbt: &mut Psbt,
        _sign_options: &tdk_wallet::SignOptions,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        psbt.combine(
            self.client
                .sign_tx(psbt)
                .map_err(|e| {
                    SignerError::External(format!("While signing with hardware wallet: {}", e))
                })?
                .psbt,
        )
        .expect("Failed to combine HW signed psbt with passed PSBT");
        Ok(())
    }
}

// TODO: re-enable this once we have the `get_funded_wallet` test util
// #[cfg(test)]
// mod tests {
//     #[test]
//     fn test_hardware_signer() {
//         use std::sync::Arc;
//
//         use tdk_wallet::tests::get_funded_wallet;
//         use tdk_wallet::signer::SignerOrdering;
//         use tdk_wallet::bitcoin::Network;
//         use crate::HWISigner;
//         use hwi::HWIClient;
//
//         let mut devices = HWIClient::enumerate().unwrap();
//         if devices.is_empty() {
//             panic!("No devices found!");
//         }
//         let device = devices.remove(0).unwrap();
//         let client = HWIClient::get_client(&device, true, Network::Regtest.into()).unwrap();
//         let descriptors = client.get_descriptors::<String>(None).unwrap();
//         let custom_signer = HWISigner::from_device(&device, Network::Regtest.into()).unwrap();
//
//         let (mut wallet, _) = get_funded_wallet(&descriptors.internal[0]);
//         wallet.add_signer(
//             tdk_wallet::KeychainKind::External,
//             SignerOrdering(200),
//             Arc::new(custom_signer),
//         );
//
//         let addr = wallet.get_address(tdk_wallet::wallet::AddressIndex::LastUnused);
//         let mut builder = wallet.build_tx();
//         builder.drain_to(addr.script_pubkey()).drain_wallet();
//         let (mut psbt, _) = builder.finish().unwrap();
//
//         let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
//         assert!(finalized);
//     }
// }
