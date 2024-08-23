// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Descriptor templates
//!
//! This module contains the definition of various common script templates that are ready to be
//! used. See the documentation of each template for an example.

use tapyrus::bip32;
use tapyrus::Network;

use miniscript::{Legacy, Segwitv0, Tap};

use super::{ExtendedDescriptor, IntoWalletDescriptor, KeyMap};
use crate::descriptor::DescriptorError;
use crate::keys::{DerivableKey, IntoDescriptorKey, ValidNetworks};
use crate::wallet::utils::SecpCtx;
use crate::{descriptor, KeychainKind};

/// Type alias for the return type of [`DescriptorTemplate`], [`descriptor!`](crate::descriptor!) and others
pub type DescriptorTemplateOut = (ExtendedDescriptor, KeyMap, ValidNetworks);

/// Trait for descriptor templates that can be built into a full descriptor
///
/// Since [`IntoWalletDescriptor`] is implemented for any [`DescriptorTemplate`], they can also be
/// passed directly to the [`Wallet`](crate::Wallet) constructor.
///
/// ## Example
///
/// TODO: Fix this example
/// ```ignore
/// use bitcoin::Network;
/// use tdk_wallet::descriptor::error::Error as DescriptorError;
/// use tdk_wallet::keys::{IntoDescriptorKey, KeyError};
/// use tdk_wallet::miniscript::Legacy;
/// use tdk_wallet::template::{DescriptorTemplate, DescriptorTemplateOut};
///
/// struct MyP2PKH<K: IntoDescriptorKey<Legacy>>(K);
///
/// impl<K: IntoDescriptorKey<Legacy>> DescriptorTemplate for MyP2PKH<K> {
///     fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
///         Ok(tdk_wallet::descriptor!(pkh(self.0))?)
///     }
/// }
/// ```
pub trait DescriptorTemplate {
    /// Build the complete descriptor
    fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError>;
}

/// Turns a [`DescriptorTemplate`] into a valid wallet descriptor by calling its
/// [`build`](DescriptorTemplate::build) method
impl<T: DescriptorTemplate> IntoWalletDescriptor for T {
    fn into_wallet_descriptor(
        self,
        secp: &SecpCtx,
        network: Network,
    ) -> Result<(ExtendedDescriptor, KeyMap), DescriptorError> {
        self.build(network)?.into_wallet_descriptor(secp, network)
    }
}

/// P2PKH template. Expands to a descriptor `pkh(key)`
///
/// ## Example
///
/// TODO: Fix this example
/// ```ignore
/// # use tdk_wallet::bitcoin::{PrivateKey, Network};
/// # use tdk_wallet::Wallet;
/// # use tdk_wallet::KeychainKind;
/// use tdk_wallet::template::P2Pkh;
///
/// let key_external =
///     bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")?;
/// let key_internal =
///     bitcoin::PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW")?;
/// let mut wallet =
///     Wallet::new_no_persist(P2Pkh(key_external), P2Pkh(key_internal), Network::Prod)?;
///
/// assert_eq!(
///     wallet
///         .next_unused_address(KeychainKind::External)?
///         .to_string(),
///     "mwJ8hxFYW19JLuc65RCTaP4v1rzVU8cVMT"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct P2Pkh<K: IntoDescriptorKey<Legacy>>(pub K);

impl<K: IntoDescriptorKey<Legacy>> DescriptorTemplate for P2Pkh<K> {
    fn build(self, _network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
        descriptor!(pkh(self.0))
    }
}

/// BIP44 template. Expands to `pkh(key/44'/{0,1}'/0'/{0,1}/*)`
///
/// Since there are hardened derivation steps, this template requires a private derivable key (generally a `xprv`/`tprv`).
///
/// See [`Bip44Public`] for a template that can work with a `xpub`/`tpub`.
///
/// ## Example
///
/// TODO: Fix this example
/// ```ignore
/// # use std::str::FromStr;
/// # use tdk_wallet::bitcoin::{PrivateKey, Network};
/// # use tdk_wallet::{Wallet,  KeychainKind};
/// use tdk_wallet::template::Bip44;
///
/// let key = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m")?;
/// let mut wallet = Wallet::new_no_persist(
///     Bip44(key.clone(), KeychainKind::External),
///     Bip44(key, KeychainKind::Internal),
///     Network::Prod,
/// )?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External)?.to_string(), "mmogjc7HJEZkrLqyQYqJmxUqFaC7i4uf89");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "pkh([c55b303f/44'/1'/0']tpubDCuorCpzvYS2LCD75BR46KHE8GdDeg1wsAgNZeNr6DaB5gQK1o14uErKwKLuFmeemkQ6N2m3rNgvctdJLyr7nwu2yia7413Hhg8WWE44cgT/0/*)#5wrnv0xt");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct Bip44<K: DerivableKey<Legacy>>(pub K, pub KeychainKind);

impl<K: DerivableKey<Legacy>> DescriptorTemplate for Bip44<K> {
    fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Pkh(legacy::make_bipxx_private(44, self.0, self.1, network)?).build(network)
    }
}

/// BIP44 public template. Expands to `pkh(key/{0,1}/*)`
///
/// This assumes that the key used has already been derived with `m/44'/0'/0'` for Mainnet or `m/44'/1'/0'` for Testnet.
///
/// This template requires the parent fingerprint to populate correctly the metadata of PSBTs.
///
/// See [`Bip44`] for a template that does the full derivation, but requires private data
/// for the key.
///
/// ## Example
///
/// TODO: Fix this example
/// ``` ignore
/// # use std::str::FromStr;
/// # use tdk_wallet::bitcoin::{PrivateKey, Network};
/// # use tdk_wallet::{Wallet,  KeychainKind};
/// use tdk_wallet::template::Bip44Public;
///
/// let key = bitcoin::bip32::Xpub::from_str("tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU")?;
/// let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f")?;
/// let mut wallet = Wallet::new_no_persist(
///     Bip44Public(key.clone(), fingerprint, KeychainKind::External),
///     Bip44Public(key, fingerprint, KeychainKind::Internal),
///     Network::Prod,
/// )?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External)?.to_string(), "miNG7dJTzJqNbFS19svRdTCisC65dsubtR");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "pkh([c55b303f/44'/1'/0']tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU/0/*)#cfhumdqz");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct Bip44Public<K: DerivableKey<Legacy>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Legacy>> DescriptorTemplate for Bip44Public<K> {
    fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Pkh(legacy::make_bipxx_public(
            44, self.0, self.1, self.2, network,
        )?)
        .build(network)
    }
}

macro_rules! expand_make_bipxx {
    ( $mod_name:ident, $ctx:ty ) => {
        mod $mod_name {
            use super::*;

            pub(super) fn make_bipxx_private<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                keychain: KeychainKind,
                network: Network,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let mut derivation_path = alloc::vec::Vec::with_capacity(4);
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(bip)?);

                match network {
                    Network::Prod => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(0)?);
                    }
                    _ => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(1)?);
                    }
                }
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(0)?);

                match keychain {
                    KeychainKind::External => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(0)?)
                    }
                    KeychainKind::Internal => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(1)?)
                    },
                    _ => {}
                };

                let derivation_path: bip32::DerivationPath = derivation_path.into();

                Ok((key, derivation_path))
            }
            pub(super) fn make_bipxx_public<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                parent_fingerprint: bip32::Fingerprint,
                keychain: KeychainKind,
                network: Network,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let derivation_path: bip32::DerivationPath = match keychain {
                    KeychainKind::External => vec![bip32::ChildNumber::from_normal_idx(0)?].into(),
                    KeychainKind::Internal => vec![bip32::ChildNumber::from_normal_idx(1)?].into(),
                    _ => vec![].into(),
                };

                let source_path = bip32::DerivationPath::from(vec![
                    bip32::ChildNumber::from_hardened_idx(bip)?,
                    match network {
                        Network::Prod => bip32::ChildNumber::from_hardened_idx(0)?,
                        _ => bip32::ChildNumber::from_hardened_idx(1)?,
                    },
                    bip32::ChildNumber::from_hardened_idx(0)?,
                ]);

                Ok((key, (parent_fingerprint, source_path), derivation_path))
            }
        }
    };
}

expand_make_bipxx!(legacy, Legacy);
expand_make_bipxx!(segwit_v0, Segwitv0);
expand_make_bipxx!(segwit_v1, Tap);

#[cfg(test)]
mod test {
    // test existing descriptor templates, make sure they are expanded to the right descriptors

    use alloc::{string::ToString, vec::Vec};
    use core::str::FromStr;

    use super::*;
    use crate::descriptor::DescriptorError;
    use crate::keys::ValidNetworks;
    use assert_matches::assert_matches;
    use miniscript::descriptor::{DescriptorPublicKey, KeyMap};
    use miniscript::Descriptor;

    // BIP44 `pkh(key/44'/{0,1}'/0'/{0,1}/*)`
    #[test]
    fn test_bip44_template_cointype() {
        use tapyrus::bip32::ChildNumber::{self, Hardened};

        let xprvkey = tapyrus::bip32::Xpriv::from_str("xprv9s21ZrQH143K2fpbqApQL69a4oKdGVnVN52R82Ft7d1pSqgKmajF62acJo3aMszZb6qQ22QsVECSFxvf9uyxFUvFYQMq3QbtwtRSMjLAhMf").unwrap();
        assert_eq!(Network::Prod, xprvkey.network);
        let xdesc = Bip44(xprvkey, KeychainKind::Internal)
            .build(Network::Prod)
            .unwrap();

        if let ExtendedDescriptor::Pkh(pkh) = xdesc.0 {
            let path: Vec<ChildNumber> = pkh.into_inner().full_derivation_path().unwrap().into();
            let purpose = path.first().unwrap();
            assert_matches!(purpose, Hardened { index: 44 });
            let coin_type = path.get(1).unwrap();
            assert_matches!(coin_type, Hardened { index: 0 });
        }

        let tprvkey = tapyrus::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        assert_eq!(Network::Dev, tprvkey.network);
        let tdesc = Bip44(tprvkey, KeychainKind::Internal)
            .build(Network::Dev)
            .unwrap();

        if let ExtendedDescriptor::Pkh(pkh) = tdesc.0 {
            let path: Vec<ChildNumber> = pkh.into_inner().full_derivation_path().unwrap().into();
            let purpose = path.first().unwrap();
            assert_matches!(purpose, Hardened { index: 44 });
            let coin_type = path.get(1).unwrap();
            assert_matches!(coin_type, Hardened { index: 1 });
        }
    }

    // verify template descriptor generates expected address(es)
    fn check(
        desc: Result<(Descriptor<DescriptorPublicKey>, KeyMap, ValidNetworks), DescriptorError>,
        is_fixed: bool,
        network: Network,
        expected: &[&str],
    ) {
        let (desc, _key_map, _networks) = desc.unwrap();
        assert_eq!(!desc.has_wildcard(), is_fixed);
        for i in 0..expected.len() {
            let index = i as u32;
            let child_desc = if !desc.has_wildcard() {
                desc.at_derivation_index(0).unwrap()
            } else {
                desc.at_derivation_index(index).unwrap()
            };
            let address = child_desc.address(network).unwrap();
            assert_eq!(address.to_string(), *expected.get(i).unwrap());
        }
    }

    // P2PKH
    #[test]
    fn test_p2ph_template() {
        let prvkey =
            tapyrus::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")
                .unwrap();
        check(
            P2Pkh(prvkey).build(Network::Prod),
            true,
            Network::Dev,
            &["mwJ8hxFYW19JLuc65RCTaP4v1rzVU8cVMT"],
        );

        let pubkey = tapyrus::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        check(
            P2Pkh(pubkey).build(Network::Prod),
            true,
            Network::Dev,
            &["muZpTpBYhxmRFuCjLc7C6BBDF32C8XVJUi"],
        );
    }

    // BIP44 `pkh(key/44'/0'/0'/{0,1}/*)`
    #[test]
    fn test_bip44_template() {
        let prvkey = tapyrus::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        check(
            Bip44(prvkey, KeychainKind::External).build(Network::Prod),
            false,
            Network::Dev,
            &[
                "n453VtnjDHPyDt2fDstKSu7A3YCJoHZ5g5",
                "mvfrrumXgTtwFPWDNUecBBgzuMXhYM7KRP",
                "mzYvhRAuQqbdSKMVVzXNYyqihgNdRadAUQ",
            ],
        );
        check(
            Bip44(prvkey, KeychainKind::Internal).build(Network::Prod),
            false,
            Network::Dev,
            &[
                "muHF98X9KxEzdKrnFAX85KeHv96eXopaip",
                "n4hpyLJE5ub6B5Bymv4eqFxS5KjrewSmYR",
                "mgvkdv1ffmsXd2B1sRKQ5dByK3SzpG42rA",
            ],
        );
    }

    // BIP44 public `pkh(key/{0,1}/*)`
    #[test]
    fn test_bip44_public_template() {
        let pubkey = tapyrus::bip32::Xpub::from_str("tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU").unwrap();
        let fingerprint = tapyrus::bip32::Fingerprint::from_str("c55b303f").unwrap();
        check(
            Bip44Public(pubkey, fingerprint, KeychainKind::External).build(Network::Prod),
            false,
            Network::Dev,
            &[
                "miNG7dJTzJqNbFS19svRdTCisC65dsubtR",
                "n2UqaDbCjWSFJvpC84m3FjUk5UaeibCzYg",
                "muCPpS6Ue7nkzeJMWDViw7Lkwr92Yc4K8g",
            ],
        );
        check(
            Bip44Public(pubkey, fingerprint, KeychainKind::Internal).build(Network::Prod),
            false,
            Network::Dev,
            &[
                "moDr3vJ8wpt5nNxSK55MPq797nXJb2Ru9H",
                "ms7A1Yt4uTezT2XkefW12AvLoko8WfNJMG",
                "mhYiyat2rtEnV77cFfQsW32y1m2ceCGHPo",
            ],
        );
    }
}
