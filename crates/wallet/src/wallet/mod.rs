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

//! Wallet
//!
//! This module defines the [`Wallet`].
use crate::{
    collections::{BTreeMap, HashMap},
    keys::DescriptorKey,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use core::ops::Deref;
use core::{fmt, str::FromStr};
use descriptor::error::Error as DescriptorError;
use miniscript::{
    descriptor::{SinglePub, SinglePubKey},
    psbt::{PsbtExt, PsbtInputExt, PsbtInputSatisfier},
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ToPublicKey,
};
use tapyrus::{
    absolute, psbt, script::color_identifier::ColorIdentifier, Address, Block, FeeRate, MalFixTxid,
    Network, OutPoint, PublicKey, Script, ScriptBuf, Sequence, Transaction, TxOut, Witness,
};
use tapyrus::{address::NetworkChecked, secp256k1::Scalar};
use tapyrus::{consensus::encode::serialize, transaction, BlockHash, Psbt};
use tapyrus::{constants::mainnet_genesis_block, constants::testnet_genesis_block, Amount};
use tapyrus::{
    hex::DisplayHex,
    sighash::{EcdsaSighashType, TapSighashType},
};
use tapyrus::{secp256k1::SecretKey, PrivateKey};
use tapyrus::{
    secp256k1::{All, Secp256k1},
    TxIn,
};
pub use tdk_chain::keychain::Balance;
use tdk_chain::tx_graph::CalculateFeeError;
use tdk_chain::{
    contract,
    indexed_tx_graph::{self},
    keychain::{self, KeychainTxOutIndex},
    local_chain::{
        self, ApplyHeaderError, CannotConnectError, CheckPoint, CheckPointIter, LocalChain,
    },
    spk_client::{FullScanRequest, FullScanResult, SyncRequest, SyncResult},
    tx_graph::{CanonicalTx, TxGraph},
    Append, BlockId, ChainPosition, ConfirmationTime, ConfirmationTimeHeightAnchor, Contract,
    DescriptorId, FullTxOut, IndexedTxGraph,
};
use tdk_persist::{Persist, PersistBackend};

pub mod coin_selection;
pub mod export;
pub mod signer;
pub mod tx_builder;
pub(crate) mod utils;

pub mod error;

pub use utils::IsDust;

use coin_selection::DefaultCoinSelectionAlgorithm;
use signer::{SignOptions, SignerOrdering, SignersContainer, TransactionSigner};
use tx_builder::{FeePolicy, TxBuilder, TxParams};
use utils::{check_nsequence_rbf, After, Older, SecpCtx};

use crate::descriptor::policy::BuildSatisfaction;
use crate::descriptor::{
    self, calc_checksum, into_wallet_descriptor_checked, DerivedDescriptor, DescriptorMeta,
    ExtendedDescriptor, ExtractPolicy, IntoWalletDescriptor, Policy, XKeyUtils,
};
use crate::psbt::PsbtUtils;
use crate::signer::SignerError;
use crate::types::*;
use crate::wallet::coin_selection::Excess::{Change, NoChange};
use crate::wallet::error::{BuildFeeBumpError, CreateTxError, MiniscriptPsbtError};
use num_bigint::BigUint;

use self::coin_selection::Error;

const COINBASE_MATURITY: u32 = 100;

/// A Bitcoin wallet
///
/// The `Wallet` acts as a way of coherently interfacing with output descriptors and related transactions.
/// Its main components are:
///
/// 1. output *descriptors* from which it can derive addresses.
/// 2. [`signer`]s that can contribute signatures to addresses instantiated from the descriptors.
///
/// [`signer`]: crate::signer
#[derive(Debug)]
pub struct Wallet {
    signers: Arc<SignersContainer>,
    change_signers: Arc<SignersContainer>,
    chain: LocalChain,
    indexed_graph: IndexedTxGraph<ConfirmationTimeHeightAnchor, KeychainTxOutIndex<KeychainKind>>,
    persist: Persist<ChangeSet>,
    network: Network,
    secp: SecpCtx,
    contracts: BTreeMap<String, Contract>,
}

/// An update to [`Wallet`].
///
/// It updates [`tdk_chain::keychain::KeychainTxOutIndex`], [`tdk_chain::TxGraph`] and [`local_chain::LocalChain`] atomically.
#[derive(Debug, Clone, Default)]
pub struct Update {
    /// Contains the last active derivation indices per keychain (`K`), which is used to update the
    /// [`KeychainTxOutIndex`].
    pub last_active_indices: BTreeMap<KeychainKind, u32>,

    /// Update for the wallet's internal [`TxGraph`].
    pub graph: TxGraph<ConfirmationTimeHeightAnchor>,

    /// Update for the wallet's internal [`LocalChain`].
    ///
    /// [`LocalChain`]: local_chain::LocalChain
    pub chain: Option<CheckPoint>,
}

impl From<FullScanResult<KeychainKind>> for Update {
    fn from(value: FullScanResult<KeychainKind>) -> Self {
        Self {
            last_active_indices: value.last_active_indices,
            graph: value.graph_update,
            chain: Some(value.chain_update),
        }
    }
}

impl From<SyncResult> for Update {
    fn from(value: SyncResult) -> Self {
        Self {
            last_active_indices: BTreeMap::new(),
            graph: value.graph_update,
            chain: Some(value.chain_update),
        }
    }
}

/// The changes made to a wallet by applying an [`Update`].
pub type ChangeSet = tdk_persist::CombinedChangeSet<KeychainKind, ConfirmationTimeHeightAnchor>;

/// A derived address and the index it was found at.
/// For convenience this automatically derefs to `Address`
#[derive(Debug, PartialEq, Eq)]
pub struct AddressInfo {
    /// Child index of this address
    pub index: u32,
    /// Address
    pub address: Address,
    /// Type of keychain
    pub keychain: KeychainKind,
}

impl Deref for AddressInfo {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl fmt::Display for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl Wallet {
    /// Creates a wallet that does not persist data.
    pub fn new_no_persist<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        network: Network,
    ) -> Result<Self, DescriptorError> {
        Self::new(descriptor, change_descriptor, (), network).map_err(|e| match e {
            NewError::NonEmptyDatabase => unreachable!("mock-database cannot have data"),
            NewError::Descriptor(e) => e,
            NewError::Persist(_) => unreachable!("mock-write must always succeed"),
        })
    }

    /// Creates a wallet that does not persist data, with a custom genesis hash.
    pub fn new_no_persist_with_genesis_hash<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        network: Network,
        genesis_hash: BlockHash,
    ) -> Result<Self, crate::descriptor::DescriptorError> {
        Self::new_with_genesis_hash(descriptor, change_descriptor, (), network, genesis_hash)
            .map_err(|e| match e {
                NewError::NonEmptyDatabase => unreachable!("mock-database cannot have data"),
                NewError::Descriptor(e) => e,
                NewError::Persist(_) => unreachable!("mock-write must always succeed"),
            })
    }
}

/// The error type when constructing a fresh [`Wallet`].
///
/// Methods [`new`] and [`new_with_genesis_hash`] may return this error.
///
/// [`new`]: Wallet::new
/// [`new_with_genesis_hash`]: Wallet::new_with_genesis_hash
#[derive(Debug)]
pub enum NewError {
    /// Database already has data.
    NonEmptyDatabase,
    /// There was problem with the passed-in descriptor(s).
    Descriptor(crate::descriptor::DescriptorError),
    /// We were unable to write the wallet's data to the persistence backend.
    Persist(anyhow::Error),
}

impl fmt::Display for NewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NewError::NonEmptyDatabase => write!(
                f,
                "database already has data - use `load` or `new_or_load` methods instead"
            ),
            NewError::Descriptor(e) => e.fmt(f),
            NewError::Persist(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewError {}

/// The error type when loading a [`Wallet`] from persistence.
///
/// Method [`load`] may return this error.
///
/// [`load`]: Wallet::load
#[derive(Debug)]
pub enum LoadError {
    /// There was a problem with the passed-in descriptor(s).
    Descriptor(crate::descriptor::DescriptorError),
    /// Loading data from the persistence backend failed.
    Persist(anyhow::Error),
    /// Wallet not initialized, persistence backend is empty.
    NotInitialized,
    /// Data loaded from persistence is missing network type.
    MissingNetwork,
    /// Data loaded from persistence is missing genesis hash.
    MissingGenesis,
    /// Data loaded from persistence is missing descriptor.
    MissingDescriptor(KeychainKind),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Descriptor(e) => e.fmt(f),
            LoadError::Persist(e) => e.fmt(f),
            LoadError::NotInitialized => {
                write!(f, "wallet is not initialized, persistence backend is empty")
            }
            LoadError::MissingNetwork => write!(f, "loaded data is missing network type"),
            LoadError::MissingGenesis => write!(f, "loaded data is missing genesis hash"),
            LoadError::MissingDescriptor(k) => {
                write!(f, "loaded data is missing descriptor for keychain {k:?}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoadError {}

/// Error type for when we try load a [`Wallet`] from persistence and creating it if non-existent.
///
/// Methods [`new_or_load`] and [`new_or_load_with_genesis_hash`] may return this error.
///
/// [`new_or_load`]: Wallet::new_or_load
/// [`new_or_load_with_genesis_hash`]: Wallet::new_or_load_with_genesis_hash
#[derive(Debug)]
pub enum NewOrLoadError {
    /// There is a problem with the passed-in descriptor.
    Descriptor(crate::descriptor::DescriptorError),
    /// Either writing to or loading from the persistence backend failed.
    Persist(anyhow::Error),
    /// Wallet is not initialized, persistence backend is empty.
    NotInitialized,
    /// The loaded genesis hash does not match what was provided.
    LoadedGenesisDoesNotMatch {
        /// The expected genesis block hash.
        expected: BlockHash,
        /// The block hash loaded from persistence.
        got: Option<BlockHash>,
    },
    /// The loaded network type does not match what was provided.
    LoadedNetworkDoesNotMatch {
        /// The expected network type.
        expected: Network,
        /// The network type loaded from persistence.
        got: Option<Network>,
    },
    /// The loaded desccriptor does not match what was provided.
    LoadedDescriptorDoesNotMatch {
        /// The descriptor loaded from persistence.
        got: Option<ExtendedDescriptor>,
        /// The keychain of the descriptor not matching
        keychain: KeychainKind,
    },
}

impl fmt::Display for NewOrLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NewOrLoadError::Descriptor(e) => e.fmt(f),
            NewOrLoadError::Persist(e) => write!(
                f,
                "failed to either write to or load from persistence, {}",
                e
            ),
            NewOrLoadError::NotInitialized => {
                write!(f, "wallet is not initialized, persistence backend is empty")
            }
            NewOrLoadError::LoadedGenesisDoesNotMatch { expected, got } => {
                write!(f, "loaded genesis hash is not {}, got {:?}", expected, got)
            }
            NewOrLoadError::LoadedNetworkDoesNotMatch { expected, got } => {
                write!(f, "loaded network type is not {}, got {:?}", expected, got)
            }
            NewOrLoadError::LoadedDescriptorDoesNotMatch { got, keychain } => {
                write!(
                    f,
                    "loaded descriptor is different from what was provided, got {:?} for keychain {:?}",
                    got, keychain
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewOrLoadError {}

/// An error that may occur when inserting a transaction into [`Wallet`].
#[derive(Debug)]
pub enum InsertTxError {
    /// The error variant that occurs when the caller attempts to insert a transaction with a
    /// confirmation height that is greater than the internal chain tip.
    ConfirmationHeightCannotBeGreaterThanTip {
        /// The internal chain's tip height.
        tip_height: u32,
        /// The introduced transaction's confirmation height.
        tx_height: u32,
    },
}

impl fmt::Display for InsertTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertTxError::ConfirmationHeightCannotBeGreaterThanTip {
                tip_height,
                tx_height,
            } => {
                write!(f, "cannot insert tx with confirmation height ({}) higher than internal tip height ({})", tx_height, tip_height)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertTxError {}

/// An error that may occur when applying a block to [`Wallet`].
#[derive(Debug)]
pub enum ApplyBlockError {
    /// Occurs when the update chain cannot connect with original chain.
    CannotConnect(CannotConnectError),
    /// Occurs when the `connected_to` hash does not match the hash derived from `block`.
    UnexpectedConnectedToHash {
        /// Block hash of `connected_to`.
        connected_to_hash: BlockHash,
        /// Expected block hash of `connected_to`, as derived from `block`.
        expected_hash: BlockHash,
    },
}

impl fmt::Display for ApplyBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyBlockError::CannotConnect(err) => err.fmt(f),
            ApplyBlockError::UnexpectedConnectedToHash {
                expected_hash: block_hash,
                connected_to_hash: checkpoint_hash,
            } => write!(
                f,
                "`connected_to` hash {} differs from the expected hash {} (which is derived from `block`)",
                checkpoint_hash, block_hash
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApplyBlockError {}

const CONTRACT_MAX_SIZE: usize = 256;
/// An error that may occur when creating p2c-address.
#[derive(Debug)]
pub enum GenerateContractError {
    /// Contract data is empty
    ContractTooSmall {
        /// Contract size
        length: usize,
    },
    /// Contract data is too large.
    ContractTooLarge {
        /// Contract size
        length: usize,
    },
    /// Invalid address
    InvalidAddress(tapyrus::address::Error),
}

impl fmt::Display for GenerateContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateContractError::ContractTooSmall { length } => {
                write!(f, "contract is too short (size: {})", length)
            }
            GenerateContractError::ContractTooLarge { length } => {
                write!(f, "contract is too large (size: {})", length)
            }
            GenerateContractError::InvalidAddress(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenerateContractError {}

/// An error that may occur when registering contract data.
#[derive(Debug)]
pub enum CreateContractError {
    /// Contract with the specified contract_id already exists.
    ContractAlreadyExist {
        /// identifier of contract.
        contract_id: String,
    },
    /// Payment base is invalid.
    InvalidPublicKey {
        /// public key(payment base).
        public_key: PublicKey,
    },
    /// Other error.
    Error {
        /// An error that caused this error.
        reason: String,
    },
}

impl fmt::Display for CreateContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateContractError::ContractAlreadyExist { contract_id } => {
                write!(f, "contract already exists (contract_id: {})", contract_id)
            }
            CreateContractError::InvalidPublicKey { public_key } => {
                write!(f, "invalid payment base  ({})", public_key)
            }
            CreateContractError::Error { reason } => {
                write!(f, "can not create contract address (reason: {})", reason)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreateContractError {}

/// An error that may occur when updating contract.
#[derive(Debug)]
pub enum UpdateContractError {
    /// No contract with the specified contract_id has been found.
    ContractNotFound {
        /// identifier of contract.
        contract_id: String,
    },
    /// Other error.
    Error {
        /// An error that caused this error.
        reason: String,
    },
}

impl fmt::Display for UpdateContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateContractError::ContractNotFound { contract_id } => {
                write!(f, "contract does not found (contract_id: {})", contract_id)
            }
            UpdateContractError::Error { reason } => {
                write!(f, "can not update contract address (reason: {})", reason)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UpdateContractError {}

impl Wallet {
    /// Initialize an empty [`Wallet`].
    pub fn new<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
        network: Network,
    ) -> Result<Self, NewError> {
        let genesis_hash = mainnet_genesis_block().block_hash();
        Self::new_with_genesis_hash(descriptor, change_descriptor, db, network, genesis_hash)
    }

    /// Initialize an empty [`Wallet`].
    pub fn new_with_testnet<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
    ) -> Result<Self, NewError> {
        let genesis_hash = testnet_genesis_block().block_hash();
        Self::new_with_genesis_hash(
            descriptor,
            change_descriptor,
            db,
            Network::Prod,
            genesis_hash,
        )
    }

    fn build_p2c_spk_from_contract(wallet: &mut Wallet, contracts: contract::ChangeSet) {
        for (_, contract) in contracts {
            let payment_base = contract.payment_base;
            match wallet.create_pay_to_contract_script(&payment_base, contract.contract, None) {
                Ok(spk) => {
                    wallet.insert_p2c_spk(spk, payment_base);
                }
                _ => {}
            }
        }
    }

    /// Initialize an empty [`Wallet`] with a custom genesis hash.
    ///
    /// This is like [`Wallet::new`] with an additional `genesis_hash` parameter. This is useful
    /// for syncing from alternative networks.
    pub fn new_with_genesis_hash<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        mut db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
        network: Network,
        genesis_hash: BlockHash,
    ) -> Result<Self, NewError> {
        if let Ok(changeset) = db.load_from_persistence() {
            if changeset.is_some() {
                return Err(NewError::NonEmptyDatabase);
            }
        }
        let secp = Secp256k1::new();
        let (chain, chain_changeset) = LocalChain::from_genesis_hash(genesis_hash);
        let mut index = KeychainTxOutIndex::<KeychainKind>::default();

        let (signers, change_signers) =
            create_signers(&mut index, &secp, descriptor, change_descriptor, network)
                .map_err(NewError::Descriptor)?;

        let indexed_graph = IndexedTxGraph::new(index);

        let contracts: BTreeMap<String, Contract> = contract::ChangeSet::new();

        let mut persist = Persist::new(db);
        persist.stage(ChangeSet {
            chain: chain_changeset,
            indexed_tx_graph: indexed_graph.initial_changeset(),
            network: Some(network),
            contract: Default::default(),
        });
        persist.commit().map_err(NewError::Persist)?;

        let wallet = Wallet {
            signers,
            change_signers,
            network,
            chain,
            indexed_graph,
            persist,
            secp,
            contracts: contracts.clone(),
        };

        Ok(wallet)
    }

    /// Load [`Wallet`] from the given persistence backend.
    ///
    /// Note that the descriptor secret keys are not persisted to the db; this means that after
    /// calling this method the [`Wallet`] **won't** know the secret keys, and as such, won't be
    /// able to sign transactions.
    ///
    /// If you wish to use the wallet to sign transactions, you need to add the secret keys
    /// manually to the [`Wallet`]:
    ///
    /// ```rust,no_run,ignore
    /// # use tdk_wallet::Wallet;
    /// # use tdk_wallet::signer::{SignersContainer, SignerOrdering};
    /// # use tdk_wallet::descriptor::Descriptor;
    /// # use tapyrus::key::Secp256k1;
    /// # use tdk_wallet::KeychainKind;
    /// # use tdk_sqlite::{Store, rusqlite::Connection};
    /// #
    /// # fn main() -> Result<(), anyhow::Error> {
    /// # let temp_dir = tempfile::tempdir().expect("must create tempdir");
    /// # let file_path = temp_dir.path().join("store.db");
    /// # let conn = Connection::open(file_path).expect("must open connection");
    /// # let db = Store::new(conn).expect("must create db");
    /// let secp = Secp256k1::new();
    ///
    /// let (external_descriptor, external_keymap) = Descriptor::parse_descriptor(&secp, "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)").unwrap();
    /// let (internal_descriptor, internal_keymap) = Descriptor::parse_descriptor(&secp, "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)").unwrap();
    ///
    /// let external_signer_container = SignersContainer::build(external_keymap, &external_descriptor, &secp);
    /// let internal_signer_container = SignersContainer::build(internal_keymap, &internal_descriptor, &secp);
    ///
    /// let mut wallet = Wallet::load(db)?;
    ///
    /// external_signer_container.signers().into_iter()
    ///     .for_each(|s| wallet.add_signer(KeychainKind::External, SignerOrdering::default(), s.clone()));
    /// internal_signer_container.signers().into_iter()
    ///     .for_each(|s| wallet.add_signer(KeychainKind::Internal, SignerOrdering::default(), s.clone()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Alternatively, you can call [`Wallet::new_or_load`], which will add the private keys of the
    /// passed-in descriptors to the [`Wallet`].
    pub fn load(
        mut db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
    ) -> Result<Self, LoadError> {
        let changeset = db
            .load_from_persistence()
            .map_err(LoadError::Persist)?
            .ok_or(LoadError::NotInitialized)?;
        Self::load_from_changeset(db, changeset)
    }

    fn load_from_changeset(
        db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
        changeset: ChangeSet,
    ) -> Result<Self, LoadError> {
        let secp = Secp256k1::new();
        let network = changeset.network.ok_or(LoadError::MissingNetwork)?;
        let chain =
            LocalChain::from_changeset(changeset.chain).map_err(|_| LoadError::MissingGenesis)?;
        let mut index = KeychainTxOutIndex::<KeychainKind>::default();
        let descriptor = changeset
            .indexed_tx_graph
            .indexer
            .keychains_added
            .get(&KeychainKind::External)
            .ok_or(LoadError::MissingDescriptor(KeychainKind::External))?
            .clone();
        let change_descriptor = changeset
            .indexed_tx_graph
            .indexer
            .keychains_added
            .get(&KeychainKind::Internal)
            .ok_or(LoadError::MissingDescriptor(KeychainKind::Internal))?
            .clone();

        let (signers, change_signers) =
            create_signers(&mut index, &secp, descriptor, change_descriptor, network)
                .expect("Can't fail: we passed in valid descriptors, recovered from the changeset");

        let mut indexed_graph = IndexedTxGraph::new(index);
        indexed_graph.apply_changeset(changeset.indexed_tx_graph);

        let contracts = changeset.contract;

        let persist = Persist::new(db);

        let mut wallet = Wallet {
            signers,
            change_signers,
            chain,
            indexed_graph,
            persist,
            network,
            secp,
            contracts: contracts.clone(),
        };
        Self::build_p2c_spk_from_contract(&mut wallet, contracts);
        Ok(wallet)
    }

    /// Either loads [`Wallet`] from persistence, or initializes it if it does not exist.
    ///
    /// This method will fail if the loaded [`Wallet`] has different parameters to those provided.
    pub fn new_or_load<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
        network: Network,
    ) -> Result<Self, NewOrLoadError> {
        let genesis_hash = mainnet_genesis_block().block_hash();
        Self::new_or_load_with_genesis_hash(
            descriptor,
            change_descriptor,
            db,
            network,
            genesis_hash,
        )
    }

    /// Either loads [`Wallet`] from persistence, or initializes it if it does not exist.
    ///
    /// This method will fail if the loaded [`Wallet`] has different parameters to those provided.
    pub fn new_or_load_with_testnet<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
    ) -> Result<Self, NewOrLoadError> {
        let genesis_hash = testnet_genesis_block().block_hash();
        Self::new_or_load_with_genesis_hash(
            descriptor,
            change_descriptor,
            db,
            Network::Prod,
            genesis_hash,
        )
    }

    /// Either loads [`Wallet`] from persistence, or initializes it if it does not exist, using the
    /// provided descriptor, change descriptor, network, and custom genesis hash.
    ///
    /// This method will fail if the loaded [`Wallet`] has different parameters to those provided.
    /// This is like [`Wallet::new_or_load`] with an additional `genesis_hash` parameter. This is
    /// useful for syncing from alternative networks.
    pub fn new_or_load_with_genesis_hash<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: E,
        mut db: impl PersistBackend<ChangeSet> + Send + Sync + 'static,
        network: Network,
        genesis_hash: BlockHash,
    ) -> Result<Self, NewOrLoadError> {
        let changeset = db
            .load_from_persistence()
            .map_err(NewOrLoadError::Persist)?;
        match changeset {
            Some(changeset) => {
                let mut wallet = Self::load_from_changeset(db, changeset).map_err(|e| match e {
                    LoadError::Descriptor(e) => NewOrLoadError::Descriptor(e),
                    LoadError::Persist(e) => NewOrLoadError::Persist(e),
                    LoadError::NotInitialized => NewOrLoadError::NotInitialized,
                    LoadError::MissingNetwork => NewOrLoadError::LoadedNetworkDoesNotMatch {
                        expected: network,
                        got: None,
                    },
                    LoadError::MissingGenesis => NewOrLoadError::LoadedGenesisDoesNotMatch {
                        expected: genesis_hash,
                        got: None,
                    },
                    LoadError::MissingDescriptor(keychain) => {
                        NewOrLoadError::LoadedDescriptorDoesNotMatch {
                            got: None,
                            keychain,
                        }
                    }
                })?;
                if wallet.network != network {
                    return Err(NewOrLoadError::LoadedNetworkDoesNotMatch {
                        expected: network,
                        got: Some(wallet.network),
                    });
                }
                if wallet.chain.genesis_hash() != genesis_hash {
                    return Err(NewOrLoadError::LoadedGenesisDoesNotMatch {
                        expected: genesis_hash,
                        got: Some(wallet.chain.genesis_hash()),
                    });
                }

                let (expected_descriptor, expected_descriptor_keymap) = descriptor
                    .into_wallet_descriptor(&wallet.secp, network)
                    .map_err(NewOrLoadError::Descriptor)?;
                let wallet_descriptor = wallet.public_descriptor(KeychainKind::External);
                if wallet_descriptor != &expected_descriptor {
                    return Err(NewOrLoadError::LoadedDescriptorDoesNotMatch {
                        got: Some(wallet_descriptor.clone()),
                        keychain: KeychainKind::External,
                    });
                }
                // if expected descriptor has private keys add them as new signers
                if !expected_descriptor_keymap.is_empty() {
                    let signer_container = SignersContainer::build(
                        expected_descriptor_keymap,
                        &expected_descriptor,
                        &wallet.secp,
                    );
                    signer_container.signers().into_iter().for_each(|signer| {
                        wallet.add_signer(
                            KeychainKind::External,
                            SignerOrdering::default(),
                            signer.clone(),
                        )
                    });
                }

                let (expected_change_descriptor, expected_change_descriptor_keymap) =
                    change_descriptor
                        .into_wallet_descriptor(&wallet.secp, network)
                        .map_err(NewOrLoadError::Descriptor)?;
                let wallet_change_descriptor = wallet.public_descriptor(KeychainKind::Internal);
                if wallet_change_descriptor != &expected_change_descriptor {
                    return Err(NewOrLoadError::LoadedDescriptorDoesNotMatch {
                        got: Some(wallet_change_descriptor.clone()),
                        keychain: KeychainKind::Internal,
                    });
                }
                // if expected change descriptor has private keys add them as new signers
                if !expected_change_descriptor_keymap.is_empty() {
                    let signer_container = SignersContainer::build(
                        expected_change_descriptor_keymap,
                        &expected_change_descriptor,
                        &wallet.secp,
                    );
                    signer_container.signers().into_iter().for_each(|signer| {
                        wallet.add_signer(
                            KeychainKind::Internal,
                            SignerOrdering::default(),
                            signer.clone(),
                        )
                    });
                }

                Ok(wallet)
            }
            None => Self::new_with_genesis_hash(
                descriptor,
                change_descriptor,
                db,
                network,
                genesis_hash,
            )
            .map_err(|e| match e {
                NewError::NonEmptyDatabase => {
                    unreachable!("database is already checked to have no data")
                }
                NewError::Descriptor(e) => NewOrLoadError::Descriptor(e),
                NewError::Persist(e) => NewOrLoadError::Persist(e),
            }),
        }
    }

    /// Get the Bitcoin network the wallet is using.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Iterator over all keychains in this wallet
    pub fn keychains(&self) -> impl Iterator<Item = (&KeychainKind, &ExtendedDescriptor)> {
        self.indexed_graph.index.keychains()
    }

    /// Peek an address of the given `keychain` at `index` without revealing it.
    ///
    /// For non-wildcard descriptors this returns the same address at every provided index.
    ///
    /// # Panics
    ///
    /// This panics when the caller requests for an address of derivation index greater than the
    /// [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) max index.
    pub fn peek_address(&self, keychain: KeychainKind, mut index: u32) -> AddressInfo {
        let mut spk_iter = self
            .indexed_graph
            .index
            .unbounded_spk_iter(&keychain)
            .expect("keychain must exist");
        if !spk_iter.descriptor().has_wildcard() {
            index = 0;
        }
        let (index, spk) = spk_iter
            .nth(index as usize)
            .expect("derivation index is out of bounds");

        AddressInfo {
            index,
            address: Address::from_script(&spk, self.network).expect("must have address form"),
            keychain,
        }
    }

    /// Attempt to reveal the next address of the given `keychain`.
    ///
    /// This will increment the internal derivation index. If the keychain's descriptor doesn't
    /// contain a wildcard or every address is already revealed up to the maximum derivation
    /// index defined in [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
    /// then returns the last revealed address.
    ///
    /// # Errors
    ///
    /// If writing to persistent storage fails.
    pub fn reveal_next_address(&mut self, keychain: KeychainKind) -> anyhow::Result<AddressInfo> {
        let ((index, spk), index_changeset) = self
            .indexed_graph
            .index
            .reveal_next_spk(&keychain)
            .expect("keychain must exist");

        self.persist
            .stage_and_commit(indexed_tx_graph::ChangeSet::from(index_changeset).into())?;

        Ok(AddressInfo {
            index,
            address: Address::from_script(spk, self.network).expect("must have address form"),
            keychain,
        })
    }

    /// Reveal addresses up to and including the target `index` and return an iterator
    /// of newly revealed addresses.
    ///
    /// If the target `index` is unreachable, we make a best effort to reveal up to the last
    /// possible index. If all addresses up to the given `index` are already revealed, then
    /// no new addresses are returned.
    ///
    /// # Errors
    ///
    /// If writing to persistent storage fails.
    pub fn reveal_addresses_to(
        &mut self,
        keychain: KeychainKind,
        index: u32,
    ) -> anyhow::Result<impl Iterator<Item = AddressInfo> + '_> {
        let (spk_iter, index_changeset) = self
            .indexed_graph
            .index
            .reveal_to_target(&keychain, index)
            .expect("keychain must exist");

        self.persist
            .stage_and_commit(indexed_tx_graph::ChangeSet::from(index_changeset).into())?;

        Ok(spk_iter.map(move |(index, spk)| AddressInfo {
            index,
            address: Address::from_script(&spk, self.network).expect("must have address form"),
            keychain,
        }))
    }

    /// Get the next unused address for the given `keychain`, i.e. the address with the lowest
    /// derivation index that hasn't been used.
    ///
    /// This will attempt to derive and reveal a new address if no newly revealed addresses
    /// are available. See also [`reveal_next_address`](Self::reveal_next_address).
    ///
    /// # Errors
    ///
    /// If writing to persistent storage fails.
    pub fn next_unused_address(&mut self, keychain: KeychainKind) -> anyhow::Result<AddressInfo> {
        let ((index, spk), index_changeset) = self
            .indexed_graph
            .index
            .next_unused_spk(&keychain)
            .expect("keychain must exist");

        self.persist
            .stage_and_commit(indexed_tx_graph::ChangeSet::from(index_changeset).into())?;

        Ok(AddressInfo {
            index,
            address: Address::from_script(spk, self.network).expect("must have address form"),
            keychain,
        })
    }

    /// Generate pay-to-contract address with the specified content hash.
    pub fn create_pay_to_contract_address(
        &self,
        payment_base: &PublicKey,
        contract: Vec<u8>,
        color_id: Option<ColorIdentifier>,
    ) -> Result<Address<NetworkChecked>, GenerateContractError> {
        let script = self.create_pay_to_contract_script(payment_base, contract, color_id)?;
        let address = Address::from_script(script.as_script(), self.network)
            .map_err(GenerateContractError::InvalidAddress)?;
        Ok(address)
    }

    fn create_pay_to_contract_script(
        &self,
        payment_base: &PublicKey,
        contract: Vec<u8>,
        color_id: Option<ColorIdentifier>,
    ) -> Result<ScriptBuf, GenerateContractError> {
        let p2c_public_key = self.pay_to_contract_key(payment_base, contract)?;
        let pubkey_hash = p2c_public_key.pubkey_hash();
        let script: ScriptBuf = match color_id {
            Some(c) if c.is_colored() => ScriptBuf::new_cp2pkh(&color_id.unwrap(), &pubkey_hash),
            _ => ScriptBuf::new_p2pkh(&pubkey_hash),
        };
        Ok(script)
    }

    /// Generate pay-to-contract public key with the specified content hash.
    pub fn pay_to_contract_key(
        &self,
        payment_base: &PublicKey,
        contract: Vec<u8>,
    ) -> Result<PublicKey, GenerateContractError> {
        if contract.is_empty() {
            return Err(GenerateContractError::ContractTooSmall { length: 0 });
        }
        if contract.len() > CONTRACT_MAX_SIZE {
            return Err(GenerateContractError::ContractTooLarge {
                length: contract.len(),
            });
        }
        let key =
            Contract::create_pay_to_contract_public_key(payment_base, contract, self.secp_ctx());
        Ok(key)
    }

    /// Marks an address used of the given `keychain` at `index`.
    ///
    /// Returns whether the given index was present and then removed from the unused set.
    pub fn mark_used(&mut self, keychain: KeychainKind, index: u32) -> bool {
        self.indexed_graph.index.mark_used(keychain, index)
    }

    /// Undoes the effect of [`mark_used`] and returns whether the `index` was inserted
    /// back into the unused set.
    ///
    /// Since this is only a superficial marker, it will have no effect if the address at the given
    /// `index` was actually used, i.e. the wallet has previously indexed a tx output for the
    /// derived spk.
    ///
    /// [`mark_used`]: Self::mark_used
    pub fn unmark_used(&mut self, keychain: KeychainKind, index: u32) -> bool {
        self.indexed_graph.index.unmark_used(keychain, index)
    }

    /// List addresses that are revealed but unused.
    ///
    /// Note if the returned iterator is empty you can reveal more addresses
    /// by using [`reveal_next_address`](Self::reveal_next_address) or
    /// [`reveal_addresses_to`](Self::reveal_addresses_to).
    pub fn list_unused_addresses(
        &self,
        keychain: KeychainKind,
    ) -> impl DoubleEndedIterator<Item = AddressInfo> + '_ {
        self.indexed_graph
            .index
            .unused_keychain_spks(&keychain)
            .map(move |(index, spk)| AddressInfo {
                index,
                address: Address::from_script(spk, self.network).expect("must have address form"),
                keychain,
            })
    }

    /// Return whether or not a `script` is part of this wallet (either internal or external)
    pub fn is_mine(&self, script: &Script) -> bool {
        self.indexed_graph.index.index_of_spk(script).is_some()
    }

    /// Finds how the wallet derived the script pubkey `spk`.
    ///
    /// Will only return `Some(_)` if the wallet has given out the spk.
    pub fn derivation_of_spk(&self, spk: &Script) -> Option<(KeychainKind, u32)> {
        self.indexed_graph.index.index_of_spk(spk)
    }

    /// Return the list of unspent outputs of this wallet
    pub fn list_unspent(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.indexed_graph
            .graph()
            .filter_chain_unspents(
                &self.chain,
                self.chain.tip().block_id(),
                self.indexed_graph.index.outpoints(),
            )
            .map(|((k, i), full_txo)| new_local_utxo(k, i, full_txo))
    }

    /// List all relevant outputs (includes both spent and unspent, confirmed and unconfirmed).
    ///
    /// To list only unspent outputs (UTXOs), use [`Wallet::list_unspent`] instead.
    pub fn list_output(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.indexed_graph
            .graph()
            .filter_chain_txouts(
                &self.chain,
                self.chain.tip().block_id(),
                self.indexed_graph.index.outpoints(),
            )
            .map(|((k, i), full_txo)| new_local_utxo(k, i, full_txo))
    }

    /// Get all the checkpoints the wallet is currently storing indexed by height.
    pub fn checkpoints(&self) -> CheckPointIter {
        self.chain.iter_checkpoints()
    }

    /// Returns the latest checkpoint.
    pub fn latest_checkpoint(&self) -> CheckPoint {
        self.chain.tip()
    }

    /// Get unbounded script pubkey iterators for both `Internal` and `External` keychains.
    ///
    /// This is intended to be used when doing a full scan of your addresses (e.g. after restoring
    /// from seed words). You pass the `BTreeMap` of iterators to a blockchain data source (e.g.
    /// electrum server) which will go through each address until it reaches a *stop gap*.
    ///
    /// Note carefully that iterators go over **all** script pubkeys on the keychains (not what
    /// script pubkeys the wallet is storing internally).
    pub fn all_unbounded_spk_iters(
        &self,
    ) -> BTreeMap<KeychainKind, impl Iterator<Item = (u32, ScriptBuf)> + Clone> {
        self.indexed_graph.index.all_unbounded_spk_iters()
    }

    /// Get an unbounded script pubkey iterator for the given `keychain`.
    ///
    /// See [`all_unbounded_spk_iters`] for more documentation
    ///
    /// [`all_unbounded_spk_iters`]: Self::all_unbounded_spk_iters
    pub fn unbounded_spk_iter(
        &self,
        keychain: KeychainKind,
    ) -> impl Iterator<Item = (u32, ScriptBuf)> + Clone {
        self.indexed_graph
            .index
            .unbounded_spk_iter(&keychain)
            .expect("keychain must exist")
    }

    /// Returns the utxo owned by this wallet corresponding to `outpoint` if it exists in the
    /// wallet's database.
    pub fn get_utxo(&self, op: OutPoint) -> Option<LocalOutput> {
        let (keychain, index, _) = self.indexed_graph.index.txout(op)?;
        self.indexed_graph
            .graph()
            .filter_chain_unspents(
                &self.chain,
                self.chain.tip().block_id(),
                core::iter::once(((), op)),
            )
            .map(|(_, full_txo)| new_local_utxo(keychain, index, full_txo))
            .next()
    }

    /// Inserts a [`TxOut`] at [`OutPoint`] into the wallet's transaction graph.
    ///
    /// This is used for providing a previous output's value so that we can use [`calculate_fee`]
    /// or [`calculate_fee_rate`] on a given transaction. Outputs inserted with this method will
    /// not be returned in [`list_unspent`] or [`list_output`].
    ///
    /// Any inserted `TxOut`s are not persisted until [`commit`] is called.
    ///
    /// **WARNING:** This should only be used to add `TxOut`s that the wallet does not own. Only
    /// insert `TxOut`s that you trust the values for!
    ///
    /// [`calculate_fee`]: Self::calculate_fee
    /// [`calculate_fee_rate`]: Self::calculate_fee_rate
    /// [`list_unspent`]: Self::list_unspent
    /// [`list_output`]: Self::list_output
    /// [`commit`]: Self::commit
    pub fn insert_txout(&mut self, outpoint: OutPoint, txout: TxOut) {
        let additions = self.indexed_graph.insert_txout(outpoint, txout);
        self.persist.stage(ChangeSet::from(additions));
    }

    /// Calculates the fee of a given transaction. Returns [`Amount::ZERO`] if `tx` is a coinbase transaction.
    ///
    /// To calculate the fee for a [`Transaction`] with inputs not owned by this wallet you must
    /// manually insert the TxOut(s) into the tx graph using the [`insert_txout`] function.
    ///
    /// Note `tx` does not have to be in the graph for this to work.
    ///
    /// # Examples
    ///
    /// ```rust, no_run
    /// # use tapyrus::MalFixTxid;
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let txid:MalFixTxid = todo!();
    /// let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    /// let fee = wallet.calculate_fee(&tx).expect("fee");
    /// ```
    ///
    ///
    /// ```rust, no_run
    /// # use tapyrus::Psbt;
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let mut psbt: Psbt = todo!();
    /// let tx = &psbt.clone().extract_tx().expect("tx");
    /// let fee = wallet.calculate_fee(tx).expect("fee");
    /// ```
    /// [`insert_txout`]: Self::insert_txout
    pub fn calculate_fee(&self, tx: &Transaction) -> Result<Amount, CalculateFeeError> {
        self.indexed_graph.graph().calculate_fee(tx)
    }

    /// Calculate the [`FeeRate`] for a given transaction.
    ///
    /// To calculate the fee rate for a [`Transaction`] with inputs not owned by this wallet you must
    /// manually insert the TxOut(s) into the tx graph using the [`insert_txout`] function.
    ///
    /// Note `tx` does not have to be in the graph for this to work.
    ///
    /// # Examples
    ///
    /// ```rust, no_run
    /// # use tapyrus::MalFixTxid;
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let txid:MalFixTxid = todo!();
    /// let tx = wallet.get_tx(txid).expect("transaction").tx_node.tx;
    /// let fee_rate = wallet.calculate_fee_rate(&tx).expect("fee rate");
    /// ```
    ///
    /// ```rust, no_run
    /// # use tapyrus::Psbt;
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let mut psbt: Psbt = todo!();
    /// let tx = &psbt.clone().extract_tx().expect("tx");
    /// let fee_rate = wallet.calculate_fee_rate(tx).expect("fee rate");
    /// ```
    /// [`insert_txout`]: Self::insert_txout
    pub fn calculate_fee_rate(&self, tx: &Transaction) -> Result<FeeRate, CalculateFeeError> {
        self.calculate_fee(tx).map(|fee| fee / tx.weight())
    }

    /// Compute the `tx`'s sent and received [`Amount`]s.
    ///
    /// This method returns a tuple `(sent, received)`. Sent is the sum of the txin amounts
    /// that spend from previous txouts tracked by this wallet. Received is the summation
    /// of this tx's outputs that send to script pubkeys tracked by this wallet.
    ///
    /// # Examples
    ///
    /// ```rust, no_run
    /// # use tapyrus::{MalFixTxid, script::color_identifier::ColorIdentifier};
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let txid:MalFixTxid = todo!();
    /// let tx = wallet.get_tx(txid).expect("tx exists").tx_node.tx;
    /// let color_id = ColorIdentifier::default();
    /// let (sent, received) = wallet.sent_and_received(&tx, &color_id);
    /// ```
    ///
    /// ```rust, no_run
    /// # use tapyrus::{Psbt, script::color_identifier::ColorIdentifier};
    /// # use tdk_wallet::Wallet;
    /// # let mut wallet: Wallet = todo!();
    /// # let mut psbt: Psbt = todo!();
    /// let tx = &psbt.clone().extract_tx().expect("tx");
    /// let color_id = ColorIdentifier::default();
    /// let (sent, received) = wallet.sent_and_received(tx, &color_id);
    /// ```
    pub fn sent_and_received(
        &self,
        tx: &Transaction,
        color_id: &ColorIdentifier,
    ) -> (Amount, Amount) {
        self.indexed_graph.index.sent_and_received(tx, .., color_id)
    }

    /// Get a single transaction from the wallet as a [`CanonicalTx`] (if the transaction exists).
    ///
    /// `CanonicalTx` contains the full transaction alongside meta-data such as:
    /// * Blocks that the transaction is [`Anchor`]ed in. These may or may not be blocks that exist
    ///   in the best chain.
    /// * The [`ChainPosition`] of the transaction in the best chain - whether the transaction is
    ///   confirmed or unconfirmed. If the transaction is confirmed, the anchor which proves the
    ///   confirmation is provided. If the transaction is unconfirmed, the unix timestamp of when
    ///   the transaction was last seen in the mempool is provided.
    ///
    /// ```rust, no_run
    /// use tdk_chain::Anchor;
    /// use tdk_wallet::{chain::ChainPosition, Wallet};
    /// # let wallet: Wallet = todo!();
    /// # let my_txid: tapyrus::MalFixTxid = todo!();
    ///
    /// let canonical_tx = wallet.get_tx(my_txid).expect("panic if tx does not exist");
    ///
    /// // get reference to full transaction
    /// println!("my tx: {:#?}", canonical_tx.tx_node.tx);
    ///
    /// // list all transaction anchors
    /// for anchor in canonical_tx.tx_node.anchors {
    ///     println!(
    ///         "tx is anchored by block of hash {}",
    ///         anchor.anchor_block().hash
    ///     );
    /// }
    ///
    /// // get confirmation status of transaction
    /// match canonical_tx.chain_position {
    ///     ChainPosition::Confirmed(anchor) => println!(
    ///         "tx is confirmed at height {}, we know this since {}:{} is in the best chain",
    ///         anchor.confirmation_height, anchor.anchor_block.height, anchor.anchor_block.hash,
    ///     ),
    ///     ChainPosition::Unconfirmed(last_seen) => println!(
    ///         "tx is last seen at {}, it is unconfirmed as it is not anchored in the best chain",
    ///         last_seen,
    ///     ),
    /// }
    /// ```
    ///
    /// [`Anchor`]: tdk_chain::Anchor
    pub fn get_tx(
        &self,
        txid: MalFixTxid,
    ) -> Option<CanonicalTx<'_, Arc<Transaction>, ConfirmationTimeHeightAnchor>> {
        let graph = self.indexed_graph.graph();

        Some(CanonicalTx {
            chain_position: graph.get_chain_position(
                &self.chain,
                self.chain.tip().block_id(),
                txid,
            )?,
            tx_node: graph.get_tx_node(txid)?,
        })
    }

    /// Add a new checkpoint to the wallet's internal view of the chain.
    /// This stages but does not [`commit`] the change.
    ///
    /// Returns whether anything changed with the insertion (e.g. `false` if checkpoint was already
    /// there).
    ///
    /// [`commit`]: Self::commit
    pub fn insert_checkpoint(
        &mut self,
        block_id: BlockId,
    ) -> Result<bool, local_chain::AlterCheckPointError> {
        let changeset = self.chain.insert_block(block_id)?;
        let changed = !changeset.is_empty();
        self.persist.stage(changeset.into());
        Ok(changed)
    }

    /// Add a transaction to the wallet's internal view of the chain. This stages but does not
    /// [`commit`] the change.
    ///
    /// Returns whether anything changed with the transaction insertion (e.g. `false` if the
    /// transaction was already inserted at the same position).
    ///
    /// A `tx` can be rejected if `position` has a height greater than the [`latest_checkpoint`].
    /// Therefore you should use [`insert_checkpoint`] to insert new checkpoints before manually
    /// inserting new transactions.
    ///
    /// **WARNING:** If `position` is confirmed, we anchor the `tx` to a the lowest checkpoint that
    /// is >= the `position`'s height. The caller is responsible for ensuring the `tx` exists in our
    /// local view of the best chain's history.
    ///
    /// [`commit`]: Self::commit
    /// [`latest_checkpoint`]: Self::latest_checkpoint
    /// [`insert_checkpoint`]: Self::insert_checkpoint
    pub fn insert_tx(
        &mut self,
        tx: Transaction,
        position: ConfirmationTime,
    ) -> Result<bool, InsertTxError> {
        let (anchor, last_seen) = match position {
            ConfirmationTime::Confirmed { height, time } => {
                // anchor tx to checkpoint with lowest height that is >= position's height
                let anchor = self
                    .chain
                    .range(height..)
                    .last()
                    .ok_or(InsertTxError::ConfirmationHeightCannotBeGreaterThanTip {
                        tip_height: self.chain.tip().height(),
                        tx_height: height,
                    })
                    .map(|anchor_cp| ConfirmationTimeHeightAnchor {
                        anchor_block: anchor_cp.block_id(),
                        confirmation_height: height,
                        confirmation_time: time,
                    })?;

                (Some(anchor), None)
            }
            ConfirmationTime::Unconfirmed { last_seen } => (None, Some(last_seen)),
        };

        let mut changeset = ChangeSet::default();
        let txid = tx.malfix_txid();
        changeset.append(self.indexed_graph.insert_tx(tx).into());
        if let Some(anchor) = anchor {
            changeset.append(self.indexed_graph.insert_anchor(txid, anchor).into());
        }
        if let Some(last_seen) = last_seen {
            changeset.append(self.indexed_graph.insert_seen_at(txid, last_seen).into());
        }

        let changed = !changeset.is_empty();
        self.persist.stage(changeset);
        Ok(changed)
    }

    /// Iterate over the transactions in the wallet.
    pub fn transactions(
        &self,
    ) -> impl Iterator<Item = CanonicalTx<'_, Arc<Transaction>, ConfirmationTimeHeightAnchor>> + '_
    {
        self.indexed_graph
            .graph()
            .list_chain_txs(&self.chain, self.chain.tip().block_id())
    }

    /// Return the balance, separated into available, trusted-pending, untrusted-pending and immature
    /// values.
    pub fn balance(&self, color_id: ColorIdentifier) -> Balance {
        let balances: HashMap<ColorIdentifier, Balance> = self.balances();
        if let Some(balance) = balances.get(&color_id) {
            balance.to_owned()
        } else {
            Balance {
                immature: Amount::ZERO,
                trusted_pending: Amount::ZERO,
                untrusted_pending: Amount::ZERO,
                confirmed: Amount::ZERO,
            }
        }
    }

    /// Return the balances, which key is Color Identifier and value is instance of Balance
    pub fn balances(&self) -> HashMap<ColorIdentifier, Balance> {
        self.indexed_graph.graph().balance(
            &self.chain,
            self.chain.tip().block_id(),
            self.indexed_graph.index.outpoints(),
            |&(k, _), _| k == KeychainKind::Internal,
        )
    }

    /// Add an external signer
    ///
    /// See [the `signer` module](signer) for an example.
    pub fn add_signer(
        &mut self,
        keychain: KeychainKind,
        ordering: SignerOrdering,
        signer: Arc<dyn TransactionSigner>,
    ) {
        let signers = match keychain {
            KeychainKind::External => Arc::make_mut(&mut self.signers),
            KeychainKind::Internal => Arc::make_mut(&mut self.change_signers),
            KeychainKind::PayToContract { .. } => Arc::make_mut(&mut self.signers),
        };

        signers.add_external(signer.id(&self.secp), ordering, signer);
    }

    /// Get the signers
    ///
    /// ## Example
    ///
    /// TODO: fix this example
    /// ```ignore
    /// # use tdk_wallet::{Wallet, KeychainKind};
    /// # use tdk_wallet::tapyrus::Network;
    /// let descriptor = "wpkh(tprv8ZgxMBicQKsPe73PBRSmNbTfbcsZnwWhz5eVmhHpi31HW29Z7mc9B4cWGRQzopNUzZUT391DeDJxL2PefNunWyLgqCKRMDkU1s2s8bAfoSk/84'/1'/0'/0/*)";
    /// let change_descriptor = "wpkh(tprv8ZgxMBicQKsPe73PBRSmNbTfbcsZnwWhz5eVmhHpi31HW29Z7mc9B4cWGRQzopNUzZUT391DeDJxL2PefNunWyLgqCKRMDkU1s2s8bAfoSk/84'/1'/0'/1/*)";
    /// let wallet = Wallet::new_no_persist(descriptor, change_descriptor, Network::Prod)?;
    /// for secret_key in wallet.get_signers(KeychainKind::External).signers().iter().filter_map(|s| s.descriptor_secret_key()) {
    ///     // secret_key: tprv8ZgxMBicQKsPe73PBRSmNbTfbcsZnwWhz5eVmhHpi31HW29Z7mc9B4cWGRQzopNUzZUT391DeDJxL2PefNunWyLgqCKRMDkU1s2s8bAfoSk/84'/0'/0'/0/*
    ///     println!("secret_key: {}", secret_key);
    /// }
    ///
    /// Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_signers(&self, keychain: KeychainKind) -> Arc<SignersContainer> {
        match keychain {
            KeychainKind::External => Arc::clone(&self.signers),
            KeychainKind::Internal => Arc::clone(&self.change_signers),
            KeychainKind::PayToContract { .. } => Arc::clone(&self.signers),
        }
    }

    /// Start building a transaction.
    ///
    /// This returns a blank [`TxBuilder`] from which you can specify the parameters for the transaction.
    ///
    /// ## Example
    ///
    /// TODO: fix this example
    /// ```ignore
    /// # use std::str::FromStr;
    /// # use tapyrus::*;
    /// # use tdk_wallet::*;
    /// # use tdk_wallet::wallet::ChangeSet;
    /// # use tdk_wallet::wallet::error::CreateTxError;
    /// # use tdk_persist::PersistBackend;
    /// # use anyhow::Error;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let mut wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap().assume_checked();
    /// let psbt = {
    ///    let mut builder =  wallet.build_tx();
    ///    builder
    ///        .add_recipient(to_address.script_pubkey(), Amount::from_tap(50_000));
    ///    builder.finish()?
    /// };
    ///
    /// // sign and broadcast ...
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    ///
    /// [`TxBuilder`]: crate::TxBuilder
    pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
        TxBuilder {
            wallet: alloc::rc::Rc::new(core::cell::RefCell::new(self)),
            params: TxParams::default(),
            coin_selection: DefaultCoinSelectionAlgorithm::default(),
        }
    }

    pub(crate) fn create_tx<Cs: coin_selection::CoinSelectionAlgorithm>(
        &mut self,
        coin_selection: Cs,
        params: TxParams,
    ) -> Result<Psbt, CreateTxError> {
        let keychains: BTreeMap<_, _> = self.indexed_graph.index.keychains().collect();
        let external_descriptor = keychains.get(&KeychainKind::External).expect("must exist");
        let internal_descriptor = keychains.get(&KeychainKind::Internal).expect("must exist");

        let external_policy = external_descriptor
            .extract_policy(&self.signers, BuildSatisfaction::None, &self.secp)?
            .unwrap();
        let internal_policy = internal_descriptor
            .extract_policy(&self.change_signers, BuildSatisfaction::None, &self.secp)?
            .unwrap();

        // The policy allows spending external outputs, but it requires a policy path that hasn't been
        // provided
        if params.change_policy != tx_builder::ChangeSpendPolicy::OnlyChange
            && external_policy.requires_path()
            && params.external_policy_path.is_none()
        {
            return Err(CreateTxError::SpendingPolicyRequired(
                KeychainKind::External,
            ));
        };
        // Same for the internal_policy path
        if params.change_policy != tx_builder::ChangeSpendPolicy::ChangeForbidden
            && internal_policy.requires_path()
            && params.internal_policy_path.is_none()
        {
            return Err(CreateTxError::SpendingPolicyRequired(
                KeychainKind::Internal,
            ));
        };

        let external_requirements = external_policy.get_condition(
            params
                .external_policy_path
                .as_ref()
                .unwrap_or(&BTreeMap::new()),
        )?;
        let internal_requirements = internal_policy.get_condition(
            params
                .internal_policy_path
                .as_ref()
                .unwrap_or(&BTreeMap::new()),
        )?;

        let requirements = external_requirements.merge(&internal_requirements)?;

        let version = match params.version {
            Some(tx_builder::Version(0)) => return Err(CreateTxError::Version0),
            Some(tx_builder::Version(1)) if requirements.csv.is_some() => {
                return Err(CreateTxError::Version1Csv)
            }
            Some(tx_builder::Version(x)) => x,
            None if requirements.csv.is_some() => 2,
            None => 1,
        };

        // We use a match here instead of a unwrap_or_else as it's way more readable :)
        let current_height = match params.current_height {
            // If they didn't tell us the current height, we assume it's the latest sync height.
            None => {
                let tip_height = self.chain.tip().height();
                absolute::LockTime::from_height(tip_height).expect("invalid height")
            }
            Some(h) => h,
        };

        let lock_time = match params.locktime {
            // When no nLockTime is specified, we try to prevent fee sniping, if possible
            None => {
                // Fee sniping can be partially prevented by setting the timelock
                // to current_height. If we don't know the current_height,
                // we default to 0.
                let fee_sniping_height = current_height;

                // We choose the biggest between the required nlocktime and the fee sniping
                // height
                match requirements.timelock {
                    // No requirement, just use the fee_sniping_height
                    None => fee_sniping_height,
                    // There's a block-based requirement, but the value is lower than the fee_sniping_height
                    Some(value @ absolute::LockTime::Blocks(_)) if value < fee_sniping_height => {
                        fee_sniping_height
                    }
                    // There's a time-based requirement or a block-based requirement greater
                    // than the fee_sniping_height use that value
                    Some(value) => value,
                }
            }
            // Specific nLockTime required and we have no constraints, so just set to that value
            Some(x) if requirements.timelock.is_none() => x,
            // Specific nLockTime required and it's compatible with the constraints
            Some(x)
                if requirements.timelock.unwrap().is_same_unit(x)
                    && x >= requirements.timelock.unwrap() =>
            {
                x
            }
            // Invalid nLockTime required
            Some(x) => {
                return Err(CreateTxError::LockTime {
                    requested: x,
                    required: requirements.timelock.unwrap(),
                })
            }
        };

        // The nSequence to be by default for inputs unless an explicit sequence is specified.
        let n_sequence = match (params.rbf, requirements.csv) {
            // No RBF or CSV but there's an nLockTime, so the nSequence cannot be final
            (None, None) if lock_time != absolute::LockTime::ZERO => {
                Sequence::ENABLE_LOCKTIME_NO_RBF
            }
            // No RBF, CSV or nLockTime, make the transaction final
            (None, None) => Sequence::MAX,

            // No RBF requested, use the value from CSV. Note that this value is by definition
            // non-final, so even if a timelock is enabled this nSequence is fine, hence why we
            // don't bother checking for it here. The same is true for all the other branches below
            (None, Some(csv)) => csv,

            // RBF with a specific value but that value is too high
            (Some(tx_builder::RbfValue::Value(rbf)), _) if !rbf.is_rbf() => {
                return Err(CreateTxError::RbfSequence)
            }
            // RBF with a specific value requested, but the value is incompatible with CSV
            (Some(tx_builder::RbfValue::Value(rbf)), Some(csv))
                if !check_nsequence_rbf(rbf, csv) =>
            {
                return Err(CreateTxError::RbfSequenceCsv { rbf, csv })
            }

            // RBF enabled with the default value with CSV also enabled. CSV takes precedence
            (Some(tx_builder::RbfValue::Default), Some(csv)) => csv,
            // Valid RBF, either default or with a specific value. We ignore the `CSV` value
            // because we've already checked it before
            (Some(rbf), _) => rbf.get_value(),
        };

        let (fee_rate, mut fee_amount) = match params.fee_policy.unwrap_or_default() {
            //FIXME: see https://github.com/bitcoindevkit/bdk/issues/256
            FeePolicy::FeeAmount(fee) => {
                if let Some(previous_fee) = params.bumping_fee {
                    if fee < previous_fee.absolute {
                        return Err(CreateTxError::FeeTooLow {
                            required: Amount::from_tap(previous_fee.absolute),
                        });
                    }
                }
                (FeeRate::ZERO, fee)
            }
            FeePolicy::FeeRate(rate) => {
                if let Some(previous_fee) = params.bumping_fee {
                    let required_feerate = FeeRate::from_tap_per_kwu(
                        previous_fee.rate.to_tap_per_kwu()
                            + FeeRate::BROADCAST_MIN.to_tap_per_kwu(), // +1 sat/vb
                    );
                    if rate < required_feerate {
                        return Err(CreateTxError::FeeRateTooLow {
                            required: required_feerate,
                        });
                    }
                }
                (rate, 0)
            }
        };

        let mut tx = Transaction {
            version: transaction::Version::non_standard(version),
            lock_time,
            input: vec![],
            output: vec![],
        };

        if params.manually_selected_only && params.utxos.is_empty() {
            return Err(CreateTxError::NoUtxosSelected);
        }

        let mut outgoings: BTreeMap<ColorIdentifier, Amount> = BTreeMap::new();
        outgoings.insert(ColorIdentifier::default(), Amount::from_tap(0));

        let mut received = Amount::ZERO;

        let recipients = params.recipients.iter().map(|(r, v, c)| (r, *v, *c));

        for (index, (script_pubkey, value, color_id)) in recipients.clone().enumerate() {
            if !params.allow_dust
                && value.is_dust(script_pubkey)
                && color_id.is_default()
                && !script_pubkey.is_provably_unspendable()
            {
                return Err(CreateTxError::OutputBelowDustLimit(index));
            }

            if self.is_mine(script_pubkey) {
                received += Amount::from_tap(value);
            }

            let new_out = if color_id.is_colored() {
                TxOut {
                    script_pubkey: script_pubkey.clone().add_color(color_id).unwrap(),
                    value: Amount::from_tap(value),
                }
            } else {
                TxOut {
                    script_pubkey: script_pubkey.clone(),
                    value: Amount::from_tap(value),
                }
            };

            tx.output.push(new_out);

            let mut outgoing = *outgoings.get(&color_id).unwrap_or(&Amount::ZERO);
            outgoing += Amount::from_tap(value);
            outgoings.insert(color_id, outgoing);
        }

        fee_amount += (fee_rate * tx.weight()).to_tap();

        let (required_utxos, optional_utxos) =
            self.preselect_utxos(&params, Some(current_height.to_consensus_u32()));

        // get drain script
        let drain_script = match params.drain_to {
            Some(ref drain_recipient) => drain_recipient.clone(),
            None => {
                let change_keychain = KeychainKind::Internal;
                let ((index, spk), index_changeset) = self
                    .indexed_graph
                    .index
                    .next_unused_spk(&change_keychain)
                    .expect("keychain must exist");
                let spk = spk.into();
                self.indexed_graph.index.mark_used(change_keychain, index);
                self.persist
                    .stage(ChangeSet::from(indexed_tx_graph::ChangeSet::from(
                        index_changeset,
                    )));
                self.persist.commit().map_err(CreateTxError::Persist)?;
                spk
            }
        };

        let (required_utxos, optional_utxos) =
            coin_selection::filter_duplicates(required_utxos, optional_utxos);

        let mut selected_coins: Vec<Utxo> = Vec::new();

        // Reverse the outgoings so that it ends with the default color (TPC)
        for (color_id, outgoing) in outgoings.iter().rev() {
            let target_amount = if color_id.is_default() {
                outgoing.to_tap() + fee_amount
            } else {
                outgoing.to_tap()
            };

            let coin_selection = coin_selection.coin_select(
                required_utxos.clone(),
                optional_utxos.clone(),
                fee_rate,
                target_amount,
                &drain_script,
                color_id,
            )?;

            fee_amount += coin_selection.fee_amount;
            let excess = &coin_selection.excess;

            tx.input.extend(
                coin_selection
                    .selected
                    .iter()
                    .map(|u| tapyrus::TxIn {
                        previous_output: u.outpoint(),
                        script_sig: ScriptBuf::default(),
                        sequence: u.sequence().unwrap_or(n_sequence),
                        witness: Witness::new(),
                    })
                    .collect::<Vec<TxIn>>(),
            );
            selected_coins.extend(coin_selection.selected);

            let output_exists =
                tx.output
                    .iter()
                    .any(|output| match output.script_pubkey.color_id() {
                        None => color_id.is_default(),
                        Some(this_color_id) => this_color_id == *color_id,
                    });

            if !output_exists {
                // Uh oh, our transaction has no outputs.
                // We allow this when:
                // - We have a drain_to address and the utxos we must spend (this happens,
                // for example, when we RBF)
                // - We have a drain_to address and drain_wallet set
                // - We have an output for colored coin sending but we don't have TPC output.(This
                // case we should have TPC inputs and an output for bear fees.)
                // Otherwise, we don't know who we should send the funds to, and how much
                // we should send!

                let utxo_exists = params.utxos.iter().any(|utxo| {
                    match utxo.utxo.txout().script_pubkey.color_id() {
                        None => color_id.is_default(),
                        Some(this_color_id) => this_color_id == *color_id,
                    }
                });

                if (params.drain_to.is_some() && (params.drain_wallet || utxo_exists)) {
                    if let NoChange {
                        dust_threshold,
                        remaining_amount,
                        change_fee,
                    } = excess
                    {
                        let available = if color_id.is_default() {
                            remaining_amount.saturating_sub(*change_fee)
                        } else {
                            *remaining_amount
                        };
                        return Err(CreateTxError::CoinSelection(Error::InsufficientFunds {
                            needed: *dust_threshold,
                            available,
                        }));
                    }
                } else if (color_id.is_default() && outgoings.len() > 1) {
                    // We have colored coin outputs but no TPC output
                } else {
                    return Err(CreateTxError::NoRecipients);
                }
            }

            match excess {
                NoChange {
                    remaining_amount, ..
                } => {
                    if color_id.is_default() {
                        fee_amount += remaining_amount;
                    }
                }
                Change { amount, fee } => {
                    if color_id.is_default() && self.is_mine(&drain_script) {
                        received += Amount::from_tap(*amount);
                    }
                    fee_amount += fee;

                    // create drain output
                    let script = if color_id.is_default() {
                        drain_script.clone()
                    } else {
                        drain_script.add_color(*color_id).unwrap()
                    };
                    let drain_output = TxOut {
                        value: Amount::from_tap(*amount),
                        script_pubkey: script,
                    };

                    // TODO: We should pay attention when adding a new output: this might increase
                    // the length of the "number of vouts" parameter by 2 bytes, potentially making
                    // our feerate too low
                    tx.output.push(drain_output);
                }
            };
        }

        // sort input/outputs according to the chosen algorithm
        params.ordering.sort_tx(&mut tx);

        let psbt = self.complete_transaction(tx, selected_coins, params)?;
        Ok(psbt)
    }

    /// Bump the fee of a transaction previously created with this wallet.
    ///
    /// Returns an error if the transaction is already confirmed or doesn't explicitly signal
    /// *replace by fee* (RBF). If the transaction can be fee bumped then it returns a [`TxBuilder`]
    /// pre-populated with the inputs and outputs of the original transaction.
    ///
    /// ## Example
    ///
    /// ```no_run,ignore
    /// # // TODO: remove norun -- bumping fee seems to need the tx in the wallet database first.
    /// # use std::str::FromStr;
    /// # use tapyrus::*;
    /// # use tdk_wallet::*;
    /// # use tdk_wallet::wallet::ChangeSet;
    /// # use tdk_wallet::wallet::error::CreateTxError;
    /// # use tdk_persist::PersistBackend;
    /// # use anyhow::Error;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let mut wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap().assume_checked();
    /// let mut psbt = {
    ///     let mut builder = wallet.build_tx();
    ///     builder
    ///         .add_recipient(to_address.script_pubkey(), Amount::from_tap(50_000))
    ///         .enable_rbf();
    ///     builder.finish()?
    /// };
    /// let _ = wallet.sign(&mut psbt, SignOptions::default())?;
    /// let tx = psbt.clone().extract_tx().expect("tx");
    /// // broadcast tx but it's taking too long to confirm so we want to bump the fee
    /// let mut psbt =  {
    ///     let mut builder = wallet.build_fee_bump(tx.malfix_txid())?;
    ///     builder
    ///         .fee_rate(FeeRate::from_tap_per_vb(5).expect("valid feerate"));
    ///     builder.finish()?
    /// };
    ///
    /// let _ = wallet.sign(&mut psbt, SignOptions::default())?;
    /// let fee_bumped_tx = psbt.extract_tx();
    /// // broadcast fee_bumped_tx to replace original
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    // TODO: support for merging multiple transactions while bumping the fees
    pub fn build_fee_bump(
        &mut self,
        txid: MalFixTxid,
    ) -> Result<TxBuilder<'_, DefaultCoinSelectionAlgorithm>, BuildFeeBumpError> {
        let graph = self.indexed_graph.graph();
        let txout_index = &self.indexed_graph.index;
        let chain_tip = self.chain.tip().block_id();

        let mut tx = graph
            .get_tx(txid)
            .ok_or(BuildFeeBumpError::TransactionNotFound(txid))?
            .as_ref()
            .clone();

        let pos = graph
            .get_chain_position(&self.chain, chain_tip, txid)
            .ok_or(BuildFeeBumpError::TransactionNotFound(txid))?;
        if let ChainPosition::Confirmed(_) = pos {
            return Err(BuildFeeBumpError::TransactionConfirmed(txid));
        }

        if !tx
            .input
            .iter()
            .any(|txin| txin.sequence.to_consensus_u32() <= 0xFFFFFFFD)
        {
            return Err(BuildFeeBumpError::IrreplaceableTransaction(
                tx.malfix_txid(),
            ));
        }

        let fee = self
            .calculate_fee(&tx)
            .map_err(|_| BuildFeeBumpError::FeeRateUnavailable)?;
        let fee_rate = self
            .calculate_fee_rate(&tx)
            .map_err(|_| BuildFeeBumpError::FeeRateUnavailable)?;

        // remove the inputs from the tx and process them
        let original_txin = tx.input.drain(..).collect::<Vec<_>>();
        let original_utxos = original_txin
            .iter()
            .map(|txin| -> Result<_, BuildFeeBumpError> {
                let prev_tx = graph
                    .get_tx(txin.previous_output.txid)
                    .ok_or(BuildFeeBumpError::UnknownUtxo(txin.previous_output))?;
                let txout = &prev_tx.output[txin.previous_output.vout as usize];

                let confirmation_time: ConfirmationTime = graph
                    .get_chain_position(&self.chain, chain_tip, txin.previous_output.txid)
                    .ok_or(BuildFeeBumpError::UnknownUtxo(txin.previous_output))?
                    .cloned()
                    .into();

                let weighted_utxo = match txout_index.index_of_spk(&txout.script_pubkey) {
                    Some((keychain, derivation_index)) => {
                        let satisfaction_weight = self
                            .get_descriptor_for_keychain(keychain)
                            .max_weight_to_satisfy()
                            .unwrap();
                        WeightedUtxo {
                            utxo: Utxo::Local(LocalOutput {
                                outpoint: txin.previous_output,
                                txout: txout.clone(),
                                keychain,
                                is_spent: true,
                                derivation_index,
                                confirmation_time,
                            }),
                            satisfaction_weight,
                        }
                    }
                    None => {
                        let satisfaction_weight =
                            serialize(&txin.script_sig).len() * 4 + serialize(&txin.witness).len();
                        WeightedUtxo {
                            utxo: Utxo::Foreign {
                                outpoint: txin.previous_output,
                                sequence: Some(txin.sequence),
                                psbt_input: Box::new(psbt::Input {
                                    witness_utxo: Some(txout.clone()),
                                    non_witness_utxo: Some(prev_tx.as_ref().clone()),
                                    ..Default::default()
                                }),
                            },
                            satisfaction_weight,
                        }
                    }
                };

                Ok(weighted_utxo)
            })
            .collect::<Result<Vec<_>, _>>()?;

        if tx.output.len() > 1 {
            let mut change_index = None;
            for (index, txout) in tx.output.iter().enumerate() {
                let change_keychain = KeychainKind::Internal;
                match txout_index.index_of_spk(&txout.script_pubkey) {
                    Some((keychain, _)) if keychain == change_keychain => {
                        change_index = Some(index)
                    }
                    _ => {}
                }
            }

            if let Some(change_index) = change_index {
                tx.output.remove(change_index);
            }
        }

        let params = TxParams {
            // TODO: figure out what rbf option should be?
            version: Some(tx_builder::Version(tx.version.0)),
            recipients: tx
                .output
                .into_iter()
                .map(|txout| {
                    (
                        txout.script_pubkey.clone(),
                        txout.value.to_tap(),
                        txout.script_pubkey.color_id().unwrap_or_default(),
                    )
                })
                .collect(),
            utxos: original_utxos,
            bumping_fee: Some(tx_builder::PreviousFee {
                absolute: fee.to_tap(),
                rate: fee_rate,
            }),
            ..Default::default()
        };

        Ok(TxBuilder {
            wallet: alloc::rc::Rc::new(core::cell::RefCell::new(self)),
            params,
            coin_selection: DefaultCoinSelectionAlgorithm::default(),
        })
    }

    /// Sign a transaction with all the wallet's signers, in the order specified by every signer's
    /// [`SignerOrdering`]. This function returns the `Result` type with an encapsulated `bool` that has the value true if the PSBT was finalized, or false otherwise.
    ///
    /// The [`SignOptions`] can be used to tweak the behavior of the software signers, and the way
    /// the transaction is finalized at the end. Note that it can't be guaranteed that *every*
    /// signers will follow the options, but the "software signers" (WIF keys and `xprv`) defined
    /// in this library will.
    ///
    /// ## Example
    ///
    /// TODO: fix this example
    /// ```ignore
    /// # use std::str::FromStr;
    /// # use tapyrus::*;
    /// # use tdk_wallet::*;
    /// # use tdk_wallet::wallet::ChangeSet;
    /// # use tdk_wallet::wallet::error::CreateTxError;
    /// # use tdk_persist::PersistBackend;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let mut wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap().assume_checked();
    /// let mut psbt = {
    ///     let mut builder = wallet.build_tx();
    ///     builder.add_recipient(to_address.script_pubkey(), Amount::from_tap(50_000));
    ///     builder.finish()?
    /// };
    /// let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    /// assert!(finalized, "we should have signed all the inputs");
    /// # Ok::<(),anyhow::Error>(())
    pub fn sign(&self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<bool, SignerError> {
        // This adds all the PSBT metadata for the inputs, which will help us later figure out how
        // to derive our keys
        self.update_psbt_with_descriptor(psbt)
            .map_err(SignerError::MiniscriptPsbt)?;

        // If we aren't allowed to use `witness_utxo`, ensure that every input (except p2tr and finalized ones)
        // has the `non_witness_utxo`
        if !sign_options.trust_witness_utxo
            && psbt
                .inputs
                .iter()
                .filter(|i| i.final_script_witness.is_none() && i.final_script_sig.is_none())
                .filter(|i| i.tap_internal_key.is_none() && i.tap_merkle_root.is_none())
                .any(|i| i.non_witness_utxo.is_none())
        {
            return Err(SignerError::MissingNonWitnessUtxo);
        }

        // If the user hasn't explicitly opted-in, refuse to sign the transaction unless every input
        // is using `SIGHASH_ALL` or `SIGHASH_DEFAULT` for taproot
        if !sign_options.allow_all_sighashes
            && !psbt.inputs.iter().all(|i| {
                i.sighash_type.is_none()
                    || i.sighash_type == Some(EcdsaSighashType::All.into())
                    || i.sighash_type == Some(TapSighashType::All.into())
                    || i.sighash_type == Some(TapSighashType::Default.into())
            })
        {
            return Err(SignerError::NonStandardSighash);
        }

        /// Add all contracts to sign_options
        let mut sign_options = sign_options.clone();
        sign_options.contracts.append(&mut self.contracts.clone());
        for signer in self
            .signers
            .signers()
            .iter()
            .chain(self.change_signers.signers().iter())
        {
            signer.sign_transaction(psbt, &sign_options, &self.secp)?;
        }

        // attempt to finalize
        if sign_options.try_finalize {
            self.finalize_psbt(psbt, sign_options)
        } else {
            Ok(false)
        }
    }

    /// Return the spending policies for the wallet's descriptor
    pub fn policies(&self, keychain: KeychainKind) -> Result<Option<Policy>, DescriptorError> {
        let signers = match keychain {
            KeychainKind::External => &self.signers,
            KeychainKind::Internal => &self.change_signers,
            KeychainKind::PayToContract { .. } => &self.signers,
        };

        self.public_descriptor(keychain).extract_policy(
            signers,
            BuildSatisfaction::None,
            &self.secp,
        )
    }

    /// Return the "public" version of the wallet's descriptor, meaning a new descriptor that has
    /// the same structure but with every secret key removed
    ///
    /// This can be used to build a watch-only version of a wallet
    pub fn public_descriptor(&self, keychain: KeychainKind) -> &ExtendedDescriptor {
        self.indexed_graph
            .index
            .keychains()
            .find(|(k, _)| *k == &keychain)
            .map(|(_, d)| d)
            .expect("keychain must exist")
    }

    /// Finalize a PSBT, i.e., for each input determine if sufficient data is available to pass
    /// validation and construct the respective `scriptSig` or `scriptWitness`. Please refer to
    /// [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Input_Finalizer)
    /// for further information.
    ///
    /// Returns `true` if the PSBT could be finalized, and `false` otherwise.
    ///
    /// The [`SignOptions`] can be used to tweak the behavior of the finalizer.
    pub fn finalize_psbt(
        &self,
        psbt: &mut Psbt,
        sign_options: SignOptions,
    ) -> Result<bool, SignerError> {
        let chain_tip = self.chain.tip().block_id();

        let tx = &psbt.unsigned_tx;
        let mut finished = true;

        for (n, input) in tx.input.iter().enumerate() {
            let psbt_input = &psbt
                .inputs
                .get(n)
                .ok_or(SignerError::InputIndexOutOfRange)?;
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                continue;
            }
            let confirmation_height = self
                .indexed_graph
                .graph()
                .get_chain_position(&self.chain, chain_tip, input.previous_output.txid)
                .map(|chain_position| match chain_position {
                    ChainPosition::Confirmed(a) => a.confirmation_height,
                    ChainPosition::Unconfirmed(_) => u32::MAX,
                });
            let current_height = sign_options
                .assume_height
                .unwrap_or_else(|| self.chain.tip().height());

            // - Try to derive the descriptor by looking at the txout. If it's in our database, we
            //   know exactly which `keychain` to use, and which derivation index it is
            // - If that fails, try to derive it by looking at the psbt input: the complete logic
            //   is in `src/descriptor/mod.rs`, but it will basically look at `bip32_derivation`,
            //   `redeem_script` and `witness_script` to determine the right derivation
            // - If that also fails, it will try it on the internal descriptor, if present
            let desc = psbt
                .get_utxo_for(n)
                .and_then(|txout| self.get_descriptor_for_txout(&txout))
                .or_else(|| {
                    self.indexed_graph.index.keychains().find_map(|(_, desc)| {
                        desc.derive_from_psbt_input(psbt_input, psbt.get_utxo_for(n), &self.secp)
                    })
                });

            match desc {
                Some(desc) => {
                    let mut tmp_input = tapyrus::TxIn::default();
                    match desc.satisfy(
                        &mut tmp_input,
                        (
                            PsbtInputSatisfier::new(psbt, n),
                            After::new(Some(current_height), false),
                            Older::new(Some(current_height), confirmation_height, false),
                        ),
                    ) {
                        Ok(_) => {
                            let psbt_input = &mut psbt.inputs[n];
                            psbt_input.final_script_sig = Some(tmp_input.script_sig);
                            psbt_input.final_script_witness = Some(tmp_input.witness);
                            if sign_options.remove_partial_sigs {
                                psbt_input.partial_sigs.clear();
                            }
                            if sign_options.remove_taproot_extras {
                                // We just constructed the final witness, clear these fields.
                                psbt_input.tap_key_sig = None;
                                psbt_input.tap_script_sigs.clear();
                                psbt_input.tap_scripts.clear();
                                psbt_input.tap_key_origins.clear();
                                psbt_input.tap_internal_key = None;
                                psbt_input.tap_merkle_root = None;
                            }
                        }
                        Err(_) => finished = false,
                    }
                }
                None => finished = false,
            }
        }

        if finished && sign_options.remove_taproot_extras {
            for output in &mut psbt.outputs {
                output.tap_key_origins.clear();
            }
        }

        Ok(finished)
    }

    /// Return the secp256k1 context used for all signing operations
    pub fn secp_ctx(&self) -> &SecpCtx {
        &self.secp
    }

    /// Returns the descriptor used to create addresses for a particular `keychain`.
    pub fn get_descriptor_for_keychain(&self, keychain: KeychainKind) -> &ExtendedDescriptor {
        self.public_descriptor(keychain)
    }

    /// The derivation index of this wallet. It will return `None` if it has not derived any addresses.
    /// Otherwise, it will return the index of the highest address it has derived.
    pub fn derivation_index(&self, keychain: KeychainKind) -> Option<u32> {
        self.indexed_graph.index.last_revealed_index(&keychain)
    }

    /// The index of the next address that you would get if you were to ask the wallet for a new address
    pub fn next_derivation_index(&self, keychain: KeychainKind) -> u32 {
        self.indexed_graph
            .index
            .next_index(&keychain)
            .expect("keychain must exist")
            .0
    }

    /// Informs the wallet that you no longer intend to broadcast a tx that was built from it.
    ///
    /// This frees up the change address used when creating the tx for use in future transactions.
    // TODO: Make this free up reserved utxos when that's implemented
    pub fn cancel_tx(&mut self, tx: &Transaction) {
        let txout_index = &mut self.indexed_graph.index;
        for txout in &tx.output {
            if let Some((keychain, index)) = txout_index.index_of_spk(&txout.script_pubkey) {
                // NOTE: unmark_used will **not** make something unused if it has actually been used
                // by a tx in the tracker. It only removes the superficial marking.
                txout_index.unmark_used(keychain, index);
            }
        }
    }

    fn get_descriptor_for_txout(&self, txout: &TxOut) -> Option<DerivedDescriptor> {
        let payment_base = self
            .spk_index()
            .p2c_spk(&txout.script_pubkey.remove_color());
        if let Some(p) = payment_base {
            // find pay-to-contract
            let contract = self.contracts.values().find(|c| *p == c.payment_base);
            if let Some(c) = contract {
                let public_key = Contract::create_pay_to_contract_public_key(
                    &c.payment_base,
                    c.contract.clone(),
                    &self.secp_ctx(),
                );

                if let Ok(ddk) = DefiniteDescriptorKey::from_str(
                    &public_key.inner.serialize().to_lower_hex_string(),
                ) {
                    return Some(
                        Descriptor::<DefiniteDescriptorKey>::new_pkh(ddk)
                            .expect("can not create new descriptor"),
                    );
                }
            }
            return None;
        }
        let (keychain, child) = self
            .indexed_graph
            .index
            .index_of_spk(&txout.script_pubkey)?;
        let descriptor: &Descriptor<DescriptorPublicKey> =
            self.get_descriptor_for_keychain(keychain);
        descriptor.at_derivation_index(child).ok()
    }

    pub fn contract_for_utxo(
        &self,
        utxo: &LocalOutput,
    ) -> Result<Option<Contract>, GenerateContractError> {
        let color_id = utxo.txout.script_pubkey.color_id();
        for (_, contract) in self.contracts.iter() {
            let p2c_script = self.create_pay_to_contract_script(
                &contract.payment_base,
                contract.contract.clone(),
                color_id,
            )?;
            if p2c_script == utxo.txout.script_pubkey {
                return Ok(Some(contract.clone()));
            }
        }
        Ok(None)
    }

    fn get_available_utxos(&self) -> Vec<(LocalOutput, usize)> {
        self.list_unspent()
            .filter(|utxo| {
                if let Some(contract) = self.contract_for_utxo(utxo).unwrap_or(None) {
                    contract.spendable
                } else {
                    true
                }
            })
            .map(|utxo| {
                let keychain = utxo.keychain;
                (utxo, {
                    self.get_descriptor_for_keychain(keychain)
                        .max_weight_to_satisfy()
                        .unwrap()
                })
            })
            .collect()
    }

    /// Given the options returns the list of utxos that must be used to form the
    /// transaction and any further that may be used if needed.
    fn preselect_utxos(
        &self,
        params: &TxParams,
        current_height: Option<u32>,
    ) -> (Vec<WeightedUtxo>, Vec<WeightedUtxo>) {
        let TxParams {
            change_policy,
            unspendable,
            utxos,
            drain_wallet,
            manually_selected_only,
            bumping_fee,
            ..
        } = params;

        let manually_selected = utxos.clone();
        // we mandate confirmed transactions if we're bumping the fee
        let must_only_use_confirmed_tx = bumping_fee.is_some();
        let must_use_all_available = *drain_wallet;

        let chain_tip = self.chain.tip().block_id();
        //    must_spend <- manually selected utxos
        //    may_spend  <- all other available utxos
        let mut may_spend = self.get_available_utxos();

        may_spend.retain(|may_spend| {
            !manually_selected
                .iter()
                .any(|manually_selected| manually_selected.utxo.outpoint() == may_spend.0.outpoint)
        });
        let mut must_spend = manually_selected;

        // NOTE: we are intentionally ignoring `unspendable` here. i.e manual
        // selection overrides unspendable.
        if *manually_selected_only {
            return (must_spend, vec![]);
        }

        let satisfies_confirmed = may_spend
            .iter()
            .map(|u| -> bool {
                let txid = u.0.outpoint.txid;
                let tx = match self.indexed_graph.graph().get_tx(txid) {
                    Some(tx) => tx,
                    None => return false,
                };
                let confirmation_time: ConfirmationTime = match self
                    .indexed_graph
                    .graph()
                    .get_chain_position(&self.chain, chain_tip, txid)
                {
                    Some(chain_position) => chain_position.cloned().into(),
                    None => return false,
                };

                // Whether the UTXO is mature and, if needed, confirmed
                let mut spendable = true;
                if must_only_use_confirmed_tx && !confirmation_time.is_confirmed() {
                    return false;
                }
                if tx.is_coinbase() {
                    debug_assert!(
                        confirmation_time.is_confirmed(),
                        "coinbase must always be confirmed"
                    );
                    if let Some(current_height) = current_height {
                        match confirmation_time {
                            ConfirmationTime::Confirmed { height, .. } => {
                                // https://github.com/bitcoin/bitcoin/blob/c5e67be03bb06a5d7885c55db1f016fbf2333fe3/src/validation.cpp#L373-L375
                                spendable &=
                                    (current_height.saturating_sub(height)) >= COINBASE_MATURITY;
                            }
                            ConfirmationTime::Unconfirmed { .. } => spendable = false,
                        }
                    }
                }
                spendable
            })
            .collect::<Vec<_>>();

        let mut i = 0;
        may_spend.retain(|u| {
            let retain = change_policy.is_satisfied_by(&u.0)
                && !unspendable.contains(&u.0.outpoint)
                && satisfies_confirmed[i];
            i += 1;
            retain
        });

        let mut may_spend = may_spend
            .into_iter()
            .map(|(local_utxo, satisfaction_weight)| WeightedUtxo {
                satisfaction_weight,
                utxo: Utxo::Local(local_utxo),
            })
            .collect();

        if must_use_all_available {
            must_spend.append(&mut may_spend);
        }

        (must_spend, may_spend)
    }

    fn complete_transaction(
        &self,
        tx: Transaction,
        selected: Vec<Utxo>,
        params: TxParams,
    ) -> Result<Psbt, CreateTxError> {
        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        if params.add_global_xpubs {
            let all_xpubs = self
                .keychains()
                .flat_map(|(_, desc)| desc.get_extended_keys())
                .collect::<Vec<_>>();

            for xpub in all_xpubs {
                let origin = match xpub.origin {
                    Some(origin) => origin,
                    None if xpub.xkey.depth == 0 => {
                        (xpub.root_fingerprint(&self.secp), vec![].into())
                    }
                    _ => return Err(CreateTxError::MissingKeyOrigin(xpub.xkey.to_string())),
                };

                psbt.xpub.insert(xpub.xkey, origin);
            }
        }

        let mut lookup_output = selected
            .into_iter()
            .map(|utxo| (utxo.outpoint(), utxo))
            .collect::<HashMap<_, _>>();

        // add metadata for the inputs
        for (psbt_input, input) in psbt.inputs.iter_mut().zip(psbt.unsigned_tx.input.iter()) {
            let utxo = match lookup_output.remove(&input.previous_output) {
                Some(utxo) => utxo,
                None => continue,
            };

            match utxo {
                Utxo::Local(utxo) => {
                    *psbt_input =
                        match self.get_psbt_input(utxo, params.sighash, params.only_witness_utxo) {
                            Ok(psbt_input) => psbt_input,
                            Err(e) => match e {
                                CreateTxError::UnknownUtxo => psbt::Input {
                                    sighash_type: params.sighash,
                                    ..psbt::Input::default()
                                },
                                _ => return Err(e),
                            },
                        }
                }
                Utxo::Foreign {
                    outpoint,
                    psbt_input: foreign_psbt_input,
                    ..
                } => {
                    if foreign_psbt_input.non_witness_utxo.is_none() {
                        return Err(CreateTxError::MissingNonWitnessUtxo(outpoint));
                    }
                    *psbt_input = *foreign_psbt_input;
                }
            }
        }

        self.update_psbt_with_descriptor(&mut psbt)?;

        Ok(psbt)
    }

    /// get the corresponding PSBT Input for a LocalUtxo
    pub fn get_psbt_input(
        &self,
        utxo: LocalOutput,
        sighash_type: Option<psbt::PsbtSighashType>,
        _only_witness_utxo: bool,
    ) -> Result<psbt::Input, CreateTxError> {
        // let mut script_pubkey = txo.txout.script_pubkey;
        // Try to find the prev_script in our db to figure out if this is internal or external,
        // and the derivation index
        let script = if utxo.txout.script_pubkey.is_colored() {
            utxo.txout.script_pubkey.remove_color()
        } else {
            utxo.txout.script_pubkey
        };
        let payment_base = self.spk_index().p2c_spk(&script);

        let (keychain, child) = if let Some(p) = payment_base {
            self.indexed_graph
                .index
                .index_of_spk(&ScriptBuf::new_p2pkh(&p.pubkey_hash()))
                .ok_or(CreateTxError::UnknownUtxo)?
        } else {
            self.indexed_graph
                .index
                .index_of_spk(&script)
                .ok_or(CreateTxError::UnknownUtxo)?
        };

        let mut psbt_input = psbt::Input {
            sighash_type,
            ..psbt::Input::default()
        };

        let desc = self.get_descriptor_for_keychain(keychain);
        let derived_descriptor = desc
            .at_derivation_index(child)
            .expect("child can't be hardened");

        psbt_input
            .update_with_descriptor_unchecked(&derived_descriptor)
            .map_err(MiniscriptPsbtError::Conversion)?;

        let prev_output = utxo.outpoint;
        if let Some(prev_tx) = self.indexed_graph.graph().get_tx(prev_output.txid) {
            psbt_input.non_witness_utxo = Some(prev_tx.as_ref().clone());
        }
        Ok(psbt_input)
    }

    fn update_psbt_with_descriptor(&self, psbt: &mut Psbt) -> Result<(), MiniscriptPsbtError> {
        // We need to borrow `psbt` mutably within the loops, so we have to allocate a vec for all
        // the input utxos and outputs
        let utxos = (0..psbt.inputs.len())
            .filter_map(|i| psbt.get_utxo_for(i).map(|utxo| (true, i, utxo)))
            .chain(
                psbt.unsigned_tx
                    .output
                    .iter()
                    .enumerate()
                    .map(|(i, out)| (false, i, out.clone())),
            )
            .collect::<Vec<_>>();

        // Try to figure out the keychain and derivation for every input and output
        for (is_input, index, out) in utxos.into_iter() {
            if let Some((keychain, child)) =
                self.indexed_graph.index.index_of_spk(&out.script_pubkey)
            {
                let desc = self.get_descriptor_for_keychain(keychain);
                let desc = desc
                    .at_derivation_index(child)
                    .expect("child can't be hardened");

                if is_input {
                    psbt.update_input_with_descriptor(index, &desc)
                        .map_err(MiniscriptPsbtError::UtxoUpdate)?;
                } else {
                    psbt.update_output_with_descriptor(index, &desc)
                        .map_err(MiniscriptPsbtError::OutputUpdate)?;
                }
            }
        }

        Ok(())
    }

    /// Return the checksum of the public descriptor associated to `keychain`
    ///
    /// Internally calls [`Self::get_descriptor_for_keychain`] to fetch the right descriptor
    pub fn descriptor_checksum(&self, keychain: KeychainKind) -> String {
        self.get_descriptor_for_keychain(keychain)
            .to_string()
            .split_once('#')
            .unwrap()
            .1
            .to_string()
    }

    /// Applies an update to the wallet and stages the changes (but does not [`commit`] them).
    ///
    /// Usually you create an `update` by interacting with some blockchain data source and inserting
    /// transactions related to your wallet into it.
    ///
    /// [`commit`]: Self::commit
    pub fn apply_update(&mut self, update: impl Into<Update>) -> Result<(), CannotConnectError> {
        let update = update.into();
        let mut changeset = match update.chain {
            Some(chain_update) => ChangeSet::from(self.chain.apply_update(chain_update)?),
            None => ChangeSet::default(),
        };

        let (_, index_changeset) = self
            .indexed_graph
            .index
            .reveal_to_target_multi(&update.last_active_indices);
        changeset.append(ChangeSet::from(indexed_tx_graph::ChangeSet::from(
            index_changeset,
        )));
        changeset.append(ChangeSet::from(
            self.indexed_graph.apply_update(update.graph),
        ));
        self.persist.stage(changeset);
        Ok(())
    }

    /// Commits all currently [`staged`] changed to the persistence backend returning and error when
    /// this fails.
    ///
    /// This returns whether the `update` resulted in any changes.
    ///
    /// [`staged`]: Self::staged
    pub fn commit(&mut self) -> anyhow::Result<bool> {
        self.persist.commit().map(|c| c.is_some())
    }

    /// Returns the changes that will be committed with the next call to [`commit`].
    ///
    /// [`commit`]: Self::commit
    pub fn staged(&self) -> &ChangeSet {
        self.persist.staged()
    }

    /// Get a reference to the inner [`TxGraph`].
    pub fn tx_graph(&self) -> &TxGraph<ConfirmationTimeHeightAnchor> {
        self.indexed_graph.graph()
    }

    /// Get a reference to the inner [`KeychainTxOutIndex`].
    pub fn spk_index(&self) -> &KeychainTxOutIndex<KeychainKind> {
        &self.indexed_graph.index
    }

    fn insert_p2c_spk(&mut self, spk: ScriptBuf, payment_base: PublicKey) {
        self.indexed_graph.index.insert_p2c_spk(spk, payment_base)
    }

    /// Get a reference to the inner [`LocalChain`].
    pub fn local_chain(&self) -> &LocalChain {
        &self.chain
    }

    /// Introduces a `block` of `height` to the wallet, and tries to connect it to the
    /// `prev_blockhash` of the block's header.
    ///
    /// This is a convenience method that is equivalent to calling [`apply_block_connected_to`]
    /// with `prev_blockhash` and `height-1` as the `connected_to` parameter.
    ///
    /// [`apply_block_connected_to`]: Self::apply_block_connected_to
    pub fn apply_block(&mut self, block: &Block, height: u32) -> Result<(), CannotConnectError> {
        let connected_to = match height.checked_sub(1) {
            Some(prev_height) => BlockId {
                height: prev_height,
                hash: block.header.prev_blockhash,
            },
            None => BlockId {
                height,
                hash: block.block_hash(),
            },
        };
        self.apply_block_connected_to(block, height, connected_to)
            .map_err(|err| match err {
                ApplyHeaderError::InconsistentBlocks => {
                    unreachable!("connected_to is derived from the block so must be consistent")
                }
                ApplyHeaderError::CannotConnect(err) => err,
            })
    }

    /// Applies relevant transactions from `block` of `height` to the wallet, and connects the
    /// block to the internal chain.
    ///
    /// The `connected_to` parameter informs the wallet how this block connects to the internal
    /// [`LocalChain`]. Relevant transactions are filtered from the `block` and inserted into the
    /// internal [`TxGraph`].
    pub fn apply_block_connected_to(
        &mut self,
        block: &Block,
        height: u32,
        connected_to: BlockId,
    ) -> Result<(), ApplyHeaderError> {
        let mut changeset = ChangeSet::default();
        changeset.append(
            self.chain
                .apply_header_connected_to(&block.header, height, connected_to)?
                .into(),
        );
        changeset.append(
            self.indexed_graph
                .apply_block_relevant(block, height)
                .into(),
        );
        self.persist.stage(changeset);
        Ok(())
    }

    /// Apply relevant unconfirmed transactions to the wallet.
    ///
    /// Transactions that are not relevant are filtered out.
    ///
    /// This method takes in an iterator of `(tx, last_seen)` where `last_seen` is the timestamp of
    /// when the transaction was last seen in the mempool. This is used for conflict resolution
    /// when there is conflicting unconfirmed transactions. The transaction with the later
    /// `last_seen` is prioritized.
    pub fn apply_unconfirmed_txs<'t>(
        &mut self,
        unconfirmed_txs: impl IntoIterator<Item = (&'t Transaction, u64)>,
    ) {
        let indexed_graph_changeset = self
            .indexed_graph
            .batch_insert_relevant_unconfirmed(unconfirmed_txs);
        self.persist.stage(ChangeSet::from(indexed_graph_changeset));
    }

    /// Return if specified payment base is in wallet.
    fn is_valid_payment_base(&self, payment_base: &PublicKey) -> bool {
        self.indexed_graph
            .index
            .index_of_spk(ScriptBuf::new_p2pkh(&payment_base.pubkey_hash()).as_script())
            .is_some()
    }

    /// Store pay-to-contract information to the wallet.
    pub fn store_contract(
        &mut self,
        contract_id: String,
        contract: Vec<u8>,
        payment_base: PublicKey,
        spendable: bool,
    ) -> Result<Contract, CreateContractError> {
        let mut changeset = ChangeSet::default();
        if let Some(c) = self.contracts.get(&contract_id) {
            return Err(CreateContractError::ContractAlreadyExist { contract_id });
        }

        if !self.is_valid_payment_base(&payment_base) {
            return Err(CreateContractError::InvalidPublicKey {
                public_key: payment_base.clone(),
            });
        }

        let new_contract = {
            let spk = self
                .create_pay_to_contract_script(&payment_base, contract.clone(), None)
                .map_err(|e| CreateContractError::InvalidPublicKey {
                    public_key: payment_base,
                })?;
            self.insert_p2c_spk(spk.clone(), payment_base);
            let new_contract = Contract {
                contract_id: contract_id.clone(),
                contract: contract.clone(),
                payment_base,
                spendable,
            };
            changeset
                .contract
                .insert(contract_id.clone(), new_contract.clone());

            self.contracts
                .insert(contract_id.clone(), new_contract.clone());

            // Insert p2c public key descriptor.
            let p2c_pk = self
                .pay_to_contract_key(&new_contract.payment_base, new_contract.contract.clone())
                .unwrap();
            let keychain_kind = KeychainKind::PayToContract {
                p2c_pk: p2c_pk.clone(),
            };
            let p2c_descriptor = Descriptor::new_pkh(DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::FullKey(p2c_pk),
                origin: None,
            }))
            .unwrap();
            let txout_index_changeset = self
                .indexed_graph
                .index
                .insert_descriptor(keychain_kind, p2c_descriptor);
            let (_, reveal_changeset) = self
                .indexed_graph
                .index
                .reveal_to_target(&keychain_kind, 0)
                .unwrap();
            changeset
                .indexed_tx_graph
                .indexer
                .append(txout_index_changeset);
            changeset.indexed_tx_graph.indexer.append(reveal_changeset);

            self.persist
                .stage_and_commit(changeset)
                .map_err(|e| CreateContractError::Error {
                    reason: e.to_string(),
                })?;
            new_contract
        };
        Ok(new_contract)
    }

    /// Update pay-to-contract information to the wallet.
    ///
    /// A spendable flag is only field to be updated.
    pub fn update_contract(
        &mut self,
        contract_id: String,
        spendable: bool,
    ) -> Result<(), UpdateContractError> {
        let mut changeset = ChangeSet::default();
        if let Some(contract) = self.contracts.get(&contract_id) {
            let new_contract = Contract {
                contract_id: contract_id.clone(),
                contract: contract.contract.clone(),
                payment_base: contract.payment_base,
                spendable,
            };
            changeset
                .contract
                .insert(contract_id.clone(), new_contract.clone());
            self.contracts.insert(contract_id.clone(), new_contract);
            self.persist
                .stage_and_commit(changeset)
                .map_err(|e| UpdateContractError::Error {
                    reason: e.to_string(),
                })?;
        } else {
            return Err(UpdateContractError::ContractNotFound { contract_id });
        }
        Ok(())
    }
}

/// Methods to construct sync/full-scan requests for spk-based chain sources.
impl Wallet {
    /// Create a partial [`SyncRequest`] for this wallet for all revealed spks.
    ///
    /// This is the first step when performing a spk-based wallet partial sync, the returned
    /// [`SyncRequest`] collects all revealed script pubkeys from the wallet keychain needed to
    /// start a blockchain sync with a spk based blockchain client.
    pub fn start_sync_with_revealed_spks(&self) -> SyncRequest {
        SyncRequest::from_chain_tip(self.chain.tip())
            .populate_with_revealed_spks(&self.indexed_graph.index, ..)
    }

    /// Create a [`FullScanRequest] for this wallet.
    ///
    /// This is the first step when performing a spk-based wallet full scan, the returned
    /// [`FullScanRequest] collects iterators for the wallet's keychain script pub keys needed to
    /// start a blockchain full scan with a spk based blockchain client.
    ///
    /// This operation is generally only used when importing or restoring a previously used wallet
    /// in which the list of used scripts is not known.
    pub fn start_full_scan(&self) -> FullScanRequest<KeychainKind> {
        FullScanRequest::from_keychain_txout_index(self.chain.tip(), &self.indexed_graph.index)
    }
}

impl AsRef<tdk_chain::tx_graph::TxGraph<ConfirmationTimeHeightAnchor>> for Wallet {
    fn as_ref(&self) -> &tdk_chain::tx_graph::TxGraph<ConfirmationTimeHeightAnchor> {
        self.indexed_graph.graph()
    }
}

/// Deterministically generate a unique name given the descriptors defining the wallet
///
/// Compatible with [`wallet_name_from_descriptor`]
pub fn wallet_name_from_descriptor<T>(
    descriptor: T,
    change_descriptor: Option<T>,
    network: Network,
    secp: &SecpCtx,
) -> Result<String, DescriptorError>
where
    T: IntoWalletDescriptor,
{
    //TODO check descriptors contains only public keys
    let descriptor = descriptor
        .into_wallet_descriptor(secp, network)?
        .0
        .to_string();
    let mut wallet_name = calc_checksum(&descriptor[..descriptor.find('#').unwrap()])?;
    if let Some(change_descriptor) = change_descriptor {
        let change_descriptor = change_descriptor
            .into_wallet_descriptor(secp, network)?
            .0
            .to_string();
        wallet_name.push_str(
            calc_checksum(&change_descriptor[..change_descriptor.find('#').unwrap()])?.as_str(),
        );
    }

    Ok(wallet_name)
}

fn new_local_utxo(
    keychain: KeychainKind,
    derivation_index: u32,
    full_txo: FullTxOut<ConfirmationTimeHeightAnchor>,
) -> LocalOutput {
    LocalOutput {
        outpoint: full_txo.outpoint,
        txout: full_txo.txout,
        is_spent: full_txo.spent_by.is_some(),
        confirmation_time: full_txo.chain_position.into(),
        keychain,
        derivation_index,
    }
}

fn create_signers<E: IntoWalletDescriptor>(
    index: &mut KeychainTxOutIndex<KeychainKind>,
    secp: &Secp256k1<All>,
    descriptor: E,
    change_descriptor: E,
    network: Network,
) -> Result<(Arc<SignersContainer>, Arc<SignersContainer>), DescriptorError> {
    let descriptor = into_wallet_descriptor_checked(descriptor, secp, network)?;
    let change_descriptor = into_wallet_descriptor_checked(change_descriptor, secp, network)?;
    if descriptor.0 == change_descriptor.0 {
        return Err(DescriptorError::ExternalAndInternalAreTheSame);
    }

    let (descriptor, keymap) = descriptor;
    let signers = Arc::new(SignersContainer::build(keymap, &descriptor, secp));
    let _ = index.insert_descriptor(KeychainKind::External, descriptor);

    let (descriptor, keymap) = change_descriptor;
    let change_signers = Arc::new(SignersContainer::build(keymap, &descriptor, secp));
    let _ = index.insert_descriptor(KeychainKind::Internal, descriptor);

    Ok((signers, change_signers))
}

/// Transforms a [`FeeRate`] to `f64` with unit as sat/vb.
#[macro_export]
#[doc(hidden)]
macro_rules! floating_rate {
    ($rate:expr) => {{
        use $crate::tapyrus::blockdata::constants::WITNESS_SCALE_FACTOR;
        // sat_kwu / 250.0 -> sat_vb
        $rate.to_tap_per_kwu() as f64 / ((1000 / WITNESS_SCALE_FACTOR) as f64)
    }};
}

#[macro_export]
#[doc(hidden)]
/// Macro for getting a wallet for use in a doctest
macro_rules! doctest_wallet {
    () => {{
        use $crate::tapyrus::{BlockHash, Transaction, absolute, TxOut, Network, hashes::Hash};
        use $crate::chain::{ConfirmationTime, BlockId};
        use $crate::{KeychainKind, wallet::Wallet};
        let descriptor = "tr([73c5da0a/86'/0'/0']tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc/0/*)";
        let change_descriptor = "tr([73c5da0a/86'/0'/0']tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc/1/*)";

        let mut wallet = Wallet::new_no_persist(
            descriptor,
            change_descriptor,
            Network::Dev,
        )
        .unwrap();
        let address = wallet.peek_address(KeychainKind::External, 0).address;
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_tap(500_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let _ = wallet.insert_checkpoint(BlockId { height: 1_000, hash: BlockHash::all_zeros() });
        let _ = wallet.insert_tx(tx.clone(), ConfirmationTime::Confirmed {
            height: 500,
            time: 50_000
        });

        wallet
    }}
}
