# BDK TestEnv

This crate sets up a regtest environment with a single [`bitcoind`] node
connected to an [`electrs`] instance. This framework provides the infrastructure
for testing chain source crates, e.g., [`tdk_chain`], [`bdk_electrum`],
[`tdk_esplora`], etc.