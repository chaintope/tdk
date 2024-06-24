# BDK File Store

This is a simple append-only flat file implementation of [`PersistBackend`](tdk_persist::PersistBackend).

The main structure is [`Store`] which works with any [`tdk_chain`] based changesets to persist data into a flat file.

[`tdk_chain`]:https://docs.rs/tdk_chain/latest/tdk_chain/
