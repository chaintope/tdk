# BDK SQLite

This is a simple [SQLite] relational database schema backed implementation of [`PersistBackend`](tdk_persist::PersistBackend).

The main structure is `Store` which persists [`tdk_persist`] `CombinedChangeSet` data into a SQLite database file.

[`tdk_persist`]:https://docs.rs/tdk_persist/latest/tdk_persist/
[SQLite]: https://www.sqlite.org/index.html
