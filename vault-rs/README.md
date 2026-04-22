This directory contains a fork of https://github.com/ChrisMacNaughton/vault-rs.

This fork provides comprehensive support for both KV v1 and KV v2 secrets engines, including:
* Full metadata retrieval for version history tracking.
* Versioned read operations to fetch specific historical data.
* Full state management: soft-delete, undelete, and permanent destruction of specific versions or entire secrets.
* Cross-architecture support using `rustls` for easier compilation.

PR to the upstream project to follow.
