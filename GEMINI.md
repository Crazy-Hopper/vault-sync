# GEMINI.md - vault-sync

## Project Overview
`vault-sync` is a Rust-based CLI tool and service designed to replicate secrets from one HashiCorp Vault or OpenBao instance to another. 
It supports initial full copies, periodic reconciliation, and real-time updates by listening to Vault's Socket Audit Device.
The project is split into a main application crate (`vault-sync`) and a dependent Rust client crate for Vault (`vault-rs`).

## Architecture
The project maintains a strict separation between the low-level Vault API client and the application-specific synchronization logic:

### `vault-rs/` (The Library)
A general-purpose HashiCorp Vault API client (forked and modified).
- **Low-level API:** Implements HTTP requests to Vault endpoints (including `/metadata`, `/delete`, `/undelete`, `/destroy`).
- **Granular Encoding**: Implements segment-based URL encoding to safely handle special characters (e.g., `?`, `%`) in secret names while preserving query parameters and structural slashes.
- **Generic Types:** Defines standard Vault types (`VaultResponse`, `SecretMetadata`, etc.), including the `oldest_version` field for KV v2 history tracking.
- **Protocol Logic:** Handles protocol-level differences between KV versions.
- **TLS:** Switched to `rustls` to support seamless cross-compilation without system dependencies.

### `src/` (The Application)
Business logic for the synchronization tool, utilizing `vault-rs`.
- **Orchestration (`main.rs`):** 
    - Manages priority-based communication channels.
    - **Fast Lane**: Unbounded channel for immediate processing of real-time Audit Log events.
    - **Slow Lane**: Bounded sync channel for background Full Sync operations to prevent memory saturation.
- **Sync Logic (`sync.rs`):** 
    - **KV v2 Full Versioning:** Replicates entire secret histories sequentially, matching version numbers exactly.
    - **Gap Filling**: Uses `oldest_version` metadata to create and destroy placeholders for purged source versions, ensuring destination version numbers align perfectly with source.
    - **State Mirroring:** Synchronizes historical `delete`, `undelete`, and `destroy` actions.
    - **Self-Healing:** Automatically identifies versions that were previously replicated as placeholders (due to being deleted on source) and re-syncs them from scratch if they are undeleted on the source with different content.
    - **Path Filtering:** Supports an `ignore` block with glob patterns to skip specific secret paths during sync and audit processing.
- **Audit Handling (`audit.rs`):** Defines the structure for Socket Audit Device logs and filters for significant KV operations (create, update, delete).

**Key Technologies:**
- **Language:** Rust (Cargo, standard `src/` layout)
- **External Systems:** HashiCorp Vault, Kubernetes, Docker, Helm
- **Authentication:** Token and AppRole Vault Auth Methods

## Building and Running

**Building from source:**
```shell
cargo build --release
```

**Docker (amd64 from arm64 host):**
```shell
docker build -t vault-sync:latest -f docker/Dockerfile.cross .
```

**Running the CLI:**
```shell
vault-sync --config vault-sync.yaml
```

**Testing:**
Integration tests are provided via bash scripts:
```shell
./scripts/test-sync.sh
./scripts/test-helm.sh
```

## Development Conventions
- **Rust Standards:** Standard `cargo` conventions. `rustls` is the default TLS provider.
- **Configuration:** YAML or environment variables.
- **Secret Replication:** Supports KV v1 (latest version) and KV v2 (full history and state mirroring).
- **Testing Scripts:** Verification should be performed using the provided bash integration scripts.
