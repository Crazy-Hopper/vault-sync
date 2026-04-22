# vault-sync

> **DISCLAIMER:** This fork has been updated exclusively by an **AI Agent**. The author has no formal knowledge of Rust. While the tool has been tested and verified for specific use cases, serious care and thorough testing should be taken before using it in production environments.

A tool to replicate secrets from one HashiCorp Vault or OpenBao instance to another.

## How it works

When vault-sync starts, it performs a full copy of the secrets from the source Vault instance to the destination Vault instance.

### KV v2 Full History & State Mirroring
For KV secrets engine v2, it replicates the **entire version history**, preserving exact version numbers and matching states (live, deleted, or destroyed). 
*   **Version Alignment (Gap-Filling)**: If the source history is truncated (e.g., versions 1-20 are purged), the tool automatically creates "destroyed placeholders" on the destination to ensure that version numbers match perfectly (e.g., both will have versions 21-30).
*   **Self-Healing**: If a version was previously replicated as a placeholder (due to being deleted on source) and is later undeleted on the source with different content, the tool identifies the mismatch and re-syncs the secret metadata and history from scratch.

### Real-Time Updates
You can manually enable the [Socket Audit Device](https://www.vaultproject.io/docs/audit/socket) for the source Vault to stream audit logs to vault-sync. 
*   **Priority Processing (Fast Lane / Slow Lane)**: To ensure "nearly instant" replication, the tool uses a dual-channel architecture. Audit log events (Fast Lane) always "cut the line" and are processed immediately, even if a background full synchronization is actively checking thousands of secrets (Slow Lane).
*   **State Mirroring**: Real-time updates include replication of `delete`, `undelete`, and `destroy` operations.

Note that vault-sync does not create or delete the audit devices by itself.

It is possible to use the same Vault instance as the source and the destination.
You need to specify different prefixes (`src.prefix` and `dst.prefix`) in the configuration file to make sure the source and the destination do not overlap.

## Filtering

You can specify a list of path patterns to ignore during synchronization using the `ignore` block in the configuration file.
Patterns support standard glob syntax (e.g., `test/*`, `secret/**/tmp_*`).
Ignored paths will be skipped during both the initial full sync and real-time updates via the audit device.

## Limitations

* Only two Vault auth methods are supported: [Token](https://www.vaultproject.io/docs/auth/token) and [AppRole](https://www.vaultproject.io/docs/auth/approle)
* For KV v2, replicating a soft-deleted version from the source results in a placeholder in the destination (since deleted data is unreadable).
* **Special Characters**: Most special characters in secret names (including `?`, `%`, `#`, `№`) are supported via robust segment-based URL encoding.

## Configuration

Use the [example](vault-sync.example.yaml) to create your own configuration file.

### Logging
The log level can be dynamically set using the `RUST_LOG` environment variable (e.g., `RUST_LOG=debug`). It defaults to `info`.

### Environment Variables
Instead of specifying secrets in the configuration file, you can use:
* For Token auth method: `VAULT_SYNC_SRC_TOKEN`, `VAULT_SYNC_DST_TOKEN`
* For AppRole auth method: `VAULT_SYNC_SRC_ROLE_ID`, `VAULT_SYNC_SRC_SECRET_ID`, `VAULT_SYNC_DST_ROLE_ID`, `VAULT_SYNC_DST_SECRET_ID`

### Source Vault

A token or AppRole for the source Vault should have a policy that allows listing and reading secrets:

For [KV secrets engine v1](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1):
```shell
cat <<EOF | vault policy write vault-sync-src -
path "secret/*" {
  capabilities = ["read", "list"]
}
EOF
```

For [KV secrets engine v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2):
```shell
cat <<EOF | vault policy write vault-sync-src -
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
EOF
```

Enabling audit log:
```shell
# Create a failsafe audit device
vault audit enable -path stdout file file_path=stdout

# Create the socket audit device for vault-sync
vault audit enable -path vault-sync socket socket_type=tcp address=vault-sync:8202
```

### Destination Vault

For [KV secrets engine v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2):
```shell
cat <<EOF | vault policy write vault-sync-dst -
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOF
```

## Running

```shell
vault-sync --config vault-sync.yaml
```

Command line options:

* `--dry-run`: Shows proposed changes without applying them.
* `--once`: Runs a full sync once and then exits. In this mode, port binding and audit workers are disabled.
* `--no-full-sync`: Disables the periodic background full synchronization. The tool will rely solely on initial sync and real-time audit events.

## Installation

### From source code

```shell
cargo build --release
```

### Docker

Build the image locally:

```shell
docker build -t vault-sync:latest -f docker/Dockerfile .
```

For cross-platform builds (e.g., building `amd64` on Apple Silicon), use the cross-compilation Dockerfile:

```shell
docker build -t vault-sync:latest -f docker/Dockerfile.cross .
```

Run the container:

```shell
docker run -it -v $PWD:/vault-sync vault-sync:latest \
  vault-sync --config /vault-sync/vault-sync.yaml
```

### Helm chart
See `install/helm/vault-sync` for the chart.
