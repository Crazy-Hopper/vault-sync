use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::{thread, time};

use glob::Pattern;
use hashicorp_vault::client::{EndpointResponse, HttpVerb, SecretsEngine};
use log::{debug, info, warn};
use serde_json::Value;

use crate::audit;
use crate::config::{get_backends, EngineVersion, VaultSyncConfig};
use crate::vault::VaultClient;

pub fn audit_device_exists(name: &str, client: Arc<Mutex<VaultClient>>) -> bool {
    let client = client.lock().unwrap();
    let name = format!("{}/", name);
    match client.call_endpoint::<Value>(HttpVerb::GET, "sys/audit", None, None) {
        Ok(response) => {
            debug!("GET sys/audit: {:?}", response);
            if let EndpointResponse::VaultResponse(response) = response {
                if let Some(Value::Object(map)) = response.data {
                    for (key, _) in &map {
                        if key == &name {
                            return true;
                        }
                    }
                }
            }
        }
        Err(error) => {
            warn!("GET sys/audit: {}", error);
        }
    }
    false
}

pub fn full_sync_worker(
    config: &VaultSyncConfig,
    client: Arc<Mutex<VaultClient>>,
    tx: mpsc::SyncSender<SecretOp>,
) {
    info!("FullSync worker started");
    let interval = time::Duration::from_secs(config.full_sync_interval);
    let prefix = &config.src.prefix;
    let backends = get_backends(&config.src.backend);
    let ignore = &config.ignore;
    loop {
        full_sync(prefix, &backends, ignore, client.clone(), tx.clone());
        thread::sleep(interval);
    }
}

struct Item {
    parent: String,
    secrets: Option<Vec<String>>,
    index: usize,
}

pub fn full_sync(
    prefix: &str,
    backends: &Vec<String>,
    ignore: &Vec<String>,
    client: Arc<Mutex<VaultClient>>,
    tx: mpsc::SyncSender<SecretOp>,
) {
    let prefix = normalize_prefix(prefix);
    info!("FullSync started");
    let now = time::Instant::now();
    for backend in backends {
        full_sync_internal(&prefix, backend, ignore, client.clone(), tx.clone());
    }
    info!("FullSync finished in {}ms", now.elapsed().as_millis());
}

fn full_sync_internal(
    prefix: &str,
    backend: &str,
    ignore: &Vec<String>,
    client: Arc<Mutex<VaultClient>>,
    tx: mpsc::SyncSender<SecretOp>,
) {
    let mut stack: Vec<Item> = Vec::new();
    let item = Item {
        parent: prefix.to_string(),
        secrets: None,
        index: 0,
    };
    stack.push(item);

    'outer: while stack.len() > 0 {
        let len = stack.len();
        let item = stack.get_mut(len - 1).unwrap();
        if item.secrets.is_none() {
            let secrets = {
                let mut client = client.lock().unwrap();
                client.secret_backend(backend);
                client.list_secrets(&item.parent)
            };
            match secrets {
                Ok(secrets) => {
                    item.secrets = Some(secrets);
                }
                Err(error) => {
                    warn!("Failed to list secrets in {}: {}", &item.parent, error);
                }
            }
        }
        if let Some(secrets) = &item.secrets {
            while item.index < secrets.len() {
                let secret = &secrets[item.index];
                item.index += 1;
                let full_name = format!("{}{}", &item.parent, &secret);
                if is_ignored(ignore, &full_name) {
                    debug!("Ignoring {}", &full_name);
                    continue;
                }
                if secret.ends_with("/") {
                    let item = Item {
                        parent: full_name,
                        secrets: None,
                        index: 0,
                    };
                    stack.push(item);
                    continue 'outer;
                } else {
                    let op = SecretOp::Create(SecretPath {
                        mount: backend.to_string(),
                        path: full_name,
                    });
                    if let Err(error) = tx.send(op) {
                        warn!("Failed to send a secret to a sync thread: {}", error);
                    }
                }
            }
        }
        stack.pop();
    }
    let _ = tx.send(SecretOp::FullSyncFinished);
}

pub fn log_sync(config: &VaultSyncConfig, stream: TcpStream, tx: mpsc::Sender<SecretOp>) {
    match stream.peer_addr() {
        Ok(peer_addr) => {
            info!("New connection from {}", peer_addr);
        }
        Err(_) => {
            info!("New connection");
        }
    }
    let backends = get_backends(&config.src.backend);
    let prefix = &config.src.prefix;
    let version = &config.src.version;

    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(_) => {
                debug!("Log: '{}'", line.trim());
                let audit_log: Result<audit::AuditLog, _> = serde_json::from_str(&line);
                match audit_log {
                    Ok(audit_log) => {
                        if let Some(op) =
                            audit_log_op(&backends, &prefix, &version, &config.ignore, &audit_log)
                        {
                            if let Err(error) = tx.send(op) {
                                warn!("Failed to send a secret to a sync thread: {}", error);
                            }
                        }
                    }
                    Err(error) => {
                        warn!("Failed to deserialize: {}, response: {}", error, &line);
                    }
                }
            }
            Err(error) => {
                warn!("Error: {}", error);
                break;
            }
        }
    }
    debug!("Closed connection");
}

#[derive(Debug)]
pub struct SecretPath {
    mount: String,
    path: String,
}

#[derive(Debug)]
pub enum SecretOp {
    Create(SecretPath),
    Update(SecretPath),
    Delete(SecretPath),
    FullSyncFinished,
}

struct SyncStats {
    updated: u64,
    deleted: u64,
}

impl SyncStats {
    fn new() -> SyncStats {
        SyncStats {
            updated: 0,
            deleted: 0,
        }
    }
    fn reset(&mut self) {
        self.updated = 0;
        self.deleted = 0;
    }
}

pub fn sync_worker(
    audit_rx: mpsc::Receiver<SecretOp>,
    full_rx: mpsc::Receiver<SecretOp>,
    config: &VaultSyncConfig,
    src_client: Arc<Mutex<VaultClient>>,
    dst_client: Arc<Mutex<VaultClient>>,
    dry_run: bool,
    run_once: bool,
) {
    let src_prefix = normalize_prefix(&config.src.prefix);
    let dst_prefix = normalize_prefix(&config.dst.prefix);
    let src_mounts = get_backends(&config.src.backend);
    let dst_mounts = get_backends(&config.dst.backend);
    let mount_map: HashMap<&str, &str> = src_mounts
        .iter()
        .map(|s| s.as_str())
        .zip(dst_mounts.iter().map(|s| s.as_str()))
        .collect();

    info!("Sync worker started");
    let mut stats = SyncStats::new();

    loop {
        // 1. Always prioritize the Audit log (Fast Lane)
        while let Ok(op) = audit_rx.try_recv() {
            if process_op(
                op,
                &src_prefix,
                &dst_prefix,
                &mount_map,
                &src_client,
                &dst_client,
                dry_run,
                &mut stats,
            ) {
                if run_once {
                    return;
                }
            }
        }

        // 2. Otherwise wait for a FullSync operation or a new Audit event
        // We use recv_timeout so we can periodically check the Audit lane again
        if let Ok(op) = full_rx.recv_timeout(time::Duration::from_millis(100)) {
            if process_op(
                op,
                &src_prefix,
                &dst_prefix,
                &mount_map,
                &src_client,
                &dst_client,
                dry_run,
                &mut stats,
            ) {
                if run_once {
                    return;
                }
            }
        }
    }
}

// Returns true if processing should stop (FullSyncFinished in run_once mode)
fn process_op(
    op: SecretOp,
    src_prefix: &str,
    dst_prefix: &str,
    mount_map: &HashMap<&str, &str>,
    src_client: &Arc<Mutex<VaultClient>>,
    dst_client: &Arc<Mutex<VaultClient>>,
    dry_run: bool,
    stats: &mut SyncStats,
) -> bool {
    match op {
        SecretOp::Update(path) | SecretOp::Create(path) => {
            let src_path = &path.path;
            let dst_path = secret_src_to_dst_path(src_prefix, dst_prefix, src_path);

            let (src_engine, dst_engine) = {
                let mut src = src_client.lock().unwrap();
                src.secret_backend(&path.mount);
                let mut dst = dst_client.lock().unwrap();
                dst.secret_backend(mount_map[path.mount.as_str()]);
                (src.get_secrets_engine(), dst.get_secrets_engine())
            };

            if src_engine == hashicorp_vault::client::SecretsEngine::KVV2
                && dst_engine == hashicorp_vault::client::SecretsEngine::KVV2
            {
                // KV v2 to KV v2: Replicate all versions
                let src_metadata = {
                    let client = src_client.lock().unwrap();
                    client.get_secret_metadata(src_path)
                };

                if let Err(error) = src_metadata {
                    warn!("Failed to get source metadata for {}: {}", &src_path, error);
                    return false;
                }
                let src_metadata = src_metadata.unwrap();

                let dst_metadata = {
                    let client = dst_client.lock().unwrap();
                    client.get_secret_metadata(&dst_path)
                };

                let (mut dst_current_version, mut dst_versions) = match dst_metadata {
                    Ok(meta) => (meta.current_version, meta.versions),
                    Err(_) => (0, HashMap::new()),
                };

                // Check if any historical version needs a full reset (e.g. was undeleted on source with different content)
                let mut needs_full_reset = false;
                for v in 1..=dst_current_version {
                    let v_str = v.to_string();
                    let src_v_meta = src_metadata.versions.get(&v_str);
                    let dst_v_meta = dst_versions.get(&v_str);
                    if let (Some(src), Some(dst)) = (src_v_meta, dst_v_meta) {
                        if src.deletion_time.is_empty() && !dst.deletion_time.is_empty() {
                            // Source is Live, Destination is Deleted
                            info!(
                                "Version {} of secret {} was undeleted on source. Checking contents...",
                                v, &dst_path
                            );
                            if !dry_run {
                                let client_dst = dst_client.lock().unwrap();
                                let _ = client_dst.undelete_secret_versions(&dst_path, vec![v]);

                                let src_secret: Result<Value, _> = {
                                    let client_src = src_client.lock().unwrap();
                                    client_src.get_custom_secret_version(src_path, v)
                                };
                                let dst_secret: Result<Value, _> =
                                    client_dst.get_custom_secret_version(&dst_path, v);

                                match (src_secret, dst_secret) {
                                    (Ok(s), Ok(d)) => {
                                        if s != d {
                                            info!(
                                                "Version {} contents differ. Full reset required.",
                                                v
                                            );
                                            needs_full_reset = true;
                                            break;
                                        } else {
                                            info!(
                                                "Version {} contents match. Resumed version without reset.",
                                                v
                                            );
                                        }
                                    }
                                    _ => {
                                        info!("Could not compare version {} contents. Full reset required.", v);
                                        needs_full_reset = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if needs_full_reset {
                    info!("Secret {} has versions that were undeleted on source. Destroying and re-syncing all versions.", &dst_path);
                    if !dry_run {
                        let client = dst_client.lock().unwrap();
                        let _ = client.delete_secret_metadata(&dst_path);
                    }
                    dst_current_version = 0;
                    dst_versions = HashMap::new();
                }

                for v in 1..=(src_metadata.current_version) {
                    let v_str = v.to_string();
                    let src_v_meta = src_metadata.versions.get(&v_str);
                    let dst_v_meta = dst_versions.get(&v_str);

                    if v > dst_current_version {
                        // New version: Catch up
                        if v < src_metadata.oldest_version
                            || src_v_meta.map_or(true, |m| m.destroyed)
                        {
                            // Version is purged (v < oldest) or destroyed on source
                            info!(
                                "Creating and destroying placeholder for version {} of secret {}",
                                v, &dst_path
                            );
                            if !dry_run {
                                let dummy = HashMap::<String, String>::new();
                                let client = dst_client.lock().unwrap();
                                // Create a new version (will be 'v' if numbers align)
                                let _ = client.set_custom_secret(&dst_path, &dummy);
                                // Immediately destroy it to mark it as purged/destroyed
                                let _ = client.destroy_secret_versions(&dst_path, vec![v]);
                            }
                        } else {
                            let src_v_meta = src_v_meta.unwrap();
                            if !src_v_meta.deletion_time.is_empty() {
                                info!("Deleting version {} of secret {}", v, &dst_path);
                                if !dry_run {
                                    let dummy = HashMap::<String, String>::new();
                                    let client = dst_client.lock().unwrap();
                                    let _ = client.set_custom_secret(&dst_path, &dummy);
                                    let _ = client.delete_secret_versions(&dst_path, vec![v]);
                                }
                            } else {
                                let src_secret: Result<Value, _> = {
                                    let client = src_client.lock().unwrap();
                                    client.get_custom_secret_version(src_path, v)
                                };

                                if let Err(error) = src_secret {
                                    warn!(
                                        "Failed to get secret {} version {}: {}",
                                        &src_path, v, error
                                    );
                                    continue;
                                }
                                let src_secret = src_secret.unwrap();

                                info!("Replicating version {} of secret {}", v, &dst_path);
                                if !dry_run {
                                    let client = dst_client.lock().unwrap();
                                    let result = client.set_custom_secret(&dst_path, &src_secret);
                                    if let Err(error) = result {
                                        warn!(
                                            "Failed to set secret {} version {}: {}",
                                            &dst_path, v, error
                                        );
                                    } else {
                                        stats.updated += 1;
                                    }
                                }
                            }
                        }
                    } else if let (Some(src), Some(dst)) = (src_v_meta, dst_v_meta) {
                        // Existing version: Sync state changes (only destroy and delete, undelete is handled by reset above)
                        if src.destroyed && !dst.destroyed {
                            info!(
                                "Destroying historical version {} of secret {}",
                                v, &dst_path
                            );
                            if !dry_run {
                                let client = dst_client.lock().unwrap();
                                let _ = client.destroy_secret_versions(&dst_path, vec![v]);
                            }
                        } else if !src.deletion_time.is_empty() && dst.deletion_time.is_empty() {
                            info!("Deleting historical version {} of secret {}", v, &dst_path);
                            if !dry_run {
                                let client = dst_client.lock().unwrap();
                                let _ = client.delete_secret_versions(&dst_path, vec![v]);
                            }
                        }
                    }
                }
            } else {
                // Standard sync for KV v1 or mixed engines
                let src_secret: Result<Value, _> = {
                    let mut client = src_client.lock().unwrap();
                    client.secret_backend(&path.mount);
                    client.get_custom_secret(src_path)
                };
                let dst_secret: Result<Value, _> = {
                    let mut client = dst_client.lock().unwrap();
                    client.secret_backend(mount_map[path.mount.as_str()]);
                    client.get_custom_secret(&dst_path)
                };
                if let Err(error) = src_secret {
                    warn!("Failed to get secret {}: {}", src_path, error);
                    return false;
                }
                let src_secret = src_secret.unwrap();
                if let Ok(dst_secret) = dst_secret {
                    if dst_secret == src_secret {
                        return false;
                    }
                }
                info!("Creating/updating secret {}", &dst_path);
                if !dry_run {
                    let result = {
                        let client = dst_client.lock().unwrap();
                        client.set_custom_secret(&dst_path, &src_secret)
                    };
                    if let Err(error) = result {
                        warn!("Failed to set secret {}: {}", &dst_path, error);
                    } else {
                        stats.updated += 1;
                    }
                }
            }
        }
        SecretOp::Delete(path) => {
            let secret = secret_src_to_dst_path(src_prefix, dst_prefix, &path.path);
            if !dry_run {
                let mut client = dst_client.lock().unwrap();
                client.secret_backend(mount_map[path.mount.as_str()]);
                let engine = client.get_secrets_engine();
                if engine == SecretsEngine::KVV2 {
                    info!("Deleting secret metadata (permanent) {}", &secret);
                    let _ = client.delete_secret_metadata(&secret);
                } else {
                    info!("Deleting secret {}", &secret);
                    let _ = client.delete_secret(&secret);
                }
            } else {
                info!("Deleting secret (dry-run) {}", &secret);
                stats.deleted += 1;
            }
        }
        SecretOp::FullSyncFinished => {
            info!(
                "FullSync processing finished. Secrets created/updated: {}, deleted: {}",
                &stats.updated, &stats.deleted
            );
            stats.reset();
            return true;
        }
    }
    false
}

// Convert AuditLog to SecretOp
fn audit_log_op(
    mounts: &Vec<String>,
    prefix: &str,
    version: &EngineVersion,
    ignore: &Vec<String>,
    log: &audit::AuditLog,
) -> Option<SecretOp> {
    if log.log_type != "response" {
        return None;
    }
    if log.request.mount_type.is_none() {
        return None;
    }
    if log.request.mount_type != Some("kv".to_string()) {
        return None;
    }

    let operation = log.request.operation.clone();
    if operation != "create"
        && operation != "update"
        && operation != "delete"
        && operation != "destroy"
        && operation != "undelete"
    {
        return None;
    }

    let path = match version {
        EngineVersion::V1 => secret_path_v1(&log.request.path),
        EngineVersion::V2 => secret_path_v2(&log.request.path),
    };
    if let Some(path) = path {
        if !mounts.contains(&path.0) {
            return None;
        }
        if !path.1.starts_with(prefix) {
            return None;
        }
        if is_ignored(ignore, &path.1) {
            debug!("Ignoring secret from audit log: {}", &path.1);
            return None;
        }
        debug!(
            "Received audit log for {} {}",
            &operation, &log.request.path
        );

        // For KV v2, we map most operations to Update to trigger a refresh of all versions.
        // The only exception is a permanent delete via the metadata endpoint.
        if *version == EngineVersion::V2 {
            if log.request.path.contains("/metadata/") && operation == "delete" {
                return Some(SecretOp::Delete(SecretPath {
                    mount: path.0,
                    path: path.1,
                }));
            }
            return Some(SecretOp::Update(SecretPath {
                mount: path.0,
                path: path.1,
            }));
        }

        // KV v1 logic
        if operation == "delete" {
            return Some(SecretOp::Delete(SecretPath {
                mount: path.0,
                path: path.1,
            }));
        } else {
            return Some(SecretOp::Update(SecretPath {
                mount: path.0,
                path: path.1,
            }));
        }
    }

    None
}

// Convert Vault path to a secret path for KV v1
// Example: "secret/path/to/secret" -> "secret", "path/to/secret"
fn secret_path_v1(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split("/").collect();
    if parts.len() < 2 {
        return None;
    }
    Some((parts[0].to_string(), parts[1..].join("/")))
}

// Convert Vault path to a secret path for KV v2
// Example: "secret/data/path/to/secret" -> "secret", "path/to/secret"
fn secret_path_v2(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split("/").collect();
    if parts.len() < 3 {
        return None;
    }
    match parts[1] {
        "data" | "metadata" | "destroy" | "delete" | "undelete" => {
            Some((parts[0].to_string(), parts[2..].join("/")))
        }
        _ => None,
    }
}

fn normalize_prefix(prefix: &str) -> String {
    if prefix.len() == 0 {
        return "".to_string();
    }
    if prefix.ends_with("/") {
        prefix.to_string()
    } else {
        format!("{}/", prefix)
    }
}

// Convert source secret path to destination secret path. Prefixes must be normalized!
// Example: "src/secret1" -> "dst/secret2"
fn secret_src_to_dst_path(src_prefix: &str, dst_prefix: &str, path: &str) -> String {
    let mut path = path.to_string();
    if src_prefix.len() > 0 {
        path = path.trim_start_matches(src_prefix).to_string();
    }
    format!("{}{}", dst_prefix, &path)
}

fn is_ignored(ignore: &Vec<String>, path: &str) -> bool {
    for pattern in ignore {
        if let Ok(glob) = Pattern::new(pattern) {
            if glob.matches(path) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::sync::{
        is_ignored, normalize_prefix, secret_path_v1, secret_path_v2, secret_src_to_dst_path,
    };

    #[test]
    fn test_is_ignored() {
        let ignore = vec!["secret/foo/*".to_string(), "secret/bar".to_string()];
        assert_eq!(is_ignored(&ignore, "secret/foo/bar"), true);
        assert_eq!(is_ignored(&ignore, "secret/foo/baz"), true);
        assert_eq!(is_ignored(&ignore, "secret/bar"), true);
        assert_eq!(is_ignored(&ignore, "secret/qux"), false);
        assert_eq!(is_ignored(&ignore, "secret/foo"), false);
    }

    #[test]
    fn test_secret_path_v1_matches() {
        let path = "secret/path/to/secret";
        let path = secret_path_v1(&path).unwrap();
        assert_eq!(path.0, "secret");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_custom_secret_path_v1_matches() {
        let path = "custom/path/to/secret";
        let path = secret_path_v1(&path).unwrap();
        assert_eq!(path.0, "custom");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_secret_path_v1_not_matches() {
        let path = "secret";
        let path = secret_path_v1(&path);
        assert_eq!(path.is_none(), true);
    }

    #[test]
    fn test_secret_path_v2_matches() {
        let prefixes = vec!["data", "metadata", "destroy", "delete", "undelete"];
        for prefix in prefixes {
            let path = format!("secret/{}/path/to/secret", prefix);
            let parsed = secret_path_v2(&path).unwrap();
            assert_eq!(parsed.0, "secret");
            assert_eq!(parsed.1, "path/to/secret");
        }
    }

    #[test]
    fn test_custom_secret_path_v2_matches() {
        let path = "custom/data/path/to/secret";
        let path = secret_path_v2(&path).unwrap();
        assert_eq!(path.0, "custom");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_secret_path_v2_not_matches() {
        let path = "secret/invalid/path/to/secret";
        let path = secret_path_v2(&path);
        assert_eq!(path.is_none(), true);
    }

    #[test]
    fn test_normalize_prefix() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("src"), "src/");
        assert_eq!(normalize_prefix("src/"), "src/");
    }

    #[test]
    fn test_secret_src_to_dst_path() {
        assert_eq!(
            secret_src_to_dst_path("src/", "dst/", "src/secret"),
            "dst/secret"
        );
        assert_eq!(
            secret_src_to_dst_path("", "dst/", "src/secret"),
            "dst/src/secret"
        );
        assert_eq!(secret_src_to_dst_path("", "", "src/secret"), "src/secret");
    }
}
