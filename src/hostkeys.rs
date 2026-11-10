//! SSH host key verification against OpenSSH-format `known_hosts` files.
//!
//! Two sources: the application's own `known_hosts` (read/write, where accepted
//! keys are appended) and the user's `~/.ssh/known_hosts` (read-only). A key
//! that is present in either is trusted; a *different* key for the same host in
//! either is a hard failure — never silently accepted.
//!
//! ⚠ "Different" includes a different key *type*. russh's own check only
//! calls a mismatch a change when the algorithms agree, and reports a host
//! with an ed25519 key on file, offered an RSA one, as merely unknown. With a
//! trust-on-first-use policy that is a silent bypass: whoever sits in the
//! path offers only RSA, the new key is learned, and the password follows.
//! So a host with any entry on file is never `Unknown` here.
//!
//! Trust on first use lives here: `check` reports `Unknown` and it is the
//! caller's job to ask someone, then call `learn`. This module never prompts,
//! which is what lets it be shared between applications with different UIs.

use anyhow::{Context, Result};
use russh::keys::{HashAlg, PublicKey};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Known,
    Unknown,
    /// A key for this host is on file but it is not this key.
    Changed { file: PathBuf, line: usize },
}

pub struct HostKeys {
    own: PathBuf,
    user: Option<PathBuf>,
    /// Written into the header comment of a freshly created file, so someone
    /// reading it knows which application put it there.
    label: String,
}

impl HostKeys {
    pub fn new(data_dir: &Path, label: &str) -> Self {
        Self {
            own: data_dir.join("known_hosts"),
            user: dirs::home_dir().map(|h| h.join(".ssh").join("known_hosts")),
            label: label.to_string(),
        }
    }

    /// For tests and unusual layouts: explicit file paths.
    pub fn with_paths(own: PathBuf, user: Option<PathBuf>) -> Self {
        Self { own, user, label: "charon-ssh".to_string() }
    }

    /// Set the label written into the header of a newly created known_hosts
    /// file (`with_paths` defaults it to "charon-ssh"), so a file one
    /// application created doesn't claim to belong to another.
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = label.to_string();
        self
    }

    pub fn own_path(&self) -> &Path {
        &self.own
    }

    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> Verdict {
        let sources = std::iter::once(&self.own).chain(self.user.iter());
        let mut known = false;
        // The first entry on file for this host, of whatever type, if the key
        // turns out to match none of them.
        let mut other: Option<(PathBuf, usize)> = None;
        for file in sources {
            match russh::keys::check_known_hosts_path(host, port, key, file) {
                Ok(true) => known = true,
                Ok(false) => {
                    if other.is_none() {
                        if let Ok(entries) =
                            russh::keys::known_hosts::known_host_keys_path(host, port, file)
                        {
                            if let Some((line, _)) = entries.first() {
                                other = Some((file.clone(), real_line(file, *line)));
                            }
                        }
                    }
                }
                Err(russh::keys::Error::KeyChanged { line }) => {
                    return Verdict::Changed { file: file.clone(), line: real_line(file, line) };
                }
                // Unparseable entry (e.g. a key type russh doesn't know) → treat the
                // file as silent on this host rather than blocking the connection.
                Err(e) => tracing::warn!(file = %file.display(), "known_hosts unreadable: {e}"),
            }
        }
        match (known, other) {
            (true, _) => Verdict::Known,
            // A key of another type is on file and this one is not: a change,
            // not a first meeting. See the module docs.
            (false, Some((file, line))) => Verdict::Changed { file, line },
            (false, None) => Verdict::Unknown,
        }
    }

    /// Is this the application's own (writable) file, as opposed to the user's?
    pub fn is_own(&self, file: &Path) -> bool {
        file == self.own
    }

    /// Remove every entry for `host:port` from our own known_hosts (the user's
    /// file is never touched). Returns how many lines went. Only plain (unhashed)
    /// patterns are matched, which is all this crate ever writes there.
    pub fn forget(&self, host: &str, port: u16) -> Result<usize> {
        let text = match std::fs::read_to_string(&self.own) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).context("read known_hosts"),
        };
        let target = host_pattern(host, port);
        let mut removed = 0;
        let kept: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty()) // russh's append leaves blank lines; tidy them
            .filter(|line| {
                let matches = !line.starts_with('#')
                    && line.split_whitespace().next().is_some_and(|pat| pat.split(',').any(|p| p == target));
                if matches {
                    removed += 1;
                }
                !matches
            })
            .collect();
        if removed > 0 {
            let mut out = kept.join("\n");
            out.push('\n');
            std::fs::write(&self.own, out).with_context(|| format!("rewrite {}", self.own.display()))?;
        }
        Ok(removed)
    }

    /// Append the key to our own known_hosts.
    pub fn learn(&self, host: &str, port: u16, key: &PublicKey) -> Result<()> {
        // russh writes a leading newline into an empty file; seed a header instead
        // so line numbers in "changed" messages point at real entries.
        if std::fs::metadata(&self.own).map(|m| m.len() == 0).unwrap_or(true) {
            if let Some(parent) = self.own.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(
                &self.own,
                format!(
                    "# {} known_hosts: SSH host keys accepted in the app\n",
                    self.label
                ),
            )
            .with_context(|| format!("create {}", self.own.display()))?;
        }
        russh::keys::known_hosts::learn_known_hosts_path(host, port, key, &self.own)
            .with_context(|| format!("append to {}", self.own.display()))
    }
}

/// OpenSSH's host field: bare host on port 22, `[host]:port` otherwise.
pub fn host_pattern(host: &str, port: u16) -> String {
    if port == 22 { host.to_string() } else { format!("[{host}]:{port}") }
}

/// russh numbers only non-comment lines in `KeyChanged`; map that back to
/// the actual line in the file so the user can find and remove it.
fn real_line(file: &Path, nth_non_comment: usize) -> usize {
    let Ok(text) = std::fs::read_to_string(file) else { return nth_non_comment };
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#'))
        .nth(nth_non_comment.saturating_sub(1))
        .map(|(i, _)| i + 1)
        .unwrap_or(nth_non_comment)
}

/// "SHA256:…" as ssh-keygen prints it.
pub fn fingerprint(key: &PublicKey) -> String {
    // ssh-key's Fingerprint displays with its "SHA256:" prefix already.
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// The key type as OpenSSH names it, e.g. `ssh-ed25519`.
pub fn key_type(key: &PublicKey) -> String {
    key.algorithm().as_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{private::Ed25519Keypair, public::KeyData};

    /// A different Ed25519 key on every call (fixed seeds; no RNG needed).
    fn key() -> PublicKey {
        use std::sync::atomic::{AtomicU8, Ordering};
        static N: AtomicU8 = AtomicU8::new(1);
        let kp = Ed25519Keypair::from_seed(&[N.fetch_add(1, Ordering::Relaxed); 32]);
        PublicKey::new(KeyData::Ed25519(kp.public), "")
    }

    #[test]
    fn fingerprint_is_ssh_keygen_style() {
        let f = fingerprint(&key());
        assert!(f.starts_with("SHA256:") && !f.starts_with("SHA256:SHA256:"), "{f}");
        assert_eq!(f.len(), "SHA256:".len() + 43);
        assert_eq!(key_type(&key()), "ssh-ed25519");
    }

    #[test]
    fn unknown_then_learn_then_known() {
        let dir = tempfile::tempdir().unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), None);
        let k = key();
        assert_eq!(hk.check("10.0.0.1", 22, &k), Verdict::Unknown);
        hk.learn("10.0.0.1", 22, &k).unwrap();
        assert_eq!(hk.check("10.0.0.1", 22, &k), Verdict::Known);
        // Port-specific entries do not leak across ports.
        assert_eq!(hk.check("10.0.0.1", 2222, &k), Verdict::Unknown);
        hk.learn("10.0.0.1", 2222, &k).unwrap();
        assert_eq!(hk.check("10.0.0.1", 2222, &k), Verdict::Known);
        let text = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
        assert!(text.contains("[10.0.0.1]:2222 ssh-ed25519 "));
    }

    #[test]
    fn different_key_for_same_host_is_changed() {
        let dir = tempfile::tempdir().unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), None);
        hk.learn("h", 22, &key()).unwrap();
        match hk.check("h", 22, &key()) {
            Verdict::Changed { file, line } => {
                let text = std::fs::read_to_string(file).unwrap();
                assert!(text.lines().nth(line - 1).unwrap().starts_with("h ssh-ed25519 "), "line points at the entry");
            }
            v => panic!("expected Changed, got {v:?}"),
        }
    }

    /// An ECDSA key, for the different-type case.
    fn ecdsa_key() -> PublicKey {
        let pem = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAgFLNP+hrAVOB2ebGyk1nwH+rGv25yVv+PuZt3wNgu8wK2OkrA2t5H5hx2dzXmHMmVqcfVqlUVv3DjYlbh8oaU=";
        PublicKey::from_openssh(pem).unwrap()
    }

    #[test]
    fn a_key_of_another_type_is_a_change_not_a_first_meeting() {
        let dir = tempfile::tempdir().unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), None);
        hk.learn("h", 22, &key()).unwrap();
        match hk.check("h", 22, &ecdsa_key()) {
            Verdict::Changed { file, line } => {
                let text = std::fs::read_to_string(file).unwrap();
                assert!(text.lines().nth(line - 1).unwrap().starts_with("h ssh-ed25519 "));
            }
            v => panic!("an ed25519 host offering ECDSA must not be Unknown, got {v:?}"),
        }
        // Both types on file, either one offered: known.
        let both = key();
        let hk2 = HostKeys::with_paths(dir.path().join("kh2"), None);
        hk2.learn("h", 22, &both).unwrap();
        hk2.learn("h", 22, &ecdsa_key()).unwrap();
        assert_eq!(hk2.check("h", 22, &both), Verdict::Known);
        assert_eq!(hk2.check("h", 22, &ecdsa_key()), Verdict::Known);
        // Another host's entry says nothing about this one.
        assert_eq!(hk.check("other", 22, &ecdsa_key()), Verdict::Unknown);
    }

    #[test]
    fn known_in_one_file_wins_over_another_type_in_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user_known_hosts");
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), Some(user.clone()));
        let k = key();
        russh::keys::known_hosts::learn_known_hosts_path("h", 22, &ecdsa_key(), &user).unwrap();
        hk.learn("h", 22, &k).unwrap();
        assert_eq!(hk.check("h", 22, &k), Verdict::Known);
    }

    #[test]
    fn forget_removes_only_that_host_from_own_file() {
        let dir = tempfile::tempdir().unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), None);
        let (a, b) = (key(), key());
        hk.learn("a", 22, &a).unwrap();
        hk.learn("b", 2222, &b).unwrap();
        hk.learn("a", 22, &key()).unwrap(); // second (stale) entry for a
        assert_eq!(hk.forget("a", 22).unwrap(), 2);
        assert_eq!(hk.check("a", 22, &a), Verdict::Unknown);
        assert_eq!(hk.check("b", 2222, &b), Verdict::Known);
        assert_eq!(hk.forget("nope", 22).unwrap(), 0);
        let text = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
        assert!(text.starts_with("# charon-ssh"), "header kept");
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn with_label_names_the_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), None).with_label("myapp");
        hk.learn("h", 22, &key()).unwrap();
        let text = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
        assert!(text.starts_with("# myapp known_hosts"), "{text}");
    }

    #[test]
    fn user_file_is_a_read_only_second_source() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user_known_hosts");
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), Some(user.clone()));
        let k = key();
        russh::keys::known_hosts::learn_known_hosts_path("h", 22, &k, &user).unwrap();
        assert_eq!(hk.check("h", 22, &k), Verdict::Known);
        assert!(!dir.path().join("known_hosts").exists(), "own file untouched by a check");

        // A mismatch against the user's file is a hard failure too.
        assert!(matches!(hk.check("h", 22, &key()), Verdict::Changed { .. }));
    }

    #[test]
    fn unparseable_user_entries_do_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("user_known_hosts");
        std::fs::write(&user, "h sk-ssh-ed25519@openssh.com AAAAnotreallyakey\n").unwrap();
        let hk = HostKeys::with_paths(dir.path().join("known_hosts"), Some(user));
        assert_eq!(hk.check("h", 22, &key()), Verdict::Unknown);
    }
}
