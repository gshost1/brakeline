use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn now_secs() -> u64 {
    now_millis() / 1000
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Root for all brakeline data: `$BRAKELINE_HOME`, else `~/.brakeline`.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BRAKELINE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    crate::config::home_dir()
        .map(|h| h.join(".brakeline"))
        .context("HOME is not set; set BRAKELINE_HOME")
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write via a temp file and rename, so a crash never leaves a torn file.
/// The result is private (0600). For brakeline's own files.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    replace_file(path, bytes, None)
}

/// Like `write_atomic`, for a file the user owns (agent settings): a
/// symlinked `path` is written through to its target, so the link stays,
/// and an existing file keeps its permissions.
pub fn write_atomic_preserving(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = resolve_symlinks(path)?;
    let mode = fs::metadata(&path).ok().map(|m| m.permissions());
    replace_file(&path, bytes, mode)
}

fn replace_file(path: &Path, bytes: &[u8], mode: Option<fs::Permissions>) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    // Next to the target, so the rename stays on one filesystem. Unique per
    // call, so concurrent writers never touch each other's temp file.
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_new(&tmp, bytes, mode).and_then(|()| {
        fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_new(tmp: &Path, bytes: &[u8], mode: Option<fs::Permissions>) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(tmp)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    if let Some(mode) = mode {
        f.set_permissions(mode)
            .with_context(|| format!("cannot set permissions on {}", tmp.display()))?;
    }
    f.write_all(bytes)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    f.sync_all().ok();
    Ok(())
}

/// Follows symlinks to the final path, which need not exist yet.
fn resolve_symlinks(path: &Path) -> Result<PathBuf> {
    let mut path = path.to_path_buf();
    for _ in 0..40 {
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = fs::read_link(&path)
                    .with_context(|| format!("cannot read link {}", path.display()))?;
                path = match path.parent() {
                    Some(dir) => dir.join(target),
                    None => target,
                };
            }
            _ => return Ok(path),
        }
    }
    anyhow::bail!("too many levels of symbolic links at {}", path.display())
}

fn new_state(id: &str) -> SessionState {
    SessionState {
        session_id: id.to_string(),
        started_at: now_secs(),
        ..SessionState::default()
    }
}

/// Holds an exclusive advisory lock until dropped.
pub struct LockGuard {
    _file: File,
}

pub fn lock(path: &Path) -> Result<LockGuard> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open lock {}", path.display()))?;
    file.lock()
        .with_context(|| format!("cannot lock {}", path.display()))?;
    Ok(LockGuard { _file: file })
}

/// Session ids come from the agent; keep them safe to use as file names.
pub fn sanitize_id(id: &str) -> String {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.starts_with('.');
    if ok {
        id.to_string()
    } else {
        format!("h{:016x}", fnv1a(id.as_bytes()))
    }
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Stable identity of a tool call. Free-text fields that agents vary between
/// otherwise identical calls (like a Bash `description`) are ignored.
pub fn fingerprint(tool: &str, input: &Value) -> u64 {
    let mut text = String::with_capacity(128);
    text.push_str(tool);
    text.push('\u{0}');
    match input {
        Value::Object(map) => {
            let mut trimmed = map.clone();
            for key in ["description", "summary", "riskLevel"] {
                trimmed.remove(key);
            }
            canonical(&Value::Object(trimmed), &mut text);
        }
        other => canonical(other, &mut text),
    }
    fnv1a(text.as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentCall {
    pub fp: u64,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureStreak {
    pub fp: u64,
    pub label: String,
    pub consecutive: u32,
    /// Failures in the current epoch, successes in between or not.
    pub total: u32,
    pub epoch: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_write_tokens: u64,
    pub cache_read_tokens: u64,
    pub cost_usd: f64,
    pub messages: u64,
    pub factory_credits: u64,
}

/// A call that was allowed but has not reported back yet. Agents that send
/// no event for failed tool calls (Droid) leave these behind on failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub fp: u64,
    pub label: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscriptCursor {
    pub path: String,
    pub offset: u64,
    /// Recently counted message ids with the usage already attributed to
    /// each, so repeated transcript entries only add their delta.
    pub seen: VecDeque<(String, [u64; 4])>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    pub session_id: String,
    pub cwd: String,
    pub started_at: u64,
    pub last_seen: u64,
    /// Seconds the session was working: gaps between hook events up to
    /// `IDLE_GAP_SECS` count, longer ones (waiting on the user, a resumed
    /// chat) do not. The session time budget is measured against this.
    /// `None` in records written before it existed.
    pub active_secs: Option<u64>,
    pub tool_calls: u64,
    /// Allowed calls over the session's life; unlike `tool_calls`, a budget
    /// reset does not clear it.
    pub lifetime_calls: u64,
    /// Bumped whenever the agent changes files; loop counters only compare
    /// calls within the same epoch.
    pub epoch: u64,
    pub recent: VecDeque<RecentCall>,
    pub failures: Vec<FailureStreak>,
    pub consecutive_denials: u32,
    pub total_denials: u64,
    pub last_denial: Option<String>,
    pub halted: Option<String>,
    pub warned: Vec<String>,
    pub usage: Usage,
    pub transcript: TranscriptCursor,
    pub snapshots: u64,
    pub pending: Vec<Pending>,
    /// Token counters last reported by an agent that keeps its own (Droid),
    /// with `cost_usd` as a running sum of each increase priced at the model
    /// in use when it was seen; and this record as of the last budget reset.
    pub usage_raw: Usage,
    pub usage_baseline: Usage,
    /// The session this one was spawned from, followed to the top (Droid's
    /// `callingSessionId`): a mission's orchestrator, or the session that
    /// started a subagent. Its own id when it has no parent; `None` until
    /// resolved. Budgets count the whole group under this root.
    pub root: Option<String>,
}

/// What one session of a group has used by itself, children excluded.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupUse {
    pub factory_credits: u64,
    pub output_tokens: u64,
    pub tool_calls: u64,
}

impl GroupUse {
    fn add(&mut self, o: &GroupUse) {
        self.factory_credits += o.factory_credits;
        self.output_tokens += o.output_tokens;
        self.tool_calls += o.tool_calls;
    }
}

/// Sessions spawned from one root (a Droid mission and its workers), so a
/// budget covers the whole run and not each worker separately.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupState {
    pub members: std::collections::BTreeMap<String, GroupUse>,
    /// The sum as of the last `brakeline reset --budget` of a member.
    pub baseline: GroupUse,
}

impl GroupState {
    pub fn sum(&self) -> GroupUse {
        let mut t = GroupUse::default();
        for m in self.members.values() {
            t.add(m);
        }
        t
    }

    /// Use since the last budget reset.
    pub fn total(&self) -> GroupUse {
        let s = self.sum();
        let b = &self.baseline;
        GroupUse {
            factory_credits: s.factory_credits.saturating_sub(b.factory_credits),
            output_tokens: s.output_tokens.saturating_sub(b.output_tokens),
            tool_calls: s.tool_calls.saturating_sub(b.tool_calls),
        }
    }
}

const MAX_FAILURE_ENTRIES: usize = 64;
const MAX_PENDING: usize = 64;

impl SessionState {
    /// Records one failure of the call `fp` in the current epoch.
    pub fn record_failure(&mut self, fp: u64, label: &str) {
        let epoch = self.epoch;
        let f = self.failure_mut(fp, label);
        let same_epoch = f.epoch == epoch;
        f.consecutive = if same_epoch { f.consecutive + 1 } else { 1 };
        f.total = if same_epoch { f.total + 1 } else { 1 };
        f.epoch = epoch;
    }

    pub fn add_pending(&mut self, fp: u64, label: &str, at_ms: u64) {
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(Pending {
            fp,
            label: label.to_string(),
            at_ms,
        });
    }

    /// Clears the oldest pending entry for `fp`; returns whether one existed.
    pub fn resolve_pending(&mut self, fp: u64) -> bool {
        match self.pending.iter().position(|p| p.fp == fp) {
            Some(i) => {
                self.pending.remove(i);
                true
            }
            None => false,
        }
    }

    /// Counts pending calls started before `cutoff_ms` as failed.
    pub fn expire_pending(&mut self, cutoff_ms: u64) {
        let (expired, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.at_ms < cutoff_ms);
        self.pending = kept;
        for p in expired {
            self.record_failure(p.fp, &p.label);
        }
    }

    pub fn failure_mut(&mut self, fp: u64, label: &str) -> &mut FailureStreak {
        if let Some(i) = self.failures.iter().position(|f| f.fp == fp) {
            return &mut self.failures[i];
        }
        if self.failures.len() >= MAX_FAILURE_ENTRIES {
            self.failures.remove(0);
        }
        self.failures.push(FailureStreak {
            fp,
            label: label.to_string(),
            consecutive: 0,
            total: 0,
            epoch: self.epoch,
        });
        self.failures.last_mut().expect("just pushed")
    }

    pub fn failure(&self, fp: u64) -> Option<&FailureStreak> {
        self.failures.iter().find(|f| f.fp == fp)
    }

    pub fn identical_in_epoch(&self, fp: u64) -> usize {
        self.recent
            .iter()
            .filter(|c| c.fp == fp && c.epoch == self.epoch)
            .count()
    }

    pub fn remember(&mut self, fp: u64, window: usize) {
        self.recent.push_back(RecentCall {
            fp,
            epoch: self.epoch,
        });
        while self.recent.len() > window {
            self.recent.pop_front();
        }
    }
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Self> {
        ensure_private_dir(&root)?;
        ensure_private_dir(&root.join("sessions"))?;
        ensure_private_dir(&root.join("groups"))?;
        Ok(Self { root })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(data_dir()?)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn session_path(&self, id: &str) -> PathBuf {
        self.root
            .join("sessions")
            .join(format!("{}.json", sanitize_id(id)))
    }

    /// Runs `f` on the session state under an exclusive lock and persists it.
    /// Fails before running `f` if the lock cannot be taken.
    pub fn with_session<R>(
        &self,
        id: &str,
        f: impl FnOnce(&mut SessionState) -> Result<R>,
    ) -> Result<R> {
        let path = self.session_path(id);
        let _guard = lock(&path.with_extension("lock"))?;
        let mut state = read_state(&path)?.unwrap_or_else(|| new_state(id));
        let result = f(&mut state)?;
        write_atomic(&path, &serde_json::to_vec_pretty(&state)?)?;
        Ok(result)
    }

    /// Like `with_session`, but a state that was read yet could not be saved
    /// (full disk, read-only directory, no lock) still yields `f`'s result,
    /// with the save error alongside. Errors only when the state is unreadable
    /// or `f` fails.
    pub fn update_session<R>(
        &self,
        id: &str,
        f: impl FnOnce(&mut SessionState) -> Result<R>,
    ) -> Result<(R, Option<anyhow::Error>)> {
        let path = self.session_path(id);
        // Without the lock, a concurrent call may race us; deciding from the
        // last saved state is still better than not deciding at all. With no
        // lock and no saved state there is nothing to decide from.
        let guard = lock(&path.with_extension("lock"));
        let mut state = match (read_state(&path)?, &guard) {
            (Some(state), _) => state,
            (None, Ok(_)) => new_state(id),
            (None, Err(err)) => anyhow::bail!("cannot lock session state: {err:#}"),
        };
        let result = f(&mut state)?;
        let saved = guard.and_then(|_guard| {
            let bytes = serde_json::to_vec_pretty(&state)?;
            write_atomic(&path, &bytes)
        });
        Ok((result, saved.err()))
    }

    fn group_path(&self, root: &str) -> PathBuf {
        self.root
            .join("groups")
            .join(format!("{}.json", sanitize_id(root)))
    }

    pub fn group_exists(&self, root: &str) -> bool {
        self.group_path(root).exists()
    }

    /// Runs `f` on the group under `root` with an exclusive lock and saves it.
    /// Take a group lock only while holding at most a session lock, never
    /// the other way round.
    pub fn with_group<R>(&self, root: &str, f: impl FnOnce(&mut GroupState) -> R) -> Result<R> {
        let path = self.group_path(root);
        let _guard = lock(&path.with_extension("lock"))?;
        let mut group: GroupState = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("{} is not a group record", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => GroupState::default(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let before = group.clone();
        let result = f(&mut group);
        if group != before {
            write_atomic(&path, &serde_json::to_vec_pretty(&group)?)?;
        }
        Ok(result)
    }

    pub fn load_group(&self, root: &str) -> Option<GroupState> {
        let bytes = fs::read(self.group_path(root)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn load(&self, id: &str) -> Result<Option<SessionState>> {
        read_state(&self.session_path(id))
    }

    pub fn exists(&self, id: &str) -> bool {
        self.session_path(id).exists()
    }

    pub fn list(&self) -> Result<Vec<SessionState>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("sessions"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json")
                && let Ok(Some(state)) = read_state(&path)
            {
                out.push(state);
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.last_seen));
        Ok(out)
    }

    /// Deletes session files not seen for `days`. Returns how many were removed.
    pub fn gc(&self, days: u64) -> Result<usize> {
        let cutoff = now_secs().saturating_sub(days.saturating_mul(86_400));
        let mut removed = 0;
        for state in self.list()? {
            if state.last_seen < cutoff {
                let path = self.session_path(&state.session_id);
                let _guard = lock(&path.with_extension("lock"))?;
                if fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
                let _ = fs::remove_file(path.with_extension("lock"));
            }
        }
        // Groups are written on every call of a member, so an old file means
        // the whole group has gone quiet.
        let old = std::time::Duration::from_secs(days.saturating_mul(86_400));
        if let Ok(entries) = fs::read_dir(self.root.join("groups")) {
            for entry in entries.flatten() {
                let path = entry.path();
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > old);
                // The lock file stays: unlinking it while a hook waits on it
                // would let two writers in at once.
                if stale
                    && path.extension().is_some_and(|e| e == "json")
                    && let Ok(_guard) = lock(&path.with_extension("lock"))
                {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(removed)
    }
}

fn read_state(path: &Path) -> Result<Option<SessionState>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("corrupt session state {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprint_ignores_key_order_and_description() {
        let a = fingerprint(
            "Bash",
            &json!({"command": "cargo test", "description": "run tests", "timeout": 5}),
        );
        let b = fingerprint(
            "Bash",
            &json!({"timeout": 5, "command": "cargo test", "description": "again"}),
        );
        let c = fingerprint(
            "Bash",
            &json!({"command": "cargo test --all", "timeout": 5}),
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(
            a,
            fingerprint("Read", &json!({"command": "cargo test", "timeout": 5}))
        );
    }

    #[test]
    fn sanitizes_hostile_session_ids() {
        assert_eq!(sanitize_id("abc-123_x.y"), "abc-123_x.y");
        assert!(sanitize_id("../../etc/passwd").starts_with('h'));
        assert!(sanitize_id(".hidden").starts_with('h'));
        assert!(sanitize_id("").starts_with('h'));
    }

    #[test]
    fn state_round_trips_under_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        store
            .with_session("s1", |s| {
                s.tool_calls = 7;
                Ok(())
            })
            .unwrap();
        let loaded = store.load("s1").unwrap().unwrap();
        assert_eq!(loaded.tool_calls, 7);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_mode_and_new_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let fresh = dir.path().join("fresh.json");
        write_atomic(&fresh, b"{}").unwrap();
        assert_eq!(mode(&fresh), 0o600);
        // brakeline's own files become private even if they weren't.
        fs::set_permissions(&fresh, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&fresh, b"{}").unwrap();
        assert_eq!(mode(&fresh), 0o600);
        let shared = dir.path().join("shared.json");
        fs::write(&shared, b"old").unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic_preserving(&shared, b"new").unwrap();
        assert_eq!(mode(&shared), 0o640);
        assert_eq!(fs::read(&shared).unwrap(), b"new");
        // No temp files left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_follows_symlink_chains() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, b"old").unwrap();
        let mid = dir.path().join("mid.json");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&real, &mid).unwrap();
        std::os::unix::fs::symlink("mid.json", &link).unwrap();
        write_atomic_preserving(&link, b"new").unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::symlink_metadata(&mid).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&real).unwrap(), b"new");
        let lo = dir.path().join("loop");
        std::os::unix::fs::symlink("loop", &lo).unwrap();
        assert!(write_atomic_preserving(&lo, b"x").is_err());
    }

    #[test]
    fn parallel_writes_to_one_path_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        std::thread::scope(|scope| {
            for i in 0..8 {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..50 {
                        write_atomic(path, format!("{i}").as_bytes()).unwrap();
                    }
                });
            }
        });
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn no_lock_and_no_saved_state_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("data")).unwrap();
        let sessions = dir.path().join("data").join("sessions");
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o500)).unwrap();
        let writable = fs::write(sessions.join("probe"), b"").is_ok();
        let mut ran = false;
        let unlocked = store.update_session("new", |_| {
            ran = true;
            Ok(())
        });
        let reset = store.with_session("new", |_| Ok(()));
        fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            return; // running as root: permissions don't block writes
        }
        assert!(unlocked.is_err());
        assert!(!ran, "decided from a blank state");
        assert!(reset.is_err());
    }

    #[test]
    fn window_is_bounded() {
        let mut s = SessionState::default();
        for i in 0..10 {
            s.remember(i % 2, 4);
        }
        assert_eq!(s.recent.len(), 4);
        assert_eq!(s.identical_in_epoch(0), 2);
        s.epoch += 1;
        assert_eq!(s.identical_in_epoch(0), 0);
    }
}
