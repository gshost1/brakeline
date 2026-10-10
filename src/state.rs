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
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f =
            File::create(&tmp).with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
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
    pub tool_calls: u64,
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
    /// Cumulative totals last reported by an agent that keeps its own
    /// counters (Droid), and the totals at the last budget reset.
    pub usage_raw: Usage,
    pub usage_baseline: Usage,
}

const MAX_FAILURE_ENTRIES: usize = 64;
const MAX_PENDING: usize = 64;

impl SessionState {
    /// Records one failure of the call `fp` in the current epoch.
    pub fn record_failure(&mut self, fp: u64, label: &str) {
        let epoch = self.epoch;
        let f = self.failure_mut(fp, label);
        f.consecutive = if f.epoch == epoch {
            f.consecutive + 1
        } else {
            1
        };
        f.total += 1;
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
    pub fn with_session<R>(
        &self,
        id: &str,
        f: impl FnOnce(&mut SessionState) -> Result<R>,
    ) -> Result<R> {
        let path = self.session_path(id);
        let _guard = lock(&path.with_extension("lock"))?;
        let mut state = read_state(&path)?.unwrap_or_else(|| SessionState {
            session_id: id.to_string(),
            started_at: now_secs(),
            ..SessionState::default()
        });
        let result = f(&mut state)?;
        let bytes = serde_json::to_vec_pretty(&state)?;
        write_atomic(&path, &bytes)?;
        Ok(result)
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
