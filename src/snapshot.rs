//! Pre-destructive workspace snapshots stored as git objects.
//!
//! A snapshot captures tracked and untracked (non-ignored) files using a
//! throwaway index, so the user's index, working tree, branches, and stash are
//! never touched. Each snapshot is pinned by `refs/brakeline/snapshots/<id>`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::state::{self, ensure_private_dir, lock, now_secs};

pub const REF_PREFIX: &str = "refs/brakeline/snapshots/";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub repo: String,
    pub commit: String,
    pub session_id: String,
    pub reason: String,
    pub command: String,
    pub created_at: u64,
}

fn git(repo: &Path, args: &[&str], index: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    // Snapshot objects are not user history; give them a fixed identity so
    // they work on machines with no git identity configured.
    cmd.env("GIT_AUTHOR_NAME", "brakeline")
        .env("GIT_AUTHOR_EMAIL", "brakeline@localhost")
        .env("GIT_COMMITTER_NAME", "brakeline")
        .env("GIT_COMMITTER_EMAIL", "brakeline@localhost");
    let out = cmd.output().context("failed to run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn repo_root(cwd: &Path) -> Option<PathBuf> {
    git(cwd, &["rev-parse", "--show-toplevel"], None)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

fn new_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}-{:04x}",
        now.as_secs(),
        (now.subsec_nanos() ^ std::process::id()) & 0xffff
    )
}

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(self.0.with_extension("lock"));
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Writes the current work tree (tracked and untracked, minus ignored files)
/// as a git tree object, using a throwaway index. Returns the tree id.
fn worktree_tree(data_dir: &Path, root: &Path, tag: &str) -> Result<String> {
    let tmp_dir = data_dir.join("tmp");
    ensure_private_dir(&tmp_dir)?;
    let index = TempFile(tmp_dir.join(format!("index-{tag}-{}", std::process::id())));

    // Seed the temp index from the real one so unchanged files are not rehashed.
    let real_index = git(root, &["rev-parse", "--git-path", "index"], None)?;
    let real_index = {
        let p = PathBuf::from(&real_index);
        if p.is_absolute() { p } else { root.join(p) }
    };
    if real_index.exists() {
        fs::copy(&real_index, &index.0).context("cannot copy git index")?;
    }
    git(root, &["add", "-A", "--", "."], Some(&index.0))?;
    git(root, &["write-tree"], Some(&index.0))
}

/// Snapshots the repository containing `cwd`. Returns `Ok(None)` when `cwd`
/// is not inside a git work tree.
pub fn take(
    data_dir: &Path,
    cwd: &Path,
    session_id: &str,
    reason: &str,
    command: &str,
) -> Result<Option<SnapshotRecord>> {
    let Some(root) = repo_root(cwd) else {
        return Ok(None);
    };
    let id = new_id();
    let head = git(&root, &["rev-parse", "--verify", "-q", "HEAD"], None).ok();
    let tree = worktree_tree(data_dir, &root, &id)?;

    let unchanged = match &head {
        Some(h) => {
            git(&root, &["rev-parse", &format!("{h}^{{tree}}")], None).ok() == Some(tree.clone())
        }
        None => false,
    };
    let commit = match (&head, unchanged) {
        (Some(h), true) => h.clone(),
        _ => {
            let message = format!(
                "brakeline snapshot {id}\n\nbefore: {}",
                truncate(command, 500)
            );
            let mut args = vec!["commit-tree", tree.as_str(), "-m", message.as_str()];
            if let Some(h) = &head {
                args.push("-p");
                args.push(h);
            }
            git(&root, &args, None)?
        }
    };
    git(
        &root,
        &["update-ref", &format!("{REF_PREFIX}{id}"), &commit],
        None,
    )?;

    let record = SnapshotRecord {
        id,
        repo: root.to_string_lossy().into_owned(),
        commit,
        session_id: session_id.to_string(),
        reason: reason.to_string(),
        command: truncate(command, 300),
        created_at: now_secs(),
    };
    append_record(data_dir, &record)?;
    Ok(Some(record))
}

fn log_path(data_dir: &Path) -> PathBuf {
    data_dir.join("snapshots.jsonl")
}

fn append_record(data_dir: &Path, record: &SnapshotRecord) -> Result<()> {
    let _guard = lock(&data_dir.join("snapshots.lock"))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path(data_dir))?;
    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    Ok(())
}

pub fn list(data_dir: &Path) -> Result<Vec<SnapshotRecord>> {
    let text = match fs::read_to_string(log_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(text
        .lines()
        .filter_map(|l| serde_json::from_str::<SnapshotRecord>(l).ok())
        .collect())
}

pub fn find(data_dir: &Path, id: &str) -> Result<SnapshotRecord> {
    list(data_dir)?
        .into_iter()
        .rev()
        .find(|r| r.id == id)
        .with_context(|| format!("no snapshot with id {id}"))
}

/// Files restoring would add or change, compared with the whole current work
/// tree including untracked files. Deletions are omitted: restore keeps them.
pub fn preview(data_dir: &Path, record: &SnapshotRecord) -> Result<String> {
    let repo = Path::new(&record.repo);
    let current = worktree_tree(data_dir, repo, "preview")?;
    git(
        repo,
        &[
            "diff",
            "--stat",
            "--diff-filter=AMT",
            &current,
            &record.commit,
            "--",
        ],
        None,
    )
}

/// Writes the snapshot's version of `paths` (or everything) back into the
/// work tree. Files created after the snapshot are kept, and the current
/// state is snapshotted first so the restore itself can be undone.
pub fn restore(
    data_dir: &Path,
    record: &SnapshotRecord,
    paths: &[String],
) -> Result<Option<SnapshotRecord>> {
    let repo = Path::new(&record.repo);
    git(
        repo,
        &["cat-file", "-e", &format!("{}^{{commit}}", record.commit)],
        None,
    )
    .context("snapshot commit is missing (was it pruned?)")?;
    let backup = take(
        data_dir,
        repo,
        &record.session_id,
        "before restore",
        &format!("brakeline restore {}", record.id),
    )?;
    let source = format!("--source={}", record.commit);
    let mut args = vec!["restore", source.as_str(), "--worktree", "--overlay", "--"];
    if paths.is_empty() {
        args.push(".");
    } else {
        args.extend(paths.iter().map(String::as_str));
    }
    git(repo, &args, None)?;
    Ok(backup)
}

/// Keeps the newest `keep` snapshots per repository and deletes the rest.
pub fn prune(data_dir: &Path, keep: usize) -> Result<usize> {
    let _guard = lock(&data_dir.join("snapshots.lock"))?;
    let records = list(data_dir)?;
    let mut kept = Vec::new();
    let mut removed = 0;
    let mut per_repo: std::collections::HashMap<&str, usize> = Default::default();
    for record in records.iter().rev() {
        let count = per_repo.entry(record.repo.as_str()).or_default();
        if *count < keep {
            *count += 1;
            kept.push(record);
        } else {
            let _ = git(
                Path::new(&record.repo),
                &["update-ref", "-d", &format!("{REF_PREFIX}{}", record.id)],
                None,
            );
            removed += 1;
        }
    }
    kept.reverse();
    let mut text = String::new();
    for r in kept {
        text.push_str(&serde_json::to_string(r)?);
        text.push('\n');
    }
    state::write_atomic(&log_path(data_dir), text.as_bytes())?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    #[test]
    fn snapshot_recovers_uncommitted_and_untracked_work() {
        let repo = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        sh(r, &["init", "-q"]);
        fs::write(r.join("tracked.txt"), "v1").unwrap();
        fs::write(r.join(".gitignore"), "ignored.txt\n").unwrap();
        sh(r, &["add", "."]);
        sh(r, &["commit", "-q", "-m", "init"]);

        // Uncommitted edit, staged-but-uncommitted file, and an untracked file.
        fs::write(r.join("tracked.txt"), "v2 uncommitted").unwrap();
        fs::write(r.join("staged.txt"), "staged").unwrap();
        sh(r, &["add", "staged.txt"]);
        fs::write(r.join("new.txt"), "untracked").unwrap();
        fs::write(r.join("ignored.txt"), "secret").unwrap();
        let index_before = fs::read(r.join(".git/index")).unwrap();

        let rec = take(data.path(), r, "s", "test", "git reset --hard")
            .unwrap()
            .unwrap();
        // The user's index must be untouched.
        assert_eq!(fs::read(r.join(".git/index")).unwrap(), index_before);

        // Simulate the agent wiping everything.
        sh(r, &["reset", "-q", "--hard"]);
        sh(r, &["clean", "-q", "-fd"]);
        assert!(!r.join("new.txt").exists());
        assert_eq!(fs::read_to_string(r.join("tracked.txt")).unwrap(), "v1");

        let found = find(data.path(), &rec.id).unwrap();
        let shown = preview(data.path(), &found).unwrap();
        assert!(shown.contains("tracked.txt"), "{shown}");
        assert!(
            shown.contains("new.txt"),
            "untracked files must be previewed: {shown}"
        );
        let backup = restore(data.path(), &found, &[]).unwrap();
        assert!(backup.is_some());
        assert_eq!(
            fs::read_to_string(r.join("tracked.txt")).unwrap(),
            "v2 uncommitted"
        );
        assert_eq!(fs::read_to_string(r.join("new.txt")).unwrap(), "untracked");
        assert_eq!(fs::read_to_string(r.join("staged.txt")).unwrap(), "staged");
        // Ignored files are out of scope and never stored.
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(r)
                .args(["cat-file", "-e", &format!("{}:ignored.txt", rec.commit)])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .code()
                != Some(0)
        );
    }

    #[test]
    fn works_in_a_repo_with_no_commits_and_outside_git() {
        let repo = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        sh(repo.path(), &["init", "-q"]);
        fs::write(repo.path().join("a.txt"), "a").unwrap();
        let rec = take(data.path(), repo.path(), "s", "t", "rm a.txt")
            .unwrap()
            .unwrap();
        fs::remove_file(repo.path().join("a.txt")).unwrap();
        restore(data.path(), &rec, &["a.txt".into()]).unwrap();
        assert_eq!(fs::read_to_string(repo.path().join("a.txt")).unwrap(), "a");

        let plain = tempfile::tempdir().unwrap();
        assert!(
            take(data.path(), plain.path(), "s", "t", "rm x")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prune_keeps_newest_per_repo() {
        let repo = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        sh(repo.path(), &["init", "-q"]);
        let mut ids = Vec::new();
        for i in 0..4 {
            fs::write(repo.path().join("f.txt"), i.to_string()).unwrap();
            ids.push(
                take(data.path(), repo.path(), "s", "t", "rm")
                    .unwrap()
                    .unwrap()
                    .id,
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(prune(data.path(), 2).unwrap(), 2);
        let left: Vec<String> = list(data.path())
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(left, ids[2..].to_vec());
    }
}
