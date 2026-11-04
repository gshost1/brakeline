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

/// Runs git in `repo` and returns its raw stdout. `env` adds variables (such
/// as `GIT_DIR`), and `input` is written to stdin.
fn git_raw(
    repo: &Path,
    args: &[&str],
    index: Option<&Path>,
    env: &[(&str, &Path)],
    input: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    // Snapshot objects are not user history; give them a fixed identity so
    // they work on machines with no git identity configured.
    cmd.env("GIT_AUTHOR_NAME", "brakeline")
        .env("GIT_AUTHOR_EMAIL", "brakeline@localhost")
        .env("GIT_COMMITTER_NAME", "brakeline")
        .env("GIT_COMMITTER_EMAIL", "brakeline@localhost");
    let mut child = cmd.spawn().context("failed to run git")?;
    // Feed stdin from a thread so a large output cannot deadlock against it.
    let writer = match (input, child.stdin.take()) {
        (Some(data), Some(mut stdin)) => Some(std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        })),
        _ => None,
    };
    let out = child.wait_with_output().context("failed to run git")?;
    if let Some(w) = writer {
        let _ = w.join();
    }
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// Runs git and returns stdout minus its final newline. Only the newline is
/// removed: a path such as the repository root may itself end in whitespace.
fn git(repo: &Path, args: &[&str], index: Option<&Path>) -> Result<String> {
    let out = git_raw(repo, args, index, &[], None)?;
    let mut text = String::from_utf8_lossy(&out).into_owned();
    if text.ends_with('\n') {
        text.pop();
    }
    Ok(text)
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

fn temp_index(data_dir: &Path, tag: &str) -> Result<TempFile> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tmp_dir = data_dir.join("tmp");
    ensure_private_dir(&tmp_dir)?;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(TempFile(
        tmp_dir.join(format!("index-{tag}-{}-{n}", std::process::id())),
    ))
}

/// Splits NUL-terminated git output into its records.
fn split_z(out: &[u8]) -> impl Iterator<Item = &[u8]> {
    out.split(|b| *b == 0).filter(|r| !r.is_empty())
}

fn join_z<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item);
        out.push(0);
    }
    out
}

/// A git path (bytes, relative to `root`) as a filesystem path.
fn fs_path(root: &Path, rel: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        root.join(std::ffi::OsStr::from_bytes(rel))
    }
    #[cfg(not(unix))]
    {
        root.join(String::from_utf8_lossy(rel).as_ref())
    }
}

/// Index entries flagged skip-worktree and assume-unchanged, from
/// `git ls-files -v`: `S`/`s` mark skip-worktree, lowercase marks
/// assume-unchanged.
#[derive(Default)]
struct Flagged {
    skip_worktree: Vec<Vec<u8>>,
    assume_unchanged: Vec<Vec<u8>>,
}

fn flagged_paths(root: &Path, index: Option<&Path>) -> Result<Flagged> {
    let out = git_raw(root, &["ls-files", "-v", "-z"], index, &[], None)?;
    let mut flagged = Flagged::default();
    for rec in split_z(&out) {
        let (Some(&tag), Some(path)) = (rec.first(), rec.get(2..)) else {
            continue;
        };
        if tag == b'S' || tag == b's' {
            flagged.skip_worktree.push(path.to_vec());
        }
        if tag.is_ascii_lowercase() {
            flagged.assume_unchanged.push(path.to_vec());
        }
    }
    Ok(flagged)
}

/// The copied index keeps the user's skip-worktree and assume-unchanged
/// bits, which make `git add` ignore local edits to those files. Clear them
/// in the temporary index only. Skip-worktree files that are absent from
/// disk (a sparse checkout) keep the bit, so they are stored as committed
/// instead of as deleted.
fn clear_index_flags(root: &Path, index: &Path) -> Result<()> {
    let flagged = flagged_paths(root, Some(index))?;
    let present: Vec<&[u8]> = flagged
        .skip_worktree
        .iter()
        .map(Vec::as_slice)
        .filter(|p| fs::symlink_metadata(fs_path(root, p)).is_ok())
        .collect();
    for (flag, paths) in [
        ("--no-skip-worktree", present),
        (
            "--no-assume-unchanged",
            flagged.assume_unchanged.iter().map(Vec::as_slice).collect(),
        ),
    ] {
        if !paths.is_empty() {
            git_raw(
                root,
                &["update-index", flag, "-z", "--stdin"],
                Some(index),
                &[],
                Some(join_z(paths)),
            )?;
        }
    }
    Ok(())
}

/// Writes the current work tree (tracked and untracked, minus ignored files)
/// as a git tree object, using a throwaway index. Returns the tree id.
fn worktree_tree(data_dir: &Path, root: &Path, tag: &str) -> Result<String> {
    let index = temp_index(data_dir, tag)?;

    // Seed the temp index from the real one so unchanged files are not rehashed.
    let real_index = git(root, &["rev-parse", "--git-path", "index"], None)?;
    let real_index = {
        let p = PathBuf::from(&real_index);
        if p.is_absolute() { p } else { root.join(p) }
    };
    if real_index.exists() {
        fs::copy(&real_index, &index.0).context("cannot copy git index")?;
        clear_index_flags(root, &index.0)?;
    }
    git(root, &["add", "-A", "--", "."], Some(&index.0))?;
    git(root, &["write-tree"], Some(&index.0))
}

/// One file in a snapshot, by its path relative to the repository root.
struct Entry {
    path: Vec<u8>,
}

/// Lists the snapshot's files matching `paths` (all of them when empty),
/// with the same pathspec rules `git restore` uses. Fails when a pathspec
/// matches nothing, before anything has been changed.
fn snapshot_entries(
    data_dir: &Path,
    repo: &Path,
    commit: &str,
    paths: &[String],
) -> Result<Vec<Entry>> {
    let index = temp_index(data_dir, "entries")?;
    git(repo, &["read-tree", commit], Some(&index.0))?;
    let mut args = vec!["ls-files", "-s", "-z", "--error-unmatch", "--"];
    if paths.is_empty() {
        args.push(".");
    } else {
        args.extend(paths.iter().map(String::as_str));
    }
    let out =
        git_raw(repo, &args, Some(&index.0), &[], None).context("the snapshot has no such path")?;
    Ok(split_z(&out)
        .filter_map(|rec| {
            let tab = rec.iter().position(|b| *b == b'\t')?;
            Some(Entry {
                path: rec[tab + 1..].to_vec(),
            })
        })
        .collect())
}

/// Skip-worktree files that a whole-tree `git restore` would pass over but
/// that hold work: present on disk, or different in the snapshot from the
/// index. Absent and unchanged ones are sparse-checkout files; leave them.
fn skip_worktree_to_restore(repo: &Path, commit: &str, entries: &[Entry]) -> Result<Vec<Vec<u8>>> {
    let skip = flagged_paths(repo, None)?.skip_worktree;
    if skip.is_empty() {
        return Ok(Vec::new());
    }
    let in_snapshot: std::collections::HashSet<&[u8]> =
        entries.iter().map(|e| e.path.as_slice()).collect();
    let out = git_raw(
        repo,
        &["diff-index", "--cached", "--name-only", "-z", commit, "--"],
        None,
        &[],
        None,
    )?;
    let differs: std::collections::HashSet<&[u8]> = split_z(&out).collect();
    Ok(skip
        .into_iter()
        .filter(|p| in_snapshot.contains(p.as_slice()))
        .filter(|p| {
            differs.contains(p.as_slice()) || fs::symlink_metadata(fs_path(repo, p)).is_ok()
        })
        .collect())
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
    let entries = snapshot_entries(data_dir, repo, &record.commit, paths)?;
    let sparse_work = if paths.is_empty() {
        skip_worktree_to_restore(repo, &record.commit, &entries)?
    } else {
        Vec::new()
    };
    let backup = take(
        data_dir,
        repo,
        &record.session_id,
        "before restore",
        &format!("brakeline restore {}", record.id),
    )?;
    let source = format!("--source={}", record.commit);
    let mut args = vec!["restore", source.as_str(), "--worktree", "--overlay"];
    if paths.is_empty() {
        args.extend(["--", "."]);
    } else {
        // Paths the user names are restored even if flagged skip-worktree.
        args.extend(["--ignore-skip-worktree-bits", "--"]);
        args.extend(paths.iter().map(String::as_str));
    }
    git(repo, &args, None)?;
    if !sparse_work.is_empty() {
        git_raw(
            repo,
            &[
                "restore",
                source.as_str(),
                "--worktree",
                "--overlay",
                "--ignore-skip-worktree-bits",
                "--pathspec-from-file=-",
                "--pathspec-file-nul",
            ],
            None,
            &[("GIT_LITERAL_PATHSPECS", Path::new("1"))],
            Some(join_z(sparse_work.iter().map(Vec::as_slice))),
        )?;
    }
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
    fn repo_path_ending_in_a_space_is_snapshotted() {
        let base = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let r = base.path().join("sp ");
        fs::create_dir(&r).unwrap();
        sh(&r, &["init", "-q"]);
        fs::write(r.join("a.txt"), "a").unwrap();
        let rec = take(data.path(), &r, "s", "t", "rm a.txt")
            .unwrap()
            .unwrap();
        assert!(rec.repo.ends_with("sp "), "{:?}", rec.repo);
        fs::remove_file(r.join("a.txt")).unwrap();
        restore(data.path(), &rec, &[]).unwrap();
        assert_eq!(fs::read_to_string(r.join("a.txt")).unwrap(), "a");
    }

    fn committed_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        let r = repo.path();
        sh(r, &["init", "-q"]);
        for (name, body) in files {
            if let Some(parent) = Path::new(name).parent() {
                fs::create_dir_all(r.join(parent)).unwrap();
            }
            fs::write(r.join(name), body).unwrap();
        }
        sh(r, &["add", "-A"]);
        sh(r, &["commit", "-q", "-m", "init"]);
        repo
    }

    #[test]
    fn skip_worktree_and_assume_unchanged_edits_are_captured_and_restored() {
        let repo = committed_repo(&[("cfg.txt", "v1"), ("b.txt", "v1"), ("sparse.txt", "v1")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        sh(
            r,
            &["update-index", "--skip-worktree", "cfg.txt", "sparse.txt"],
        );
        sh(r, &["update-index", "--assume-unchanged", "b.txt"]);
        fs::write(r.join("cfg.txt"), "local cfg").unwrap();
        fs::write(r.join("b.txt"), "local b").unwrap();
        // Like a sparse checkout: flagged and absent from disk.
        fs::remove_file(r.join("sparse.txt")).unwrap();
        let index_before = fs::read(r.join(".git/index")).unwrap();

        let rec = take(data.path(), r, "s", "t", "rm cfg.txt b.txt")
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(r.join(".git/index")).unwrap(), index_before);
        let show = |p: &str| git(r, &["show", &format!("{}:{p}", rec.commit)], None).unwrap();
        assert_eq!(show("cfg.txt"), "local cfg");
        assert_eq!(show("b.txt"), "local b");
        assert_eq!(
            show("sparse.txt"),
            "v1",
            "absent skip-worktree file keeps HEAD"
        );

        fs::remove_file(r.join("cfg.txt")).unwrap();
        fs::remove_file(r.join("b.txt")).unwrap();
        restore(data.path(), &rec, &[]).unwrap();
        assert_eq!(fs::read_to_string(r.join("cfg.txt")).unwrap(), "local cfg");
        assert_eq!(fs::read_to_string(r.join("b.txt")).unwrap(), "local b");
        assert!(
            !r.join("sparse.txt").exists(),
            "a full restore must not materialize sparse files"
        );

        // Naming a skip-worktree path restores it as well.
        fs::remove_file(r.join("cfg.txt")).unwrap();
        restore(data.path(), &rec, &["cfg.txt".into()]).unwrap();
        assert_eq!(fs::read_to_string(r.join("cfg.txt")).unwrap(), "local cfg");
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
