//! Pre-destructive workspace snapshots stored as git objects.
//!
//! A snapshot captures tracked and untracked (non-ignored) files using a
//! throwaway index, so the user's index, working tree, branches, and stash are
//! never touched. Each snapshot is pinned by `refs/brakeline/snapshots/<id>`.

use std::ffi::OsStr;
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
    /// Paths the snapshot could not include, each with the reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncovered: Vec<String>,
}

/// Runs git in `repo` and returns its raw stdout. `env` adds variables (such
/// as `GIT_DIR`), and `input` is written to stdin.
fn git_raw(
    repo: &Path,
    args: &[&str],
    index: Option<&Path>,
    env: &[(&str, &OsStr)],
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
    Ok(text(git_raw(repo, args, index, &[], None)?))
}

fn text(out: Vec<u8>) -> String {
    let mut text = String::from_utf8_lossy(&out).into_owned();
    if text.ends_with('\n') {
        text.pop();
    }
    text
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

/// How deep untracked repositories inside untracked repositories are followed.
const MAX_NESTED_DEPTH: usize = 8;

/// A work tree written as a git tree object.
struct Tree {
    id: String,
    /// Paths left out, each with the reason.
    uncovered: Vec<String>,
}

/// Collects a work tree into a temporary index, storing the files of
/// untracked nested repositories as ordinary files. `git add -A` alone would
/// fail on a nested repository with no commits and store only a commit link
/// (not the files) for one with commits. Registered submodules are tracked
/// in the index and stay commit links.
struct Walker<'a> {
    data_dir: &'a Path,
    /// The outer repository's git directory, which receives all objects.
    git_dir: PathBuf,
    uncovered: Vec<String>,
}

impl Walker<'_> {
    /// `git add -A` of everything under `dir` into `index`, except untracked
    /// nested repositories, which are walked separately and grafted in.
    /// `nested` is false for the outer repository itself.
    fn add_all(
        &mut self,
        dir: &Path,
        index: &Path,
        nested: bool,
        shown: &str,
        depth: usize,
    ) -> Result<()> {
        let git_dir = self.git_dir.clone();
        let fsmonitor_off = [
            ("GIT_DIR", git_dir.as_os_str()),
            ("GIT_WORK_TREE", dir.as_os_str()),
            // The outer repo's file-system monitor watches a different tree.
            ("GIT_CONFIG_COUNT", OsStr::new("1")),
            ("GIT_CONFIG_KEY_0", OsStr::new("core.fsmonitor")),
            ("GIT_CONFIG_VALUE_0", OsStr::new("false")),
        ];
        let env: &[(&str, &OsStr)] = if nested { &fsmonitor_off } else { &[] };
        let out = git_raw(
            dir,
            &["ls-files", "-o", "--exclude-standard", "-z"],
            Some(index),
            env,
            None,
        )?;
        // Untracked directories are listed file by file; a trailing slash
        // marks a directory git will not enter: a nested repository.
        let repos: Vec<&[u8]> = split_z(&out).filter_map(|r| r.strip_suffix(b"/")).collect();
        let mut spec = b".\0".to_vec();
        for repo in &repos {
            spec.extend_from_slice(b":(exclude,literal)");
            spec.extend_from_slice(repo);
            spec.push(0);
        }
        git_raw(
            dir,
            &["add", "-A", "--pathspec-from-file=-", "--pathspec-file-nul"],
            Some(index),
            env,
            Some(spec),
        )?;
        for repo in repos {
            let name = format!("{shown}{}", String::from_utf8_lossy(repo));
            if let Err(err) = self.graft(dir, index, env, repo, &name, depth) {
                self.uncovered.push(format!("{name}/: {err:#}"));
            }
        }
        Ok(())
    }

    /// Writes the nested repository at `dir/repo` as a tree and reads it
    /// into `index` under that path.
    fn graft(
        &mut self,
        dir: &Path,
        index: &Path,
        env: &[(&str, &OsStr)],
        repo: &[u8],
        name: &str,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_NESTED_DEPTH {
            bail!("nested git repositories go too deep");
        }
        let Ok(rel) = std::str::from_utf8(repo) else {
            bail!("path is not valid UTF-8");
        };
        let nested_dir = fs_path(dir, repo);
        let nested_index = temp_index(self.data_dir, "nested")?;
        self.add_all(
            &nested_dir,
            &nested_index.0,
            true,
            &format!("{name}/"),
            depth + 1,
        )?;
        let nested_env = [
            ("GIT_DIR", self.git_dir.as_os_str()),
            ("GIT_WORK_TREE", nested_dir.as_os_str()),
        ];
        let tree = text(git_raw(
            &nested_dir,
            &["write-tree"],
            Some(&nested_index.0),
            &nested_env,
            None,
        )?);
        git_raw(
            dir,
            &["read-tree", &format!("--prefix={rel}/"), &tree],
            Some(index),
            env,
            None,
        )?;
        Ok(())
    }
}

/// Writes the current work tree (tracked and untracked, minus ignored files)
/// as a git tree object, using a throwaway index.
fn worktree_tree(data_dir: &Path, root: &Path, tag: &str) -> Result<Tree> {
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
    let mut walker = Walker {
        data_dir,
        git_dir: PathBuf::from(git(root, &["rev-parse", "--absolute-git-dir"], None)?),
        uncovered: Vec::new(),
    };
    walker.add_all(root, &index.0, false, "", 0)?;
    Ok(Tree {
        id: git(root, &["write-tree"], Some(&index.0))?,
        uncovered: walker.uncovered,
    })
}

/// One file in a snapshot: its mode (`100644`, `120000`, `160000`, ...)
/// and its path relative to the repository root.
struct Entry {
    mode: Vec<u8>,
    path: Vec<u8>,
}

/// Lists the snapshot's files matching `paths` (all of them when empty),
/// with the same pathspec rules `git restore` uses. Fails when a given
/// pathspec matches nothing, before anything has been changed.
fn snapshot_entries(
    data_dir: &Path,
    repo: &Path,
    commit: &str,
    paths: &[String],
) -> Result<Vec<Entry>> {
    let index = temp_index(data_dir, "entries")?;
    git(repo, &["read-tree", commit], Some(&index.0))?;
    let mut args = vec!["ls-files", "-s", "-z"];
    if !paths.is_empty() {
        args.extend(["--error-unmatch", "--"]);
        args.extend(paths.iter().map(String::as_str));
    }
    let out = match git_raw(repo, &args, Some(&index.0), &[], None) {
        Ok(out) => out,
        Err(err) if err.to_string().contains("did not match") => {
            bail!("nothing in the snapshot matches: {}", paths.join(" "))
        }
        Err(err) => return Err(err),
    };
    Ok(split_z(&out)
        .filter_map(|rec| {
            let tab = rec.iter().position(|b| *b == b'\t')?;
            Some(Entry {
                mode: rec.split(|b| *b == b' ').next()?.to_vec(),
                path: rec[tab + 1..].to_vec(),
            })
        })
        .collect())
}

/// Paths where the snapshot and the work tree disagree on file versus
/// directory. `git restore --overlay` still replaces those, deleting the
/// whole directory, ignored files included, so they are refused unless forced.
fn type_conflicts(repo: &Path, entries: &[Entry]) -> Vec<String> {
    let mut conflicts = std::collections::BTreeSet::new();
    let mut parents = std::collections::BTreeSet::new();
    for entry in entries {
        let path = entry.path.as_slice();
        if entry.mode != b"160000"
            && fs::symlink_metadata(fs_path(repo, path)).is_ok_and(|m| m.is_dir())
        {
            conflicts.insert(format!(
                "{}/ (a directory now, a file in the snapshot)",
                String::from_utf8_lossy(path)
            ));
        }
        let mut end = path.len();
        while let Some(slash) = path[..end].iter().rposition(|b| *b == b'/') {
            if !parents.insert(&path[..slash]) {
                break;
            }
            end = slash;
        }
    }
    for parent in parents {
        if fs::symlink_metadata(fs_path(repo, parent)).is_ok_and(|m| !m.is_dir()) {
            conflicts.insert(format!(
                "{} (a file now, a directory in the snapshot)",
                String::from_utf8_lossy(parent)
            ));
        }
    }
    conflicts.into_iter().collect()
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
    let Tree {
        id: tree,
        uncovered,
    } = worktree_tree(data_dir, &root, &id)?;

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
        uncovered,
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

/// What restoring a snapshot would do.
pub struct Preview {
    /// `git diff --stat` of the files restoring would add or change.
    pub diff: String,
    /// Paths that are a file on one side and a directory on the other.
    pub conflicts: Vec<String>,
}

/// Files restoring `paths` (or everything) would add or change, compared
/// with the whole current work tree including untracked files. Deletions are
/// omitted: restore keeps them.
pub fn preview(data_dir: &Path, record: &SnapshotRecord, paths: &[String]) -> Result<Preview> {
    let repo = Path::new(&record.repo);
    // Validates the paths too, with the same error restore would give.
    let entries = snapshot_entries(data_dir, repo, &record.commit, paths)?;
    let current = worktree_tree(data_dir, repo, "preview")?.id;
    let mut args = vec![
        "diff",
        "--stat",
        "--diff-filter=AMT",
        current.as_str(),
        record.commit.as_str(),
        "--",
    ];
    args.extend(paths.iter().map(String::as_str));
    Ok(Preview {
        diff: git(repo, &args, None)?,
        conflicts: type_conflicts(repo, &entries),
    })
}

/// Writes the snapshot's version of `paths` (or everything) back into the
/// work tree. Files created after the snapshot are kept, and the current
/// state is snapshotted first so the restore itself can be undone. Paths that
/// changed between file and directory are refused unless `force`.
pub fn restore(
    data_dir: &Path,
    record: &SnapshotRecord,
    paths: &[String],
    force: bool,
) -> Result<Option<SnapshotRecord>> {
    let repo = Path::new(&record.repo);
    git(
        repo,
        &["cat-file", "-e", &format!("{}^{{commit}}", record.commit)],
        None,
    )
    .context("snapshot commit is missing (was it pruned?)")?;
    let entries = snapshot_entries(data_dir, repo, &record.commit, paths)?;
    let conflicts = type_conflicts(repo, &entries);
    if !conflicts.is_empty() && !force {
        bail!(
            "restoring would replace these paths and delete everything in them, ignored files included:\n  {}\nMove them aside, restore other paths, or re-run with --force.",
            conflicts.join("\n  ")
        );
    }
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
            &[("GIT_LITERAL_PATHSPECS", OsStr::new("1"))],
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
        let shown = preview(data.path(), &found, &[]).unwrap();
        assert!(shown.diff.contains("tracked.txt"), "{}", shown.diff);
        assert!(
            shown.diff.contains("new.txt"),
            "untracked files must be previewed: {}",
            shown.diff
        );
        assert!(shown.conflicts.is_empty());
        let backup = restore(data.path(), &found, &[], false).unwrap();
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
        restore(data.path(), &rec, &["a.txt".into()], false).unwrap();
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
        restore(data.path(), &rec, &[], false).unwrap();
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
        restore(data.path(), &rec, &[], false).unwrap();
        assert_eq!(fs::read_to_string(r.join("cfg.txt")).unwrap(), "local cfg");
        assert_eq!(fs::read_to_string(r.join("b.txt")).unwrap(), "local b");
        assert!(
            !r.join("sparse.txt").exists(),
            "a full restore must not materialize sparse files"
        );

        // Naming a skip-worktree path restores it as well.
        fs::remove_file(r.join("cfg.txt")).unwrap();
        restore(data.path(), &rec, &["cfg.txt".into()], false).unwrap();
        assert_eq!(fs::read_to_string(r.join("cfg.txt")).unwrap(), "local cfg");
    }

    #[test]
    fn untracked_nested_repositories_are_snapshotted_as_plain_files() {
        let repo = committed_repo(&[("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        // A nested repo with no commits (git add -A fails on it)...
        let empty = r.join("vendor/lib");
        fs::create_dir_all(&empty).unwrap();
        sh(&empty, &["init", "-q"]);
        fs::write(empty.join("x.txt"), "x").unwrap();
        // ...and one with commits (git add -A stores only a gitlink), with its
        // own ignore rules and a repo nested inside it.
        let dep = r.join("vendor/dep");
        fs::create_dir_all(&dep).unwrap();
        sh(&dep, &["init", "-q"]);
        fs::write(dep.join("y.txt"), "y").unwrap();
        fs::write(dep.join(".gitignore"), "*.log\n").unwrap();
        sh(&dep, &["add", "-A"]);
        sh(&dep, &["commit", "-q", "-m", "dep"]);
        fs::write(dep.join("y.txt"), "y edited").unwrap();
        fs::write(dep.join("debug.log"), "noise").unwrap();
        let inner = dep.join("inner");
        fs::create_dir_all(&inner).unwrap();
        sh(&inner, &["init", "-q"]);
        fs::write(inner.join("w.txt"), "w").unwrap();

        let rec = take(data.path(), r, "s", "t", "rm -rf vendor")
            .unwrap()
            .unwrap();
        assert!(rec.uncovered.is_empty(), "{:?}", rec.uncovered);
        let mode = |p: &str| {
            git(r, &["ls-tree", &rec.commit, "--", p], None)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .to_string()
        };
        assert_eq!(mode("vendor/dep/y.txt"), "100644");
        assert_eq!(
            mode("vendor/dep/debug.log"),
            "",
            "nested ignore rules apply"
        );

        fs::remove_dir_all(r.join("vendor")).unwrap();
        restore(data.path(), &rec, &[], false).unwrap();
        assert_eq!(fs::read_to_string(empty.join("x.txt")).unwrap(), "x");
        assert_eq!(fs::read_to_string(dep.join("y.txt")).unwrap(), "y edited");
        assert_eq!(fs::read_to_string(inner.join("w.txt")).unwrap(), "w");
        assert_eq!(fs::read_to_string(r.join("a.txt")).unwrap(), "a");
    }

    #[test]
    fn restore_refuses_to_replace_a_directory_or_file_of_the_other_type() {
        let repo = committed_repo(&[("foo", "file"), ("d/a.txt", "a"), (".gitignore", "*.log\n")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        fs::write(r.join("keep.txt"), "k").unwrap();
        let rec = take(data.path(), r, "s", "t", "rm foo").unwrap().unwrap();

        // foo becomes a directory holding an ignored file; d becomes a file.
        fs::remove_file(r.join("foo")).unwrap();
        fs::create_dir(r.join("foo")).unwrap();
        fs::write(r.join("foo/new.txt"), "new").unwrap();
        fs::write(r.join("foo/x.log"), "ignored but precious").unwrap();
        fs::remove_dir_all(r.join("d")).unwrap();
        fs::write(r.join("d"), "now a file").unwrap();
        fs::remove_file(r.join("keep.txt")).unwrap();

        let shown = preview(data.path(), &rec, &[]).unwrap();
        assert_eq!(shown.conflicts.len(), 2, "{:?}", shown.conflicts);
        assert!(
            shown.conflicts[0].starts_with("d "),
            "{:?}",
            shown.conflicts
        );
        assert!(
            shown.conflicts[1].starts_with("foo/ "),
            "{:?}",
            shown.conflicts
        );

        let before = list(data.path()).unwrap().len();
        let err = restore(data.path(), &rec, &[], false).unwrap_err();
        assert!(format!("{err:#}").contains("foo/"), "{err:#}");
        assert_eq!(
            list(data.path()).unwrap().len(),
            before,
            "no backup on refusal"
        );
        assert!(!r.join("keep.txt").exists(), "nothing written on refusal");
        assert_eq!(
            fs::read_to_string(r.join("foo/x.log")).unwrap(),
            "ignored but precious"
        );

        // Paths away from the conflicts restore normally.
        restore(data.path(), &rec, &["keep.txt".into()], false).unwrap();
        assert_eq!(fs::read_to_string(r.join("keep.txt")).unwrap(), "k");

        restore(data.path(), &rec, &[], true).unwrap();
        assert_eq!(fs::read_to_string(r.join("foo")).unwrap(), "file");
        assert_eq!(fs::read_to_string(r.join("d/a.txt")).unwrap(), "a");
    }

    #[test]
    fn preview_and_restore_respect_paths_and_fail_before_any_backup() {
        let repo = committed_repo(&[("a.txt", "a"), ("b.txt", "b")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        let rec = take(data.path(), r, "s", "t", "rm").unwrap().unwrap();
        fs::remove_file(r.join("a.txt")).unwrap();
        fs::remove_file(r.join("b.txt")).unwrap();

        let shown = preview(data.path(), &rec, &["a.txt".into()]).unwrap();
        assert!(shown.diff.contains("a.txt"), "{}", shown.diff);
        assert!(!shown.diff.contains("b.txt"), "{}", shown.diff);

        let before = list(data.path()).unwrap().len();
        let err = restore(data.path(), &rec, &["nope.txt".into()], false).unwrap_err();
        assert!(format!("{err:#}").contains("nope.txt"), "{err:#}");
        assert!(preview(data.path(), &rec, &["nope.txt".into()]).is_err());
        assert_eq!(
            list(data.path()).unwrap().len(),
            before,
            "no backup on failure"
        );
        assert!(!r.join("a.txt").exists());
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
