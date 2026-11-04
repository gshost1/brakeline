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

impl SnapshotRecord {
    /// A one-line summary of the paths the snapshot left out, if any:
    /// `not covered: a/, b/ (+2 more)`.
    pub fn uncovered_note(&self) -> Option<String> {
        const SHOWN: usize = 3;
        if self.uncovered.is_empty() {
            return None;
        }
        // Entries read `path/: reason`; the path alone is enough here.
        let names: Vec<&str> = self
            .uncovered
            .iter()
            .take(SHOWN)
            .map(|u| u.split_once("/: ").map_or(u.as_str(), |(p, _)| p))
            .collect();
        let mut note = format!("not covered: {}/", names.join("/, "));
        if self.uncovered.len() > SHOWN {
            note.push_str(&format!(" (+{} more)", self.uncovered.len() - SHOWN));
        }
        Some(note)
    }
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
    let out = git_output(repo, args, index, env, input)?;
    if !out.status.success() {
        // Name the subcommand, skipping `-c key=value` options before it.
        let mut rest = args;
        while let ["-c", _, tail @ ..] = rest {
            rest = tail;
        }
        bail!(
            "git {} failed: {}",
            rest.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// Like [`git_raw`] but returns the output whatever the exit status.
fn git_output(
    repo: &Path,
    args: &[&str],
    index: Option<&Path>,
    env: &[(&str, &OsStr)],
    input: Option<Vec<u8>>,
) -> Result<std::process::Output> {
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
    Ok(out)
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

/// Whether `rel`, a path read from a nested repository (whose index may be
/// hand-crafted), names something inside `dir`: relative, with no empty,
/// `.` or `..` component, and no symbolic link among its leading components
/// on disk. Git refuses to add such paths itself, but only after it has
/// read through them.
fn safe_rel(dir: &Path, rel: &[u8]) -> bool {
    if rel.is_empty() || rel.starts_with(b"/") {
        return false;
    }
    let parts: Vec<&[u8]> = rel.split(|b| *b == b'/').collect();
    if parts.iter().any(|p| {
        p.is_empty() || *p == b"." || *p == b".." || (cfg!(not(unix)) && p.contains(&b'\\'))
    }) {
        return false;
    }
    let mut at = dir.to_path_buf();
    for part in &parts[..parts.len() - 1] {
        at = fs_path(&at, part);
        // A missing component is fine: nothing will be found under it.
        if fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            return false;
        }
    }
    true
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

/// How much of untracked nested repositories one snapshot will hash. They
/// are rehashed on every snapshot (their objects live in another
/// repository), so a large clone would otherwise stall every destructive
/// command; beyond this they are recorded as not covered.
#[derive(Clone, Copy)]
struct Limits {
    files: usize,
    bytes: u64,
}

const NESTED_LIMITS: Limits = Limits {
    files: 10_000,
    bytes: 64 * 1024 * 1024,
};

/// A path left out of a snapshot, with the reason.
struct Uncovered {
    /// Directory path relative to the repository root, without a trailing slash.
    path: String,
    reason: String,
    /// Nothing under `path` was stored. False when only some entries of the
    /// nested repository at `path` were left out.
    whole: bool,
}

impl std::fmt::Display for Uncovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/: {}", self.path, self.reason)
    }
}

/// A work tree written as a git tree object.
struct Tree {
    id: String,
    uncovered: Vec<Uncovered>,
}

/// Collects a work tree into a temporary index, storing the files of
/// untracked nested repositories as ordinary files. `git add -A` alone would
/// fail on a nested repository with no commits and store only a commit link
/// (not the files) for one with commits. Registered submodules are tracked
/// in the index and stay commit links.
struct Walker<'a> {
    data_dir: &'a Path,
    /// The outer repository's work tree; its ignore rules apply everywhere.
    root: &'a Path,
    /// The outer repository's git directory, which receives all objects.
    git_dir: PathBuf,
    uncovered: Vec<Uncovered>,
    limits: Limits,
    /// Files and bytes hashed from nested repositories so far.
    files: usize,
    bytes: u64,
}

/// A file or repository found inside a nested repository.
struct Found {
    path: Vec<u8>,
    /// In the nested repository's own index.
    tracked: bool,
    /// An untracked nested repository (or a checked-out submodule).
    repo: bool,
    len: u64,
}

/// The git directory of the repository at `dir`, following a `.git` file.
fn nested_git_dir(dir: &Path) -> Option<PathBuf> {
    let dot = dir.join(".git");
    if fs::metadata(&dot).ok()?.is_dir() {
        return Some(dot);
    }
    let text = fs::read_to_string(&dot).ok()?;
    let target = text
        .strip_prefix("gitdir:")?
        .trim_start()
        .trim_end_matches(['\n', '\r']);
    let target = PathBuf::from(target);
    Some(if target.is_absolute() {
        target
    } else {
        dir.join(target)
    })
}

impl Walker<'_> {
    /// Adds the outer repository's work tree to `index`, a copy of its real
    /// index: tracked changes with `git add -u`, untracked files from a single
    /// directory walk, and untracked nested repositories through [`graft`].
    fn add_outer(&mut self, index: &Path) -> Result<()> {
        let root = self.root;
        let out = git_raw(
            root,
            &["ls-files", "-o", "--exclude-standard", "-z"],
            Some(index),
            &[],
            None,
        )?;
        // Untracked directories are listed file by file; a trailing slash
        // marks a directory git will not enter: a nested repository.
        let (repos, files): (Vec<&[u8]>, Vec<&[u8]>) =
            split_z(&out).partition(|r| r.ends_with(b"/"));
        git_raw(root, &["add", "-u"], Some(index), &[], None)?;
        if !files.is_empty() {
            git_raw(
                root,
                &["update-index", "--add", "-z", "--stdin"],
                Some(index),
                &[],
                Some(join_z(files)),
            )?;
        }
        for repo in repos {
            let repo = &repo[..repo.len() - 1];
            self.graft(root, index, &[], repo, "", 0);
        }
        Ok(())
    }

    /// Runs git on the nested work tree `dir` with the outer repository's git
    /// directory and config, never the nested repository's own config (it
    /// may come from anywhere). The outer repository's file-system monitor
    /// watches a different tree, so it is turned off.
    fn nested_git(
        &self,
        dir: &Path,
        args: &[&str],
        index: &Path,
        input: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut full = vec!["-c", "core.fsmonitor=false"];
        full.extend_from_slice(args);
        git_raw(
            dir,
            &full,
            Some(index),
            &[
                ("GIT_DIR", self.git_dir.as_os_str()),
                ("GIT_WORK_TREE", dir.as_os_str()),
            ],
            input,
        )
    }

    /// Grafts the nested repository at `dir/repo` into `index` as plain
    /// files, or records it as not covered. `env` is what git needs to work
    /// on `index` (empty for the outer repository). `shown` is `dir`
    /// relative to the outer repository root, with a trailing slash.
    fn graft(
        &mut self,
        dir: &Path,
        index: &Path,
        env: &[(&str, &OsStr)],
        repo: &[u8],
        shown: &str,
        depth: usize,
    ) {
        let name = format!("{shown}{}", String::from_utf8_lossy(repo));
        let result = (|| {
            let Ok(rel) = std::str::from_utf8(repo) else {
                bail!("path is not valid UTF-8");
            };
            let tree = self.nested_tree(&fs_path(dir, repo), &name, depth)?;
            git_raw(
                dir,
                &["read-tree", &format!("--prefix={rel}/"), &tree],
                Some(index),
                env,
                None,
            )?;
            Ok(())
        })();
        if let Err(err) = result {
            self.uncovered.push(Uncovered {
                path: name,
                reason: format!("{err:#}"),
                whole: true,
            });
        }
    }

    /// Writes the nested repository at `dir` (shown as `name`) as a tree:
    /// the files its own index tracks plus its untracked files that its own
    /// ignore rules keep, minus anything the outer repository's rules
    /// ignore.
    fn nested_tree(&mut self, dir: &Path, name: &str, depth: usize) -> Result<String> {
        if depth >= MAX_NESTED_DEPTH {
            bail!("nested git repositories go too deep");
        }
        self.check_inside(dir)?;
        let found = self.nested_files(dir, name)?;
        let (repos, files): (Vec<Found>, Vec<Found>) = found.into_iter().partition(|f| f.repo);
        let bytes: u64 = files.iter().map(|f| f.len).sum();
        if self.files + files.len() > self.limits.files || self.bytes + bytes > self.limits.bytes {
            bail!(
                "too large to snapshot ({} files, {} MiB; nested repositories are limited to {} files and {} MiB per snapshot)",
                files.len(),
                bytes.div_ceil(1024 * 1024),
                self.limits.files,
                self.limits.bytes / (1024 * 1024)
            );
        }
        self.files += files.len();
        self.bytes += bytes;

        let index = temp_index(self.data_dir, "nested")?;
        if !files.is_empty() {
            self.nested_git(
                dir,
                &["update-index", "--add", "-z", "--stdin"],
                &index.0,
                Some(join_z(files.iter().map(|f| f.path.as_slice()))),
            )?;
        }
        let git_dir = self.git_dir.clone();
        let env = [
            ("GIT_DIR", git_dir.as_os_str()),
            ("GIT_WORK_TREE", dir.as_os_str()),
        ];
        for repo in &repos {
            self.graft(
                dir,
                &index.0,
                &env,
                &repo.path,
                &format!("{name}/"),
                depth + 1,
            );
        }
        Ok(text(self.nested_git(
            dir,
            &["write-tree"],
            &index.0,
            None,
        )?))
    }

    /// Fails unless `dir` is inside the outer work tree with no symbolic
    /// link on the way, so git is never pointed at a work tree elsewhere.
    fn check_inside(&self, dir: &Path) -> Result<()> {
        let rel = dir
            .strip_prefix(self.root)
            .ok()
            .filter(|rel| !rel.as_os_str().is_empty())
            .context("unsafe path: outside the repository")?;
        let mut at = self.root.to_path_buf();
        for part in rel.components() {
            let std::path::Component::Normal(part) = part else {
                bail!("unsafe path: outside the repository");
            };
            at.push(part);
            let meta = fs::symlink_metadata(&at).context("unsafe path")?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                bail!("unsafe path: through a symbolic link");
            }
        }
        let (root, dir) = (fs::canonicalize(self.root)?, fs::canonicalize(dir)?);
        if dir == root || !dir.starts_with(&root) {
            bail!("unsafe path: outside the repository");
        }
        Ok(())
    }

    /// What [`nested_tree`] stores for the repository at `dir`. Entries
    /// that would reach outside it are left out and recorded.
    fn nested_files(&mut self, dir: &Path, name: &str) -> Result<Vec<Found>> {
        let own = nested_git_dir(dir);
        // Its index is only read (optional locks are off); a missing one
        // reads as empty.
        let index = match &own {
            Some(d) => d.join("index"),
            None => temp_index(self.data_dir, "none")?.0.clone(),
        };
        let exclude = own
            .as_ref()
            .map(|d| d.join("info/exclude"))
            .filter(|p| p.is_file())
            .map(|p| format!("--exclude-from={}", p.display()));
        let mut args = vec![
            "ls-files",
            "-t",
            "-z",
            "--cached",
            "--others",
            "--exclude-per-directory=.gitignore",
        ];
        if let Some(e) = &exclude {
            args.push(e);
        }
        let out = self.nested_git(dir, &args, &index, None)?;
        let mut found = Vec::new();
        for rec in split_z(&out) {
            let (Some(&tag), Some(path)) = (rec.first(), rec.get(2..)) else {
                continue;
            };
            let tracked = tag != b'?';
            let rel = path.strip_suffix(b"/").unwrap_or(path);
            if !safe_rel(dir, rel) {
                self.uncovered.push(Uncovered {
                    path: name.to_string(),
                    reason: format!(
                        "unsafe path {:?} in its index left out",
                        String::from_utf8_lossy(path)
                    ),
                    whole: false,
                });
                continue;
            }
            if let Some(repo) = path.strip_suffix(b"/") {
                // Only a directory holding a repository on disk is one; an
                // index entry can claim the trailing slash for anything.
                if fs::symlink_metadata(fs_path(dir, repo).join(".git")).is_err() {
                    continue;
                }
                found.push(Found {
                    path: repo.to_vec(),
                    tracked,
                    repo: true,
                    len: 0,
                });
                continue;
            }
            // Tracked but deleted: nothing to store.
            let Ok(meta) = fs::symlink_metadata(fs_path(dir, path)) else {
                continue;
            };
            if meta.is_dir() {
                // A submodule of the nested repository.
                if fs_path(dir, path).join(".git").exists() {
                    found.push(Found {
                        path: path.to_vec(),
                        tracked,
                        repo: true,
                        len: 0,
                    });
                }
                continue;
            }
            found.push(Found {
                path: path.to_vec(),
                tracked,
                repo: false,
                len: meta.len(),
            });
        }
        let ignored = self.outer_ignored(name, &found)?;
        Ok(found
            .into_iter()
            .zip(ignored)
            .filter(|(_, ignored)| !ignored)
            .map(|(f, _)| f)
            .collect())
    }

    /// For each of `found` inside the nested repository `name`, whether the
    /// rules of the repositories around it ignore it, as if it were a plain
    /// directory. `git check-ignore` from the outer root also reads the
    /// nested repository's own `.gitignore` files; a match from those only
    /// counts against untracked files (its tracked ones were kept on purpose).
    fn outer_ignored(&self, name: &str, found: &[Found]) -> Result<Vec<bool>> {
        if found.is_empty() {
            return Ok(Vec::new());
        }
        let mut query = Vec::new();
        for f in found {
            query.extend_from_slice(name.as_bytes());
            query.push(b'/');
            query.extend_from_slice(&f.path);
            if f.repo {
                query.push(b'/');
            }
            query.push(0);
        }
        let out = git_output(
            self.root,
            &["check-ignore", "-v", "-n", "-z", "--no-index", "--stdin"],
            None,
            // Paths from stdin are taken literally (no pathspec magic).
            &[],
            Some(query),
        )?;
        // Exit 1 means nothing matched.
        if !matches!(out.status.code(), Some(0 | 1)) {
            bail!(
                "git check-ignore failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        // Records of four fields (source, line, pattern, path), one per path;
        // empty fields when nothing matched.
        let fields: Vec<&[u8]> = out.stdout.split(|b| *b == 0).collect();
        let records: Vec<&[&[u8]]> = fields.chunks_exact(4).collect();
        if records.len() != found.len() {
            bail!("unexpected git check-ignore output");
        }
        let own = format!("{name}/");
        Ok(records
            .iter()
            .zip(found)
            .map(|(rec, f)| {
                let (source, pattern) = (rec[0], rec[2]);
                let ignored = !source.is_empty() && !pattern.starts_with(b"!");
                ignored && !(f.tracked && source.starts_with(own.as_bytes()))
            })
            .collect())
    }
}

/// Writes the current work tree (tracked and untracked, minus ignored files)
/// as a git tree object, using a throwaway index.
fn worktree_tree(data_dir: &Path, root: &Path, tag: &str) -> Result<Tree> {
    worktree_tree_limited(data_dir, root, tag, NESTED_LIMITS)
}

fn worktree_tree_limited(data_dir: &Path, root: &Path, tag: &str, limits: Limits) -> Result<Tree> {
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
        root,
        git_dir: PathBuf::from(git(root, &["rev-parse", "--absolute-git-dir"], None)?),
        uncovered: Vec::new(),
        limits,
        files: 0,
        bytes: 0,
    };
    walker.add_outer(&index.0)?;
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
    let out = git_output(repo, &args, Some(&index.0), &[], None)?;
    // --error-unmatch exits 1 for a pathspec that matches nothing; other
    // failures exit 128. The status works in any locale, unlike the message.
    match out.status.code() {
        Some(0) => {}
        Some(1) if !paths.is_empty() => {
            bail!("nothing in the snapshot matches: {}", paths.join(" "))
        }
        _ => bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
    let out = out.stdout;
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

/// The skip-worktree files among `skip` that held local work when the
/// snapshot was taken: their snapshot content differs from the commit it was
/// taken on. The others are sparse-checkout files whose index entry may
/// simply have moved on with HEAD; writing the snapshot's version would put
/// stale files on disk.
fn skip_worktree_to_restore(
    repo: &Path,
    record: &SnapshotRecord,
    entries: &[Entry],
    skip: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    if skip.is_empty() {
        return Ok(Vec::new());
    }
    // A snapshot with no local work reuses HEAD's commit instead of making one.
    let subject = git(repo, &["show", "-s", "--format=%s", &record.commit], None)?;
    if subject != format!("brakeline snapshot {}", record.id) {
        return Ok(Vec::new());
    }
    let parent = format!("{}^1", record.commit);
    let changed: Option<std::collections::HashSet<Vec<u8>>> =
        match git(repo, &["rev-parse", "-q", "--verify", &parent], None) {
            Ok(_) => Some(
                split_z(&git_raw(
                    repo,
                    &[
                        "diff-tree",
                        "-r",
                        "--no-renames",
                        "--name-only",
                        "-z",
                        &parent,
                        &record.commit,
                        "--",
                    ],
                    None,
                    &[],
                    None,
                )?)
                .map(<[u8]>::to_vec)
                .collect(),
            ),
            // Taken before the first commit: everything in it was local work.
            Err(_) => None,
        };
    let in_snapshot: std::collections::HashSet<&[u8]> =
        entries.iter().map(|e| e.path.as_slice()).collect();
    Ok(skip
        .iter()
        .filter(|p| in_snapshot.contains(p.as_slice()))
        .filter(|p| changed.as_ref().is_none_or(|c| c.contains(*p)))
        .cloned()
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
    let uncovered = uncovered.iter().map(ToString::to_string).collect();

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
    /// Parts of the current work tree that could not be read, each with the
    /// reason. They are left out of `diff` rather than shown as changes.
    pub uncovered: Vec<String>,
}

/// Files restoring `paths` (or everything) would add or change, compared
/// with the whole current work tree including untracked files. Deletions are
/// omitted: restore keeps them.
pub fn preview(data_dir: &Path, record: &SnapshotRecord, paths: &[String]) -> Result<Preview> {
    let repo = Path::new(&record.repo);
    // Validates the paths too, with the same error restore would give.
    let entries = snapshot_entries(data_dir, repo, &record.commit, paths)?;
    let current = worktree_tree(data_dir, repo, "preview")?;
    let excludes: Vec<String> = current
        .uncovered
        .iter()
        .filter(|u| u.whole)
        .map(|u| format!(":(exclude,literal){}", u.path))
        .collect();
    let mut args = vec![
        "diff",
        "--stat",
        "--diff-filter=AMT",
        current.id.as_str(),
        record.commit.as_str(),
        "--",
    ];
    args.extend(paths.iter().map(String::as_str));
    args.extend(excludes.iter().map(String::as_str));
    let diff = git(repo, &args, None)?;
    Ok(Preview {
        diff,
        conflicts: type_conflicts(repo, &entries),
        uncovered: current.uncovered.iter().map(ToString::to_string).collect(),
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
    // `git restore -- .` writes a skip-worktree file whose index entry
    // differs from the snapshot (it replaces the entry, dropping the flag).
    // Those are kept out of a whole-tree restore, and the ones holding local
    // work are restored separately.
    let skip = if paths.is_empty() {
        flagged_paths(repo, None)?.skip_worktree
    } else {
        Vec::new()
    };
    let sparse_work = skip_worktree_to_restore(repo, record, &entries, &skip)?;
    let differs: Vec<Vec<u8>> = if skip.is_empty() {
        Vec::new()
    } else {
        let out = git_raw(
            repo,
            &[
                "diff-index",
                "--cached",
                "--name-only",
                "-z",
                &record.commit,
                "--",
            ],
            None,
            &[],
            None,
        )?;
        let changed: std::collections::HashSet<&[u8]> = split_z(&out).collect();
        skip.iter()
            .filter(|p| changed.contains(p.as_slice()))
            .cloned()
            .collect()
    };
    let backup = take(
        data_dir,
        repo,
        &record.session_id,
        "before restore",
        &format!("brakeline restore {}", record.id),
    )?;
    let source = format!("--source={}", record.commit);
    if paths.is_empty() {
        let skip_set: std::collections::HashSet<&[u8]> = skip.iter().map(Vec::as_slice).collect();
        // git restore fails when the pathspec matches nothing, and it does
        // not match skip-worktree entries.
        let rest = entries
            .iter()
            .any(|e| !skip_set.contains(e.path.as_slice()));
        let mut spec = b".\0".to_vec();
        for p in &differs {
            spec.extend_from_slice(b":(exclude,literal)");
            spec.extend_from_slice(p);
            spec.push(0);
        }
        if rest {
            git_raw(
                repo,
                &[
                    "restore",
                    source.as_str(),
                    "--worktree",
                    "--overlay",
                    "--pathspec-from-file=-",
                    "--pathspec-file-nul",
                ],
                None,
                &[],
                Some(spec),
            )?;
        }
    } else {
        // Paths the user names are restored even if flagged skip-worktree.
        let mut args = vec![
            "restore",
            source.as_str(),
            "--worktree",
            "--overlay",
            "--ignore-skip-worktree-bits",
            "--",
        ];
        args.extend(paths.iter().map(String::as_str));
        git(repo, &args, None)?;
    }
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

    fn in_tree(repo: &Path, commit: &str, path: &str) -> bool {
        !git(repo, &["ls-tree", commit, "--", path], None)
            .unwrap()
            .is_empty()
    }

    #[test]
    fn nested_repositories_follow_outer_ignore_rules_and_keep_their_tracked_files() {
        let repo = committed_repo(&[(".gitignore", ".env\nsecret/\nsub/skipped/\n")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        let sub = r.join("sub");
        fs::create_dir_all(sub.join("secret")).unwrap();
        sh(&sub, &["init", "-q"]);
        fs::write(sub.join(".gitignore"), "*.log\n").unwrap();
        fs::write(sub.join("forced.log"), "kept on purpose").unwrap();
        fs::write(sub.join("gone.txt"), "deleted later").unwrap();
        sh(&sub, &["add", "-f", ".gitignore", "forced.log", "gone.txt"]);
        sh(&sub, &["commit", "-q", "-m", "sub"]);
        fs::remove_file(sub.join("gone.txt")).unwrap();
        fs::write(sub.join("debug.log"), "noise").unwrap();
        fs::write(sub.join(".env"), "TOKEN=hunter2").unwrap();
        fs::write(sub.join("secret/key"), "k").unwrap();
        fs::write(sub.join("a.txt"), "a").unwrap();
        // A repository inside the nested one that the outer rules ignore.
        let skipped = sub.join("skipped");
        fs::create_dir_all(&skipped).unwrap();
        sh(&skipped, &["init", "-q"]);
        fs::write(skipped.join("s.txt"), "s").unwrap();

        let rec = take(data.path(), r, "s", "t", "rm -rf sub")
            .unwrap()
            .unwrap();
        assert!(rec.uncovered.is_empty(), "{:?}", rec.uncovered);
        assert!(in_tree(r, &rec.commit, "sub/a.txt"));
        assert!(in_tree(r, &rec.commit, "sub/forced.log"), "tracked by sub");
        assert!(!in_tree(r, &rec.commit, "sub/debug.log"), "sub's own rules");
        assert!(!in_tree(r, &rec.commit, "sub/.env"), "outer rules apply");
        assert!(
            !in_tree(r, &rec.commit, "sub/secret/key"),
            "outer rules apply"
        );
        assert!(!in_tree(r, &rec.commit, "sub/skipped/s.txt"));
        assert!(!in_tree(r, &rec.commit, "sub/gone.txt"));
    }

    #[test]
    fn nested_repositories_beyond_the_limits_are_recorded_not_hashed() {
        let repo = committed_repo(&[("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        for (name, files) in [("big", 3), ("small", 1), ("wide", 1)] {
            let d = r.join(name);
            fs::create_dir(&d).unwrap();
            sh(&d, &["init", "-q"]);
            for i in 0..files {
                fs::write(d.join(format!("f{i}.txt")), "x").unwrap();
            }
        }
        fs::write(r.join("wide/f0.txt"), vec![b'x'; 2048]).unwrap();
        let limits = Limits {
            files: 2,
            bytes: 1024,
        };
        let tree = worktree_tree_limited(data.path(), r, "t", limits).unwrap();
        let paths: Vec<&str> = tree.uncovered.iter().map(|u| u.path.as_str()).collect();
        assert_eq!(paths, ["big", "wide"]);
        assert!(
            tree.uncovered[0].reason.contains("too large"),
            "{}",
            tree.uncovered[0]
        );
        let listed = git(r, &["ls-tree", "-r", "--name-only", &tree.id], None).unwrap();
        assert_eq!(listed, "a.txt\nsmall/f0.txt");
    }

    #[test]
    fn whole_restore_leaves_sparse_files_alone_after_head_moves() {
        let repo = committed_repo(&[("cfg.txt", "v1"), ("out.txt", "v1"), ("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        sh(
            r,
            &["update-index", "--skip-worktree", "cfg.txt", "out.txt"],
        );
        fs::remove_file(r.join("out.txt")).unwrap();
        // Moves HEAD to a new out.txt without writing it to disk, as a pull
        // in a sparse checkout does.
        let advance = |body: &str| {
            let blob = text(
                git_raw(
                    r,
                    &["hash-object", "-w", "--stdin"],
                    None,
                    &[],
                    Some(body.as_bytes().to_vec()),
                )
                .unwrap(),
            );
            sh(
                r,
                &[
                    "update-index",
                    "--cacheinfo",
                    &format!("100644,{blob},out.txt"),
                ],
            );
            sh(r, &["update-index", "--skip-worktree", "out.txt"]);
            sh(r, &["commit", "-q", "-m", body]);
        };
        advance("v2");
        // No local work: the snapshot reuses HEAD, whose own commit changed out.txt.
        let clean = take(data.path(), r, "s", "t", "rm").unwrap().unwrap();
        fs::write(r.join("cfg.txt"), "local cfg").unwrap();
        let rec = take(data.path(), r, "s", "t", "rm").unwrap().unwrap();
        advance("v3");

        fs::remove_file(r.join("cfg.txt")).unwrap();
        restore(data.path(), &rec, &[], false).unwrap();
        assert_eq!(fs::read_to_string(r.join("cfg.txt")).unwrap(), "local cfg");
        assert!(
            !r.join("out.txt").exists(),
            "stale out-of-cone file written"
        );

        fs::remove_file(r.join("cfg.txt")).unwrap();
        restore(data.path(), &clean, &[], false).unwrap();
        assert!(
            !r.join("out.txt").exists(),
            "stale out-of-cone file written"
        );

        // Named explicitly, it is restored.
        restore(data.path(), &rec, &["out.txt".into()], false).unwrap();
        assert_eq!(fs::read_to_string(r.join("out.txt")).unwrap(), "v2");

        // A snapshot holding nothing but sparse files restores as a no-op.
        let only = committed_repo(&[("s.txt", "v1")]);
        let o = only.path();
        sh(o, &["update-index", "--skip-worktree", "s.txt"]);
        fs::remove_file(o.join("s.txt")).unwrap();
        let rec = take(data.path(), o, "s", "t", "rm").unwrap().unwrap();
        restore(data.path(), &rec, &[], false).unwrap();
        assert!(!o.join("s.txt").exists());
    }

    #[test]
    fn preview_lists_uncovered_repositories_instead_of_reporting_them_as_changes() {
        let repo = committed_repo(&[("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        let mut deep = r.to_path_buf();
        let mut dirs = Vec::new();
        for i in 0..=MAX_NESTED_DEPTH {
            deep = deep.join(format!("d{i}"));
            dirs.push(deep.clone());
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("f.txt"), "f").unwrap();
        let rec = take(data.path(), r, "s", "t", "rm").unwrap().unwrap();
        // Now each directory is a repository: the deepest is out of reach.
        for d in &dirs {
            sh(d, &["init", "-q"]);
        }
        let shown = preview(data.path(), &rec, &[]).unwrap();
        assert!(!shown.diff.contains("f.txt"), "{}", shown.diff);
        assert_eq!(shown.uncovered.len(), 1, "{:?}", shown.uncovered);
        assert!(shown.uncovered[0].contains("d8/"), "{:?}", shown.uncovered);
    }

    /// Re-runs the test `name` in a child process with `env` added, so a
    /// test can change git's environment without touching this process's.
    /// Returns true in the child, which then runs the test body.
    fn in_child(name: &str, env: &[(&str, &OsStr)]) -> bool {
        const CHILD: &str = "BRAKELINE_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return true;
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("snapshot::tests::{name}"),
                "--nocapture",
            ])
            .env(CHILD, "1")
            .envs(env.iter().copied())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        false
    }

    #[test]
    fn unmatched_restore_paths_are_detected_in_any_locale() {
        // German, when git's translation is installed.
        let de = OsStr::new("de_DE.UTF-8");
        if !in_child(
            "unmatched_restore_paths_are_detected_in_any_locale",
            &[("LC_ALL", de), ("LANG", de)],
        ) {
            return;
        }
        let repo = committed_repo(&[("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let rec = take(data.path(), repo.path(), "s", "t", "rm")
            .unwrap()
            .unwrap();
        let err = preview(data.path(), &rec, &["nope.txt".into()])
            .err()
            .unwrap();
        assert!(
            format!("{err:#}").contains("nothing in the snapshot matches"),
            "{err:#}"
        );
    }

    #[test]
    fn nested_walk_keeps_the_users_git_config_environment() {
        let base = tempfile::tempdir().unwrap();
        let excludes = base.path().join("excludes");
        fs::write(&excludes, "*.private\n").unwrap();
        if !in_child(
            "nested_walk_keeps_the_users_git_config_environment",
            &[
                ("GIT_CONFIG_COUNT", OsStr::new("1")),
                ("GIT_CONFIG_KEY_0", OsStr::new("core.excludesFile")),
                ("GIT_CONFIG_VALUE_0", excludes.as_os_str()),
            ],
        ) {
            return;
        }
        assert!(std::env::var_os("GIT_CONFIG_COUNT").is_some());
        let repo = committed_repo(&[("a.txt", "a")]);
        let data = tempfile::tempdir().unwrap();
        let r = repo.path();
        let sub = r.join("sub");
        fs::create_dir(&sub).unwrap();
        sh(&sub, &["init", "-q"]);
        fs::write(sub.join("notes.private"), "p").unwrap();
        fs::write(sub.join("b.txt"), "b").unwrap();
        let rec = take(data.path(), r, "s", "t", "rm").unwrap().unwrap();
        assert!(in_tree(r, &rec.commit, "sub/b.txt"));
        assert!(!in_tree(r, &rec.commit, "sub/notes.private"));
    }

    #[test]
    fn uncovered_note_names_the_first_paths() {
        let mut rec = SnapshotRecord {
            id: "1".into(),
            repo: "/r".into(),
            commit: "c".into(),
            session_id: "s".into(),
            reason: "r".into(),
            command: "rm".into(),
            created_at: 0,
            uncovered: Vec::new(),
        };
        assert_eq!(rec.uncovered_note(), None);
        rec.uncovered = vec!["a/: too large".into(), "b/c/: git failed: x/: y".into()];
        assert_eq!(rec.uncovered_note().unwrap(), "not covered: a/, b/c/");
        rec.uncovered
            .extend(["d/: e".into(), "f/: g".into(), "h/: i".into()]);
        assert_eq!(
            rec.uncovered_note().unwrap(),
            "not covered: a/, b/c/, d/ (+2 more)"
        );
    }

    /// A version 2 index listing `paths` as regular files with blob `oid`,
    /// written byte by byte: git itself refuses to add such paths.
    fn raw_index(oid: &str, paths: &[&[u8]]) -> Vec<u8> {
        let mut paths = paths.to_vec();
        paths.sort();
        let mut out = b"DIRC".to_vec();
        out.extend(2u32.to_be_bytes());
        out.extend((paths.len() as u32).to_be_bytes());
        let oid: Vec<u8> = (0..20)
            .map(|i| u8::from_str_radix(&oid[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        for path in paths {
            let start = out.len();
            out.extend([0u8; 24]); // ctime, mtime, dev, ino
            out.extend(0o100644u32.to_be_bytes());
            out.extend([0u8; 12]); // uid, gid, size
            out.extend(&oid);
            out.extend((path.len().min(0xfff) as u16).to_be_bytes());
            out.extend(path);
            // One to eight NULs, padding the entry to a multiple of eight.
            out.extend(vec![0u8; 8 - (out.len() - start) % 8]);
        }
        // An all-zero checksum tells git not to verify it.
        out.extend([0u8; 20]);
        out
    }

    fn hash(repo: &Path, body: &str) -> String {
        text(
            git_raw(
                repo,
                &["hash-object", "--stdin"],
                None,
                &[],
                Some(body.as_bytes().to_vec()),
            )
            .unwrap(),
        )
    }

    fn has_object(repo: &Path, oid: &str) -> bool {
        git(repo, &["cat-file", "-e", oid], None).is_ok()
    }

    #[cfg(unix)]
    #[test]
    fn a_hostile_nested_index_cannot_pull_in_files_from_outside_the_repository() {
        use std::os::unix::ffi::OsStrExt;
        let base = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let outside = base.path().join("outside");
        fs::create_dir_all(outside.join("private")).unwrap();
        fs::write(outside.join("private/key"), "outside private key 7f3a").unwrap();
        fs::write(outside.join("top.txt"), "outside top file 7f3a").unwrap();
        let r = base.path().join("repo");
        fs::create_dir(&r).unwrap();
        sh(&r, &["init", "-q"]);
        fs::write(r.join("a.txt"), "a").unwrap();
        sh(&r, &["add", "a.txt"]);
        sh(&r, &["commit", "-q", "-m", "init"]);

        let sub = r.join("sub");
        fs::create_dir(&sub).unwrap();
        sh(&sub, &["init", "-q"]);
        fs::write(sub.join("ok.txt"), "ok").unwrap();
        fs::write(sub.join("tracked.txt"), "tracked").unwrap();
        std::os::unix::fs::symlink(&outside, sub.join("link")).unwrap();
        let blob = hash(&sub, "tracked");
        let absolute = format!("{}/", outside.join("private").display());
        let absolute_file = outside.join("top.txt");
        // Alone in its index, this entry was hashed before git failed.
        let evil = r.join("evil");
        fs::create_dir(&evil).unwrap();
        sh(&evil, &["init", "-q"]);
        fs::write(evil.join("e.txt"), "e").unwrap();
        fs::write(
            evil.join(".git/index"),
            raw_index(&blob, &[absolute.as_bytes()]),
        )
        .unwrap();
        let hostile: Vec<&[u8]> = vec![
            absolute.as_bytes(),
            absolute_file.as_os_str().as_bytes(),
            b"../../outside/private/",
            b"../../outside/top.txt",
            b"./ok.txt",
            b"link/private/",
            b"link/top.txt",
            b"tracked.txt",
        ];
        fs::write(sub.join(".git/index"), raw_index(&blob, &hostile)).unwrap();

        let rec = take(data.path(), &r, "s", "t", "git reset --hard")
            .unwrap()
            .unwrap();
        for body in ["outside private key 7f3a", "outside top file 7f3a"] {
            assert!(
                !has_object(&r, &hash(&r, body)),
                "{body:?} reached the outer object store"
            );
        }
        // Only the bad entries are skipped; the rest of the repository is kept.
        assert!(
            in_tree(&r, &rec.commit, "sub/ok.txt"),
            "{:?}",
            rec.uncovered
        );
        assert!(in_tree(&r, &rec.commit, "sub/tracked.txt"));
        assert!(in_tree(&r, &rec.commit, "evil/e.txt"));
        let unsafe_paths = rec
            .uncovered
            .iter()
            .filter(|u| u.contains("unsafe path"))
            .count();
        assert_eq!(unsafe_paths, 8, "{:?}", rec.uncovered);
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
