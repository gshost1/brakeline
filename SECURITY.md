# Security model

## What brakeline protects against

- An agent that is honest but wrong: loops, retries, runaway spend, and destructive cleanup commands (`git restore`, `rm -rf`, `git reset --hard`) that would destroy uncommitted work.
- A cloned repository trying to weaken the guard. Project `.brakeline.toml` files can only tighten limits and cannot change pricing.

## What it does not protect against

- **A deliberately malicious agent or prompt injection that obfuscates commands.** Shell classification is heuristic (for example, `$(printf 'r''m') -rf ~` is not recognized). Pair brakeline with an OS-level sandbox for untrusted work.
- Side effects outside the git working tree: ignored files, databases, cloud resources, remote pushes.
- Tampering by anything that can write to `~/.brakeline` or the user config. These are trusted, user-owned files (created with mode 0700).

## Data handling

- No network access and no telemetry.
- Session state stores counters, hashes of tool inputs, and short labels (a tool name plus up to 80 characters of its main argument, such as a file path or command). Tool outputs are not stored.
- Snapshot metadata stores up to 300 characters of the triggering command. Snapshot contents are git objects in your own repository, under `refs/brakeline/snapshots/`. Run `brakeline prune` and then `git gc` to remove them.
- Commands may contain secrets passed on the command line. Treat `~/.brakeline` as sensitive.

## Reporting

Please report vulnerabilities privately to the maintainers rather than in a public issue.
