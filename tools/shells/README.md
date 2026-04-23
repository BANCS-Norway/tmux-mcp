# Shell integrations

Shell helpers that pair well with `tmux-mcp`. Ship one per shell; behavior is identical across implementations so you get the same UX whether you're in zsh, bash, fish, or anything else contributors add.

Currently shipped:

| Shell | File | Status |
|-------|------|--------|
| zsh   | [zsh/repo-tmux.zsh](zsh/repo-tmux.zsh) | ✅ |
| bash  | — | PRs welcome |
| fish  | — | PRs welcome |

## What `repo-tmux` does

Opens a fresh terminal inside a git repo and you land in a tmux session for that repo — either attaching to an existing one that nobody else is using, or creating a new one with a memorable name.

- **Worktree-aware.** All worktrees of the same repo share one session name. Open three worktrees in three terminals, they all land in the same tmux session.
- **Never steals.** Only attaches to sessions with no clients. If every session for the repo is already attached, creates a new one.
- **Memorable names.** Extra sessions are suffixed with words that all mean "ready" in different languages (see below). Override with your own list if you prefer.
- **Universal.** Any terminal emulator, any trigger — not VS Code-specific. Also fires when you SSH into a host and land in a git repo (bonus: survives disconnect).

## Requirements

| Tool | Minimum version | Why |
|------|-----------------|-----|
| `tmux` | any recent (≥ 2.0) | it's what we're driving |
| `git`  | 2.31 (March 2021) | uses `--path-format=absolute` on `git rev-parse`, which landed in 2.31 |
| `zsh`  | 5.0+ | the zsh implementation uses `typeset -gra` and `${=var}` splitting |

POSIX tools (`awk`, `dirname`, `basename`) are also used but are guaranteed to exist on any Unix-like system. No other dependencies — no `fzf`, no `jq`, no Python, no Node.

Other shell ports (bash, fish, etc.) will have their own version constraints; contributors should document them in the same format.

## Install (zsh)

```zsh
# Clone or download tmux-mcp somewhere, then:
source /path/to/tmux-mcp/tools/shells/zsh/repo-tmux.zsh
```

Add that line to the bottom of `~/.zshrc`. Open a new terminal inside any git repo and you'll land in a tmux session named after the repo.

To run the resolver manually (e.g. after setting an env var mid-session):

```zsh
repo-tmux
```

## Environment variables

| Variable | Effect |
|----------|--------|
| `TMUX_SESSION` | Force a specific session name. Attaches if it exists and is unattached; creates it if not; fails if already attached. |
| `REPO_TMUX_SKIP` | If set to anything, the startup hook doesn't auto-run. Useful for one-off terminals where you don't want tmux. |
| `REPO_TMUX_SUFFIXES` | Space-separated override for the default suffix list. |

VS Code users: both `TMUX_SESSION` and `REPO_TMUX_SKIP` can be set per-workspace via `terminal.integrated.env.linux` (or `.osx` / `.windows`) in `.vscode/settings.json`.

## The default suffix list

Sessions are allocated in this order:

1. `<repo>`
2. `<repo>-paratus` *(Latin)*
3. `<repo>-klar` *(Norwegian, Swedish, Danish, German)*
4. `<repo>-listo` *(Spanish)*
5. `<repo>-pronto` *(Italian)*
6. `<repo>-bereit` *(German)*
7. `<repo>-valmis` *(Finnish)*

All mean "ready." The default is opinionated but overridable — if you'd rather use NATO, Norse gods, Greek letters, or your pets' names, set `REPO_TMUX_SUFFIXES`:

```zsh
export REPO_TMUX_SUFFIXES="odin thor loki freya tyr heimdall"
```

Seven sessions per repo (base + six suffixes) is more than any human can juggle at once, so hitting the limit usually means you want to clean up rather than add more. When the list is exhausted, `repo-tmux` refuses to create and points you at how to add more.

## Shared spec (for contributors)

Any bash, fish, nu, etc. port should behave identically to the zsh version:

- Same env var names: `TMUX_SESSION`, `REPO_TMUX_SKIP`, `REPO_TMUX_SUFFIXES`.
- Same gates: interactive shell + not already in tmux (`$TMUX` empty) + inside a git worktree + not opted out.
- Same session-naming rules: `<repo>` base, then the suffix list in order.
- Same worktree resolution: `git rev-parse --path-format=absolute --git-common-dir` → parent dir → `basename`. (Standard `git rev-parse --show-toplevel` returns the *worktree* path from inside a worktree, which gives per-worktree session names — not what we want.)
- Same allocation policy: attach to first unattached match; create next free candidate; hard-stop when exhausted.
- Same exhaustion error messages (default list vs. custom list — the advice differs).

Open a PR adding `tools/shells/<shell>/repo-tmux.<ext>` and updating the table above. The zsh file is the reference implementation — port its behavior, not its syntax.
