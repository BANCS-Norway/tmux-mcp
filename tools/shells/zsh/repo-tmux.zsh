# repo-tmux — attach to an unattached tmux session for the current repo,
# or create a new one. Worktree-aware: all worktrees of a repo share one
# session name.
#
# Install: source this file from ~/.zshrc.
#
# Environment variables:
#   TMUX_SESSION         Force a specific session name (skips resolution).
#   REPO_TMUX_SKIP       If set, the startup hook does not auto-run.
#   REPO_TMUX_SUFFIXES   Space-separated override for the default suffix list.
#
# Default suffixes mean "ready" in six languages — Latin, Norwegian, Spanish,
# Italian, German, Finnish. Short, ASCII, distinct-sounding.

typeset -gra REPO_TMUX_DEFAULT_SUFFIXES=(paratus klar listo pronto bereit valmis)

repo-tmux() {
  [[ -n "${TMUX:-}" ]] && return 0
  command -v tmux >/dev/null || return 0

  local sessions
  sessions=$(tmux list-sessions -F '#{session_name} #{session_attached}' 2>/dev/null)

  # Explicit override via TMUX_SESSION.
  if [[ -n "${TMUX_SESSION:-}" ]]; then
    local target="$TMUX_SESSION" st
    st=$(awk -v n="$target" '$1 == n { print $2; exit }' <<< "$sessions")
    if [[ "$st" == "0" ]]; then
      exec tmux attach -t "$target"
    elif [[ -z "$st" ]]; then
      exec tmux new-session -s "$target"
    else
      print -u2 "repo-tmux: session '$target' is already attached."
      return 1
    fi
  fi

  # Resolve the main repo root from inside any worktree.
  local common_dir repo_root repo
  common_dir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || return 0
  repo_root=$(dirname "$common_dir")
  repo=$(basename "$repo_root")

  # Pick suffix list — custom if provided, default otherwise.
  local -a suffixes
  local is_custom=0
  if [[ -n "${REPO_TMUX_SUFFIXES:-}" ]]; then
    suffixes=(${=REPO_TMUX_SUFFIXES})
    is_custom=1
  else
    suffixes=("${REPO_TMUX_DEFAULT_SUFFIXES[@]}")
  fi

  # Candidates in allocation order: base repo, then each suffix.
  local -a candidates=("$repo")
  local s
  for s in "${suffixes[@]}"; do
    candidates+=("${repo}-${s}")
  done

  # Attach to the first unattached existing match.
  local name st
  for name in "${candidates[@]}"; do
    st=$(awk -v n="$name" '$1 == n { print $2; exit }' <<< "$sessions")
    [[ "$st" == "0" ]] && exec tmux attach -t "$name"
  done

  # Otherwise create the first candidate that doesn't exist yet.
  for name in "${candidates[@]}"; do
    st=$(awk -v n="$name" '$1 == n { print $2; exit }' <<< "$sessions")
    [[ -z "$st" ]] && exec tmux new-session -s "$name"
  done

  # Exhausted — all candidates exist and all are attached.
  if (( is_custom )); then
    print -u2 "All sessions are attached and your REPO_TMUX_SUFFIXES list is full."
    print -u2 "Add more names to continue: REPO_TMUX_SUFFIXES=\"foo bar baz qux\""
  else
    print -u2 "All sessions are attached. If you need more, define your own list:"
    print -u2 '  export REPO_TMUX_SUFFIXES="foo bar baz"'
  fi
  return 1
}

# Auto-run for fresh interactive shells inside a git repo.
if [[ -o interactive && -z "${TMUX:-}" && -z "${REPO_TMUX_SKIP:-}" ]] \
   && git -C "$PWD" rev-parse --git-dir >/dev/null 2>&1; then
  repo-tmux
fi
