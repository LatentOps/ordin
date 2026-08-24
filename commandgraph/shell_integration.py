from __future__ import annotations


SUPPORTED_SHELLS = ("bash", "zsh")

_BASH_INIT = r"""# CommandGraph interactive integration for Bash.
# Source with: source <(commandgraph shell-init bash)

__commandgraph_shell_threshold() {
  case "${COMMANDGRAPH_SHELL_FAIL_ON:-warn}" in
    warn|ask|block)
      printf '%s' "${COMMANDGRAPH_SHELL_FAIL_ON:-warn}"
      ;;
    *)
      printf '%s\n' 'CommandGraph: COMMANDGRAPH_SHELL_FAIL_ON must be warn, ask, or block.' >&2
      return 2
      ;;
  esac
}

cgr() {
  if (( $# != 1 )); then
    printf '%s\n' "Usage: cgr 'command text'" >&2
    return 2
  fi

  local command_text="$1"
  if [[ -z "${command_text//[[:space:]]/}" ]]; then
    printf '%s\n' 'CommandGraph: refusing an empty command.' >&2
    return 2
  fi

  local threshold output status
  threshold="$(__commandgraph_shell_threshold)" || return $?

  local -a review_args
  review_args=(
    check "$command_text"
    --cwd "$PWD"
    --shell bash
    --interactive
    --fail-on "$threshold"
  )
  if [[ -n "${EUID+x}" ]]; then
    review_args+=(--euid "$EUID")
  fi
  if [[ -n "${COMMANDGRAPH_REPO_ROOT:-}" ]]; then
    review_args+=(--repo-root "$COMMANDGRAPH_REPO_ROOT")
  fi

  output="$(command commandgraph "${review_args[@]}" 2>&1)"
  status=$?

  if [[ "$output" != decision:\ allow* ]]; then
    printf '%s\n' "$output" >&2
  fi
  if (( status != 0 )); then
    return "$status"
  fi

  # Deliberately use a child shell rather than eval. Stateful commands such as
  # cd/export affect only the child shell; use normal shell execution for those.
  command bash -c "$command_text" commandgraph-shell
}

commandgraph_shell_disable() {
  unset -f cgr 2>/dev/null || true
  unset -f __commandgraph_shell_threshold 2>/dev/null || true
  unset -f commandgraph_shell_disable 2>/dev/null || true
}
"""

_ZSH_INIT = r"""# CommandGraph interactive integration for Zsh.
# Source with: source <(commandgraph shell-init zsh)
# Ctrl-X Ctrl-G reviews the current ZLE buffer and accepts it only when allowed.

__commandgraph_shell_threshold() {
  case "${COMMANDGRAPH_SHELL_FAIL_ON:-warn}" in
    warn|ask|block)
      print -rn -- "${COMMANDGRAPH_SHELL_FAIL_ON:-warn}"
      ;;
    *)
      print -ru2 -- 'CommandGraph: COMMANDGRAPH_SHELL_FAIL_ON must be warn, ask, or block.'
      return 2
      ;;
  esac
}

__commandgraph_review_args() {
  local command_text="$1"
  local threshold="$2"
  local -a args
  args=(
    check "$command_text"
    --cwd "$PWD"
    --shell zsh
    --interactive
    --fail-on "$threshold"
  )
  if [[ -n "${EUID+x}" ]]; then
    args+=(--euid "$EUID")
  fi
  if [[ -n "${COMMANDGRAPH_REPO_ROOT:-}" ]]; then
    args+=(--repo-root "$COMMANDGRAPH_REPO_ROOT")
  fi
  print -rN -- "${args[@]}"
}

cgr() {
  if (( $# != 1 )); then
    print -ru2 -- "Usage: cgr 'command text'"
    return 2
  fi

  local command_text="$1"
  if [[ -z "${command_text//[[:space:]]/}" ]]; then
    print -ru2 -- 'CommandGraph: refusing an empty command.'
    return 2
  fi

  local threshold output status
  threshold="$(__commandgraph_shell_threshold)" || return $?

  local -a review_args
  review_args=(
    check "$command_text"
    --cwd "$PWD"
    --shell zsh
    --interactive
    --fail-on "$threshold"
  )
  if [[ -n "${EUID+x}" ]]; then
    review_args+=(--euid "$EUID")
  fi
  if [[ -n "${COMMANDGRAPH_REPO_ROOT:-}" ]]; then
    review_args+=(--repo-root "$COMMANDGRAPH_REPO_ROOT")
  fi

  output="$(command commandgraph "${review_args[@]}" 2>&1)"
  status=$?

  if [[ "$output" != decision:\ allow* ]]; then
    print -ru2 -- "$output"
  fi
  if (( status != 0 )); then
    return "$status"
  fi

  command zsh -c "$command_text" commandgraph-shell
}

__commandgraph_zle_review_accept() {
  local command_text="$BUFFER"
  if [[ -z "${command_text//[[:space:]]/}" ]]; then
    zle .accept-line
    return
  fi

  local threshold output status
  threshold="$(__commandgraph_shell_threshold)" || {
    zle -M 'CommandGraph: invalid enforcement threshold'
    return
  }

  local -a review_args
  review_args=(
    check "$command_text"
    --cwd "$PWD"
    --shell zsh
    --interactive
    --fail-on "$threshold"
  )
  if [[ -n "${EUID+x}" ]]; then
    review_args+=(--euid "$EUID")
  fi
  if [[ -n "${COMMANDGRAPH_REPO_ROOT:-}" ]]; then
    review_args+=(--repo-root "$COMMANDGRAPH_REPO_ROOT")
  fi

  output="$(command commandgraph "${review_args[@]}" 2>&1)"
  status=$?
  if (( status == 0 )); then
    if [[ "$output" != decision:\ allow* ]]; then
      zle -I
      print -r -- "$output"
    fi
    zle .accept-line
    return
  fi

  zle -I
  print -r -- "$output"
  zle reset-prompt
}

commandgraph_shell_enable_zle() {
  if [[ -o interactive ]]; then
    zle -N commandgraph-review-accept __commandgraph_zle_review_accept
    bindkey '^X^G' commandgraph-review-accept
  fi
}

commandgraph_shell_disable() {
  if [[ -o interactive ]]; then
    bindkey -r '^X^G' 2>/dev/null || true
    zle -D commandgraph-review-accept 2>/dev/null || true
  fi
  unfunction cgr 2>/dev/null || true
  unfunction __commandgraph_shell_threshold 2>/dev/null || true
  unfunction __commandgraph_zle_review_accept 2>/dev/null || true
  unfunction commandgraph_shell_enable_zle 2>/dev/null || true
  unfunction commandgraph_shell_disable 2>/dev/null || true
}

commandgraph_shell_enable_zle
"""


def render_shell_init(shell: str) -> str:
    normalized = shell.strip().lower()
    if normalized == "bash":
        return _BASH_INIT
    if normalized == "zsh":
        return _ZSH_INIT
    raise ValueError(f"unsupported shell {shell!r}; choose one of: {', '.join(SUPPORTED_SHELLS)}")
