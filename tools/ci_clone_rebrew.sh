#!/usr/bin/env bash
# Clone the sibling rebrew path dependency.
#
# [tool.uv.sources] in pyproject.toml resolves rebrew from ../rebrew, so a
# clean clone cannot run `uv sync` without it.  actions/checkout cannot write
# outside GITHUB_WORKSPACE, so CI calls this instead; `make clone-rebrew`
# wraps it for a workstation.
#
# REBREW_REF and REBREW_SHA default to the tag this repository was developed
# against; override either in the environment to pin a different rebrew.
# The clone fails unless REBREW_REF resolves to REBREW_SHA: tags are mutable,
# so a moved tag must not silently change the path dependency.
# REBREW_FORCE=1 overwrites a destination checkout that has uncommitted work.
set -euo pipefail

REBREW_REF="${REBREW_REF:-v2.13.1}"
REBREW_SHA="${REBREW_SHA:-d2d67c870df79214320f16b1cba1b0f6086605a7}"
REBREW_URL="${REBREW_URL:-https://github.com/maci0/rebrew.git}"
dest="${1:-../rebrew}"

# Refuse anything but a rebrew destination: this script rm -rf's dest first.
if [ "$(basename "${dest}")" != "rebrew" ]; then
  echo "refusing dest whose basename is not 'rebrew': ${dest}" >&2
  exit 1
fi

# Never block on a credential prompt (no TTY in CI).
export GIT_TERMINAL_PROMPT=0
export GIT_LFS_SKIP_SMUDGE=1

# -c outranks repo config and the clone template.  core.hooksPath=/dev/null is
# not a directory, so git runs no hooks, and protocol.ext.allow=never refuses
# ext:: remotes that would execute a helper.
git_safe=(
  -c core.fsmonitor=
  -c core.hooksPath=/dev/null
  -c protocol.ext.allow=never
  -c core.sshCommand=ssh
  -c gpg.program=gpg
  -c filter.lfs.smudge=
  -c filter.lfs.process=
  -c filter.lfs.required=false
)

# The loop below removes the destination before every attempt, which is what
# makes a retry start from a clean tree.  On a workstation that directory is
# often a real rebrew checkout someone is working in, so stop rather than
# throw that work away.  A CI runner never gets here: the destination is
# outside the workspace and does not exist yet.  The status probe runs under
# git_safe so a repository's own core.fsmonitor cannot execute on checkout.
if [ -e "${dest}/.git" ] && [ -n "$(git "${git_safe[@]}" -C "${dest}" status --porcelain)" ]; then
  if [ "${REBREW_FORCE:-0}" != "1" ]; then
    echo "refusing to overwrite ${dest}: the checkout has uncommitted changes." >&2
    echo "Commit, stash or move them, or re-run with REBREW_FORCE=1." >&2
    exit 1
  fi
fi

for attempt in 1 2 3; do
  rm -rf -- "${dest}"
  if git "${git_safe[@]}" clone --depth 1 --branch "${REBREW_REF}" -- \
      "${REBREW_URL}" "${dest}"; then
    got_sha="$(git "${git_safe[@]}" -C "${dest}" rev-parse HEAD)"
    if [ "${got_sha}" != "${REBREW_SHA}" ]; then
      echo "rebrew ${REBREW_REF} resolves to ${got_sha}, expected ${REBREW_SHA}" >&2
      exit 1
    fi
    exit 0
  fi
  if [ "${attempt}" -eq 3 ]; then
    echo "git clone rebrew (${REBREW_REF} -> ${dest}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * 5))
done
