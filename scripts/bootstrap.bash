#!/usr/bin/env bash
#
# Bootstrap the project toolchain with aqua (https://aquaproj.github.io/).
#
#   1. Install the aqua CLI (pinned) when it is not already available.
#   2. Install every tool declared in .aqua/aqua.yaml (`aqua install -a`).
#   3. Put aqua's bin directory on PATH.
#
# The script is idempotent and non-interactive, so it is safe to run repeatedly
# and to wire up as a Claude Code SessionStart hook (see .claude/settings.json).
# When it runs inside a Claude Code session it also appends the aqua environment
# to $CLAUDE_ENV_FILE so the tools stay on PATH for the whole session.

set -euo pipefail

# aqua CLI version to install when aqua is missing. Keep in sync with CI:
# .github/workflows/*.yml -> aquaproj/aqua-installer `aqua_version`.
AQUA_VERSION="v2.62.0"

# Pinned aqua-installer script (https://github.com/aquaproj/aqua-installer).
# Update AQUA_INSTALLER_SHA256 whenever AQUA_INSTALLER_VERSION changes:
#   curl -sSfL https://raw.githubusercontent.com/aquaproj/aqua-installer/<ver>/aqua-installer | sha256sum
AQUA_INSTALLER_VERSION="v4.0.5"
AQUA_INSTALLER_SHA256="451028d56959cc738564885b1dbebc2691ea038ffde04e2472e4d486a3591146"

log()
{
	printf '[bootstrap] %s\n' "$*" >&2
}

# Resolve the repo root from the script location so cwd does not matter.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# Where aqua installs itself and the tools it manages.
export AQUA_ROOT_DIR="${AQUA_ROOT_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/aquaproj-aqua}"
AQUA_BIN_DIR="${AQUA_ROOT_DIR}/bin"

# aqua discovers .aqua/aqua.yaml by walking up from cwd, but pinning it as the
# global config lets the installed tools resolve their versions from anywhere.
export AQUA_GLOBAL_CONFIG="${ROOT_DIR}/.aqua/aqua.yaml"

export PATH="${AQUA_BIN_DIR}:${PATH}"

install_aqua()
{
	if command -v aqua > /dev/null 2>&1; then
		log "aqua already installed ($(aqua version 2> /dev/null || true))"
		return
	fi

	log "installing aqua ${AQUA_VERSION} via aqua-installer ${AQUA_INSTALLER_VERSION}"

	local tmp installer
	tmp="$(mktemp -d)"
	trap 'rm -rf "${tmp}"' RETURN
	installer="${tmp}/aqua-installer"

	curl -sSfL --retry 5 -o "${installer}" \
		"https://raw.githubusercontent.com/aquaproj/aqua-installer/${AQUA_INSTALLER_VERSION}/aqua-installer"
	printf '%s  %s\n' "${AQUA_INSTALLER_SHA256}" "${installer}" | sha256sum -c - >&2

	bash "${installer}" -v "${AQUA_VERSION}" >&2
}

persist_session_env()
{
	# Only relevant when invoked as a Claude Code hook.
	[ -n "${CLAUDE_ENV_FILE:-}" ] || return 0

	local marker="# rsdebstrap aqua bootstrap"
	if grep -qsF "${marker}" "${CLAUDE_ENV_FILE}" 2> /dev/null; then
		return 0
	fi

	{
		echo "${marker}"
		echo "export AQUA_ROOT_DIR=\"${AQUA_ROOT_DIR}\""
		echo "export AQUA_GLOBAL_CONFIG=\"${AQUA_GLOBAL_CONFIG}\""
		echo "export PATH=\"${AQUA_BIN_DIR}:\$PATH\""
	} >> "${CLAUDE_ENV_FILE}"
	log "persisted aqua environment to \$CLAUDE_ENV_FILE"
}

main()
{
	install_aqua

	log "installing tools from ${AQUA_GLOBAL_CONFIG}"
	aqua install -a >&2

	persist_session_env

	log "done; aqua-managed tools are available on PATH from ${AQUA_BIN_DIR}"
}

main "$@"
