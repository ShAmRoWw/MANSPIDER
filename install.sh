#!/usr/bin/env bash
# Install the scanner and web viewer with runtime versions from uv.lock.
set -euo pipefail

usage() {
    printf '%s\n' \
        'Usage: bash install.sh' \
        '' \
        'Install MANSPIDER and its web viewer for the current Linux user.' \
        'Requires uv: https://docs.astral.sh/uv/getting-started/installation/' \
        'Uses Python 3.12 and the checked-in uv.lock; no sudo or activation needed.' \
        'Run again after updating this checkout to update the installed tools.'
}

if [[ $# -ne 0 ]]; then
    if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
        usage
        exit 0
    fi
    usage >&2
    exit 2
fi

if [[ $(uname -s) != Linux ]]; then
    printf '%s\n' 'This installer supports Linux only.' >&2
    exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
    printf '%s\n' 'uv is required. Install it first:' \
        'https://docs.astral.sh/uv/getting-started/installation/' >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for required_file in pyproject.toml uv.lock; do
    if [[ ! -f "$project_dir/$required_file" ]]; then
        printf 'Missing %s in %s. Use a complete project checkout.\n' \
            "$required_file" "$project_dir" >&2
        exit 1
    fi
done

install_tmp=$(mktemp -d -t manspider-install.XXXXXXXX)
cleanup() {
    rm -f -- "$install_tmp/constraints.txt"
    rmdir -- "$install_tmp" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --locked rejects stale metadata instead of silently changing dependencies.
# Exclude the editable checkout and dev tools from the exported constraints.
uv export --directory "$project_dir" --locked --no-dev --extra web \
    --python 3.12 --no-emit-project --no-hashes --no-annotate --no-header \
    --format requirements.txt --output-file "$install_tmp/constraints.txt" >/dev/null

# A non-editable tool installation is independent of this checkout and .venv.
# Refresh our package even when its version number has not changed. Do not
# use --force: existing commands installed by another manager must be preserved.
# uv stores the parsed constraints in its receipt, not a reference to this file.
uv tool install --python 3.12 --constraints "$install_tmp/constraints.txt" \
    --reinstall-package man-spider "$project_dir[web]"

tool_bin=$(uv tool dir --bin)
case ":${PATH:-}:" in
    *":$tool_bin:"*) ;;
    *)
        if ! uv tool update-shell; then
            printf '%s\n' 'Installed successfully, but uv could not update the shell configuration.' >&2
        fi
        printf '%s\n' 'Open a new terminal to use the updated PATH, or run now:'
        printf '  export PATH=%q:"$PATH"\n' "$tool_bin"
        ;;
esac

for executable in manspider manspider-web; do
    current_command=$(command -v "$executable" || true)
    if [[ -n "$current_command" && "$current_command" != "$tool_bin/$executable" ]]; then
        printf 'Warning: %s currently resolves to %s, not the new installation.\n' \
            "$executable" "$current_command" >&2
        printf '%s\n' 'Deactivate any old virtual environment or put the tool directory first in PATH:' >&2
        printf '  export PATH=%q:"$PATH"\n' "$tool_bin" >&2
    fi
done

printf '\nInstalled manspider and manspider-web in %s\n' "$tool_bin"
printf '%s\n' 'Run from any directory: manspider --help' \
    'Start the local web viewer: manspider-web' \
    'Update: rerun this installer from an updated checkout.' \
    'Uninstall: uv tool uninstall man-spider (scan results are kept).'
