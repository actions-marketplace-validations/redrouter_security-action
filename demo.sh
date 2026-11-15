#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD"
if [[ -x .venv/bin/python ]]; then
  exec .venv/bin/python -m demo.run "$@"
fi
if python3 -c 'import yaml' 2>/dev/null; then
  exec python3 -m demo.run "$@"
fi
printf '%s\n' 'Install the pinned demo dependency once: uv venv --python 3.12 && uv pip install PyYAML==6.0.3' >&2
exit 1
