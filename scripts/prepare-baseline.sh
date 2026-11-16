#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf .baseline && mkdir -p .baseline
git archive vulnerable-baseline target | tar -x -C .baseline
