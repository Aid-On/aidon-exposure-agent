#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${ALMIDE:=almide}"
mkdir -p bin
"$ALMIDE" check src/main.almd
"$ALMIDE" build src/main.almd -o bin/aidon-engine
