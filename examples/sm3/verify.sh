#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
JAR=${JDBC_JAR:-$SCRIPT_DIR/../../postgresql-42.7.3-sm3.1.jar}
[ -f "$JAR" ] || { echo "Set JDBC_JAR to the delivered driver JAR" >&2; exit 1; }
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM
javac -encoding UTF-8 -source 8 -target 8 -d "$BUILD_DIR" "$SCRIPT_DIR/Sm3Verify.java"
java -cp "$JAR:$BUILD_DIR" Sm3Verify
