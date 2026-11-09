#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
GOOS=linux GOARCH=amd64 make build
artifact_dir="$project_dir/dist/anbridge-linux-amd64"
mkdir -p "$artifact_dir"
install -m 0755 bin/anbridge "$artifact_dir/anbridge"
cp README.md LICENSE "$artifact_dir/"
cp -R configs deploy docs "$artifact_dir/"
tar -czf "$project_dir/dist/anbridge-linux-amd64.tar.gz" -C "$project_dir/dist" anbridge-linux-amd64
(
  cd "$project_dir/dist"
  sha256sum anbridge-linux-amd64.tar.gz > anbridge-linux-amd64.tar.gz.sha256
)
