#!/usr/bin/env bash
# Measure husk against runc.
#
# Every number in the README comes from this script. Nothing is estimated and
# nothing is copied from another machine's results — run it yourself and the
# numbers will differ, because cold-start latency is dominated by the host's
# filesystem and scheduler.
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "benchmarks need root to create namespaces and cgroups" >&2
    exit 1
fi

for tool in hyperfine runc jq; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

HUSK=${HUSK:-$(pwd)/bin/husk}
[ -x "$HUSK" ] || { echo "build husk first: make build" >&2; exit 1; }

WORK=${WORK:-/var/lib/husk-bench}
BUNDLE="$WORK/bundle"
ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz"

mkdir -p "$WORK"
if [ ! -f "$WORK/rootfs.tar.gz" ]; then
    echo "==> fetching rootfs"
    curl -fsSL -o "$WORK/rootfs.tar.gz" "$ROOTFS_URL"
fi

echo "==> preparing an OCI bundle both runtimes can use"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/rootfs"
tar -xzf "$WORK/rootfs.tar.gz" -C "$BUNDLE/rootfs"
(cd "$BUNDLE" && runc spec)

# /bin/true as the entry point: the measurement is of runtime overhead, so the
# workload must contribute as close to nothing as possible.
jq '.process.args = ["/bin/true"] | .process.terminal = false' \
    "$BUNDLE/config.json" > "$BUNDLE/config.tmp"
mv "$BUNDLE/config.tmp" "$BUNDLE/config.json"

echo
echo "==> host"
echo "kernel:  $(uname -r)"
echo "cpu:     $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "cores:   $(nproc)"
echo "memory:  $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
echo "storage: $(findmnt -no FSTYPE -T "$WORK")"

echo
echo "==> cold start, no networking"
hyperfine --warmup 5 --runs 50 --style basic \
    --prepare "runc delete -f bench-runc 2>/dev/null; true" \
    "runc run --bundle $BUNDLE bench-runc" \
    --prepare "$HUSK delete -force bench-husk 2>/dev/null; true" \
    "$HUSK run -rootfs $BUNDLE/rootfs -net none -id bench-husk /bin/true"

echo
echo "==> cold start, husk with bridge networking"
hyperfine --warmup 3 --runs 20 --style basic \
    --prepare "$HUSK delete -force bench-net 2>/dev/null; true" \
    "$HUSK run -rootfs $BUNDLE/rootfs -net bridge -id bench-net /bin/true"

echo
echo "==> peak resident set of the runtime process"
for cmd in "$HUSK run -rootfs $BUNDLE/rootfs -net none -id bench-mem /bin/true" \
           "runc run --bundle $BUNDLE bench-runc-mem"; do
    name=$(echo "$cmd" | awk '{print $1}' | xargs basename)
    rss=$(/usr/bin/time -v $cmd 2>&1 | awk '/Maximum resident/ {print $NF}')
    printf "%-6s %s KiB\n" "$name" "$rss"
    runc delete -f bench-runc-mem 2>/dev/null || true
done

echo
echo "==> cleaning up"
runc delete -f bench-runc 2>/dev/null || true
"$HUSK" delete -force bench-husk 2>/dev/null || true
"$HUSK" delete -force bench-net 2>/dev/null || true
"$HUSK" delete -force bench-mem 2>/dev/null || true
