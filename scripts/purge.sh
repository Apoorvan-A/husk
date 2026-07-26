#!/usr/bin/env bash
# Remove every host resource husk may have created.
#
# An interrupted container start, or a test run killed mid-flight, can leave a
# cgroup directory, a veth interface, an IP lease or a netfilter rule behind.
# None of them are dangerous, but they accumulate, and a leaked veth with the
# same name blocks the next container that would have used it.
set -uo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "purge must run as root" >&2
    exit 1
fi

STATE_ROOT=${HUSK_STATE_ROOT:-/run/husk}
DATA_ROOT=${HUSK_DATA_ROOT:-/var/lib/husk}
CGROUP_ROOT=${HUSK_CGROUP_ROOT:-/sys/fs/cgroup/husk}
BRIDGE=${HUSK_BRIDGE:-husk0}

echo "==> killing container processes"
for cg in "$CGROUP_ROOT"/*/; do
    [ -d "$cg" ] || continue
    # cgroup.kill is atomic across the whole subtree, which matters when the
    # thing being cleaned up is a fork bomb that outruns a PID loop.
    [ -f "$cg/cgroup.kill" ] && echo 1 > "$cg/cgroup.kill" 2>/dev/null
done
sleep 0.2

echo "==> removing cgroups"
for cg in "$CGROUP_ROOT"/*/; do
    [ -d "$cg" ] || continue
    rmdir "$cg" 2>/dev/null && echo "    removed $cg"
done
rmdir "$CGROUP_ROOT" 2>/dev/null

echo "==> removing overlay mounts and container storage"
# Reverse order so nested mounts come off before their parents.
grep -o " $DATA_ROOT/containers/[^ ]*merged " /proc/self/mountinfo 2>/dev/null \
    | tr -d ' ' | sort -r | while read -r mp; do
    umount -l "$mp" 2>/dev/null && echo "    unmounted $mp"
done
rm -rf "${DATA_ROOT:?}/containers" 2>/dev/null

echo "==> removing veth interfaces"
ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 \
    | grep '^hveth' | while read -r iface; do
    ip link delete "$iface" 2>/dev/null && echo "    deleted $iface"
done

echo "==> flushing netfilter chains"
for spec in "nat HUSK-POSTROUTING POSTROUTING" "nat HUSK-DNAT PREROUTING" \
            "nat HUSK-DNAT OUTPUT" "filter HUSK-FORWARD FORWARD"; do
    set -- $spec
    iptables -t "$1" -D "$3" -j "$2" 2>/dev/null
done
for spec in "nat HUSK-POSTROUTING" "nat HUSK-DNAT" "filter HUSK-FORWARD"; do
    set -- $spec
    iptables -t "$1" -F "$2" 2>/dev/null
    iptables -t "$1" -X "$2" 2>/dev/null && echo "    removed $2"
done

echo "==> removing the bridge"
ip link delete "$BRIDGE" 2>/dev/null && echo "    deleted $BRIDGE"

echo "==> removing runtime state"
rm -rf "${STATE_ROOT:?}" && echo "    removed $STATE_ROOT"

echo "done. images and layers under $DATA_ROOT were left alone."
