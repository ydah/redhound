#!/usr/bin/env bash
set -uo pipefail
ip link del rh0 2>/dev/null
ip netns del rh-peer 2>/dev/null
echo "removed"
