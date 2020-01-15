#!/bin/sh
set -eu

BINPATH="/usr/bin/conntracct"
SVCNAME="conntracct"

echo "Running setcap on ${BINPATH} ..."
setcap cap_sys_admin,cap_net_admin,cap_dac_override,cap_sys_resource+eip "${BINPATH}"
echo "Successfully ran setcap on ${BINPATH}!"

# Enable the service if systemctl is present.
if command -v systemctl >/dev/null 2>&1; then
  echo "Found systemctl, enabling service ${SVCNAME}."
  systemctl enable "${SVCNAME}"
else
  echo "No systemctl found, skipping systemctl enable."
fi
