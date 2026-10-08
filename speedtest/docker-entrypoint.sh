#!/bin/sh
set -e

if [ -x /data/mmwx-speedtester ]; then
  exec /data/mmwx-speedtester "$@"
fi
exec /usr/local/bin/mmwx-speedtester "$@"
