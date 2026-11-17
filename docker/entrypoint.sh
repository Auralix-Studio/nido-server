#!/bin/sh
set -e
mkdir -p /etc/nido
[ -f /etc/nido/config.yaml ] || cp /config.yaml.example /etc/nido/config.yaml
exec /usr/local/bin/nido "$@"
