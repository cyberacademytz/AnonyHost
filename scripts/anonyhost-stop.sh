#!/usr/bin/env bash
# Stops the AnonyHost dashboard AND the hosted website (Tor + Nginx).
exec "$(dirname "$(readlink -f "$0")")/anonyhost" --stop-all
