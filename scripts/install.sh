#!/usr/bin/env sh
set -eu
python3 -m pip install .
python3 -m wp_maintenance.cli install --global
python3 -m wp_maintenance.cli doctor
