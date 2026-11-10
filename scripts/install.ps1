$ErrorActionPreference = 'Stop'
python -m pip install .
python -m wp_maintenance.cli install --global
python -m wp_maintenance.cli doctor
