#!/usr/bin/env bash
set -euo pipefail

echo "Building package..."
python3 -m pip install --upgrade build twine
python3 -m build

echo "Uploading to PyPI (requires PYPI_API_TOKEN in env)..."
python3 -m twine upload dist/*

echo "Release complete."
