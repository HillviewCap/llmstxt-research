import os
import sys

# Check if running in a virtual environment
in_venv = sys.prefix != sys.base_prefix
print(f"Running in virtual environment: {in_venv}")
print(f"sys.prefix: {sys.prefix}")
print(f"sys.base_prefix: {sys.base_prefix}")

# Check VIRTUAL_ENV environment variable
virtual_env = os.environ.get("VIRTUAL_ENV", "Not set")
print(f"VIRTUAL_ENV: {virtual_env}")

# Check if .venv/bin is in PATH
path = os.environ.get("PATH", "")
venv_in_path = ".venv/bin" in path or ".venv\\Scripts" in path
print(f".venv in PATH: {venv_in_path}")
print(f"PATH: {path}")
