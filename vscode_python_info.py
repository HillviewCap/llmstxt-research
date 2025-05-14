import sys
import os
import platform
import subprocess

print("=== Python Interpreter Information ===")
print(f"Python Version: {sys.version}")
print(f"Python Executable: {sys.executable}")
print(f"Platform: {platform.platform()}")
print(f"sys.prefix: {sys.prefix}")
print(f"sys.base_prefix: {sys.base_prefix}")

# Check if running in a virtual environment
in_venv = sys.prefix != sys.base_prefix
print(f"Running in virtual environment: {in_venv}")

# Check VIRTUAL_ENV environment variable
virtual_env = os.environ.get("VIRTUAL_ENV", "Not set")
print(f"VIRTUAL_ENV: {virtual_env}")

# Try to get VSCode Python extension info
try:
    vscode_ext = os.environ.get("VSCODE_EXTENSIONS", "Not set")
    print(f"VSCode Extensions: {vscode_ext}")
except Exception as e:
    print(f"Error getting VSCode info: {e}")

# Try to get the Python interpreter path from VSCode settings
try:
    home = os.path.expanduser("~")
    vscode_settings = os.path.join(home, ".vscode", "settings.json")
    if os.path.exists(vscode_settings):
        print(f"VSCode settings found at: {vscode_settings}")
        with open(vscode_settings, "r") as f:
            print(f"VSCode settings content: {f.read()}")
    else:
        print(f"VSCode settings not found at: {vscode_settings}")
except Exception as e:
    print(f"Error reading VSCode settings: {e}")

# List all Python executables in PATH
print("\n=== Python Executables in PATH ===")
try:
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for dir in path_dirs:
        if os.path.exists(dir):
            python_exes = [f for f in os.listdir(dir) if f.startswith("python")]
            if python_exes:
                print(f"Directory: {dir}")
                for exe in python_exes:
                    exe_path = os.path.join(dir, exe)
                    try:
                        version_output = subprocess.check_output(
                            [exe_path, "--version"],
                            stderr=subprocess.STDOUT,
                            universal_newlines=True,
                        ).strip()
                        print(f"  {exe}: {version_output}")
                    except Exception as e:
                        print(f"  {exe}: Error getting version - {e}")
except Exception as e:
    print(f"Error listing Python executables: {e}")
