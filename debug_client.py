import subprocess
import os
import sys

BASE_DIR = os.getcwd()
SRC_DIR = os.path.join(BASE_DIR, "src")
VENV_PYTHON = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")

def debug_client():
    input_str = "localhost\n/register alice 1\n/exit\n"
    process = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               cwd=SRC_DIR,
                               text=True)
    stdout, stderr = process.communicate(input=input_str)
    print("--- STDOUT ---")
    print(stdout)
    print("--- STDERR ---")
    print(stderr)

if __name__ == "__main__":
    debug_client()
