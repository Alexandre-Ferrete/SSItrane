import subprocess
import time
import os
import shutil
import sys

BASE_DIR = os.getcwd()
SRC_DIR = os.path.join(BASE_DIR, "src")
VENV_PYTHON = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")

def cleanup():
    dirs = [os.path.join(SRC_DIR, "client_data"), os.path.join(SRC_DIR, "data")]
    for d in dirs:
        if os.path.exists(d): shutil.rmtree(d)

def run_server():
    env = os.environ.copy()
    env["SERVER_PASSWORD"] = "server"
    return subprocess.Popen([VENV_PYTHON, "-m", "server"], env=env, cwd=SRC_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_client(commands):
    input_str = "localhost\n" + "\n".join(commands) + "\n/exit\n"
    process = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               cwd=SRC_DIR,
                               text=True)
    stdout, stderr = process.communicate(input=input_str)
    return stdout

if __name__ == "__main__":
    cleanup()
    server = run_server()
    time.sleep(3)
    try:
        print("\n--- TEST: C-S RATCHET STABILITY ---")
        run_client(["/register alice 1"])
        
        print("[*] Alice performing 20 server commands...")
        alice_out = run_client(["/login alice 1"] + ["/list"] * 20)
        
        if alice_out.count("[*] Online:") >= 20:
            print("[OK] Client-Server Ratchet stable.")
        else:
            print("[FAIL] Client-Server session lost.")
    finally:
        server.terminate()
