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
        print("\n--- TEST: P2P & RATCHET ---")
        run_client(["/register alice 1"])
        run_client(["/register bob 2"])
        
        # Bob online em background
        bob_input = "localhost\n/login bob 2\n"
        bob_proc = subprocess.Popen([VENV_PYTHON, "-m", "client.client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=SRC_DIR)
        bob_proc.stdin.write(bob_input)
        bob_proc.stdin.flush()
        time.sleep(3)

        print("[*] Alice sending 7 messages to Bob...")
        run_client(["/login alice 1"] + ["/chat bob Msg_" + str(i) for i in range(7)])
        
        time.sleep(2)
        bob_proc.stdin.write("/exit\n")
        bob_proc.stdin.flush()
        bob_out, _ = bob_proc.communicate()

        if "Msg_6" in bob_out and "Ratchet P2P concluído" in bob_out:
            print("[OK] P2P Chat and Ratchet successful.")
        else:
            print("[FAIL] P2P Ratchet not detected or messages lost.")
    finally:
        server.terminate()
