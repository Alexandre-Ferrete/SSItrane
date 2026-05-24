import subprocess
import time
import os
import shutil
import sys

# Caminhos
BASE_DIR = os.getcwd()
SRC_DIR = os.path.join(BASE_DIR, "src")
VENV_PYTHON = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")

def cleanup():
    print("[*] Cleaning up old data...")
    client_data = os.path.join(SRC_DIR, "client_data")
    server_data = os.path.join(SRC_DIR, "data")
    if os.path.exists(client_data):
        shutil.rmtree(client_data)
    if os.path.exists(server_data):
        shutil.rmtree(server_data)

def run_server():
    print("[*] Starting Server...")
    env = os.environ.copy()
    env["SERVER_PASSWORD"] = "server"
    with open("server_test.log", "w") as log:
        return subprocess.Popen([VENV_PYTHON, "-m", "server"], 
                                env=env, 
                                cwd=SRC_DIR,
                                stdout=log,
                                stderr=log)

def run_client_script(commands, delay=1.0):
    # IP [localhost] + Comandos + /exit
    input_str = "localhost\n"
    process = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               cwd=SRC_DIR,
                               text=True)
    
    # Enviar IP primeiro e esperar o handshake
    process.stdin.write("localhost\n")
    process.stdin.flush()
    time.sleep(1) # Wait for handshake
    
    for cmd in commands:
        process.stdin.write(cmd + "\n")
        process.stdin.flush()
        time.sleep(delay)
        
    process.stdin.write("/exit\n")
    process.stdin.flush()
    stdout, stderr = process.communicate()
    return stdout

def test_p2p_and_offline():
    print("\n=== INTEGRATION TEST: P2P, OFFLINE & RATCHET ===")
    
    # 1. Register Alice and Bob
    print("[*] Registering Alice and Bob...")
    out_a = run_client_script(["/register alice 1"])
    out_b = run_client_script(["/register bob 2"])
    
    if "SUCESSO: Registo OK" not in out_a or "SUCESSO: Registo OK" not in out_b:
        print("[FAIL] Registration failed.")
        return

    # 2. Alice sends offline message to Bob
    print("[*] Alice sending offline message to Bob...")
    out_alice_off = run_client_script([
        "/login alice 1",
        "/chat bob Ola_Bob_Offline"
    ])
    
    if "está offline. A guardar mensagem segura" in out_alice_off:
        print("[OK] Alice stored offline message.")
    else:
        print("[FAIL] Alice failed to store offline message.")

    # 3. Bob logs in and receives message
    print("[*] Bob logging in to receive message...")
    out_bob_off = run_client_script(["/login bob 2"])
    if "Ola_Bob_Offline" in out_bob_off:
        print("[OK] Bob received offline message.")
    else:
        print("[FAIL] Bob failed to receive offline message.")

    # 4. Live P2P Chat (Both online)
    print("[*] Testing Live P2P Chat...")
    # Bob online em background
    bob_proc = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=SRC_DIR)
    bob_proc.stdin.write("localhost\n/login bob 2\n")
    bob_proc.stdin.flush()
    time.sleep(2)

    # Alice online e envia mensagem live
    out_alice_live = run_client_script([
        "/login alice 1",
        "/chat bob Mensagem_Live_P2P"
    ])

    time.sleep(2)
    bob_proc.stdin.write("/exit\n")
    bob_proc.stdin.flush()
    stdout_bob_live, _ = bob_proc.communicate()

    if "Mensagem_Live_P2P" in stdout_bob_live:
        print("[OK] Live P2P Message received.")
    else:
        print("[FAIL] Live P2P Message lost.")

    # 5. Ratchet P2P (Alice sends 6 messages)
    print("[*] Testing P2P Ratchet (Forward Secrecy)...")
    bob_proc2 = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=SRC_DIR)
    bob_proc2.stdin.write("localhost\n/login bob 2\n")
    bob_proc2.stdin.flush()
    time.sleep(2)

    alice_ratchet = ["/login alice 1"] + ["/chat bob Msg_" + str(i) for i in range(6)]
    run_client_script(alice_ratchet, delay=0.5)
    
    time.sleep(2)
    bob_proc2.stdin.write("/exit\n")
    bob_proc2.stdin.flush()
    stdout_bob_r, _ = bob_proc2.communicate()

    if "Ratchet P2P concluído" in stdout_bob_r:
        print("[OK] P2P Ratchet verified.")
    else:
        print("[FAIL] P2P Ratchet not detected in logs.")

if __name__ == "__main__":
    cleanup()
    server = run_server()
    time.sleep(3)
    try:
        test_p2p_and_offline()
    finally:
        server.terminate()
        print("\n[*] Integration Tests Finished.")
