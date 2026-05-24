import subprocess
import time
import os
import shutil
import sys

python_exe = os.path.join(os.getcwd(), "venv", "Scripts", "python.exe")

def run_server():
    print("[*] Starting Server...")
    env = os.environ.copy()
    env["SERVER_PASSWORD"] = "server"
    return subprocess.Popen([python_exe, "-m", "server"], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            env=env,
                            cwd=os.path.join(os.getcwd(), "src"))

def run_client_script(commands):
    # Simula entrada do utilizador
    input_str = "\n".join(commands) + "\n/exit\n"
    process = subprocess.Popen([python_exe, "-m", "client.client"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               cwd=os.path.join(os.getcwd(), "src"),
                               text=True)
    stdout, stderr = process.communicate(input="localhost\n" + input_str)
    return stdout, stderr

def test_p2p_offline_transition():
    # ... rest of the code ...
    print("\n=== STARTING INTEGRATION TEST: OFFLINE TO P2P ===")
    
    # 1. Cleanup old data
    client_data_dir = os.path.join(os.getcwd(), "src", "client_data")
    server_db = os.path.join(os.getcwd(), "src", "server.db")
    if os.path.exists(client_data_dir):
        shutil.rmtree(client_data_dir)
    if os.path.exists(server_db):
        os.remove(server_db)

    # Start Server first
    server_proc = run_server()
    time.sleep(3) # Give server time to start
    
    # Check if server is running
    if server_proc.poll() is not None:
        print("[!] Server failed to start.")
        print(server_proc.stderr.read().decode())
        return

    try:
        # 2. Register Alice and Bob
        print("[*] Registering Alice and Bob...")
        stdout_a, _ = run_client_script(["/register alice 1"])
        stdout_b, _ = run_client_script(["/register bob 2"])
        
        if "SUCESSO" not in stdout_a or "SUCESSO" not in stdout_b:
            print("[!] Registration failed.")
            return

        # 3. Alice sends offline message to Bob
        print("[*] Alice sending offline message to Bob...")
        stdout_a2, _ = run_client_script([
            "/login alice 1",
            "/chat bob This_is_an_offline_message"
        ])
        
        if "está offline" not in stdout_a2:
            print("[!] Alice failed to detect Bob as offline.")
        else:
            print("[*] Alice successfully stored offline message.")

        # 4. Bob logs in and receives message
        print("[*] Bob logging in to receive message...")
        stdout_b2, _ = run_client_script(["/login bob 2"])
        
        if "This_is_an_offline_message" in stdout_b2:
            print("[*] Bob successfully received and decrypted offline message.")
        else:
            print("[!] Bob failed to receive offline message.")

        # 5. Live P2P Chat
        print("[*] Testing Live P2P Chat...")
        bob_proc = subprocess.Popen([python_exe, "-m", "client.client"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                text=True,
                                cwd=os.path.join(os.getcwd(), "src"))
        bob_proc.stdin.write("localhost\n/login bob 2\n")
        bob_proc.stdin.flush()
        time.sleep(3)

        stdout_alice, _ = run_client_script([
            "/login alice 1",
            "/chat bob Live_P2P_Message"
        ])

        time.sleep(3)
        bob_proc.stdin.write("/exit\n")
        bob_proc.stdin.flush()
        stdout_bob, _ = bob_proc.communicate()

        if "Live_P2P_Message" in stdout_bob:
            print("[*] Live P2P Chat successful! No crashes detected.")
        else:
            print("[!] Live P2P Chat failed or message not received.")
            # print("BOB STDOUT:", stdout_bob)

    finally:
        print("[*] Stopping Server...")
        server_proc.terminate()

    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    # Ensure server is running in another terminal or start it here
    # For safety in this environment, I assume the user has the server running
    # or I will just run the logic.
    test_p2p_offline_transition()
