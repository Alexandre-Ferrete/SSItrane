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
    server_db = os.path.join(SRC_DIR, "server.db")
    if os.path.exists(client_data):
        shutil.rmtree(client_data)
    if os.path.exists(server_db):
        os.remove(server_db)

def run_server():
    print("[*] Starting Server...")
    env = os.environ.copy()
    env["SERVER_PASSWORD"] = "server"
    # Redirecionar stdout/stderr para ficheiro para evitar bloqueios de pipe
    with open("server_test.log", "w") as log:
        return subprocess.Popen([VENV_PYTHON, "-m", "server"], 
                                env=env, 
                                cwd=SRC_DIR,
                                stdout=log,
                                stderr=log)

def run_client_commands(commands):
    # Automatiza a entrada: IP [localhost] + Comandos + /exit
    input_str = "localhost\n" + "\n".join(commands) + "\n/exit\n"
    process = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               cwd=SRC_DIR,
                               text=True)
    stdout, stderr = process.communicate(input=input_str)
    return stdout

def test_register_login():
    print("\n--- TEST: REGISTER & LOGIN ---")
    out = run_client_commands(["/register alice 1"])
    if "SUCESSO: Registo OK" in out:
        print("[OK] Registration Alice successful.")
    else:
        print("[FAIL] Registration Alice failed.")

    out = run_client_commands(["/login alice 1"])
    if "SUCESSO: Login OK" in out:
        print("[OK] Login Alice successful.")
    else:
        print("[FAIL] Login Alice failed.")

def test_cs_ratchet():
    print("\n--- TEST: C-S RATCHET ---")
    # Faz várias chamadas ao servidor para verificar se o Ratchet mantém o canal aberto
    commands = ["/login alice 1"] + ["/list"] * 10
    out = run_client_commands(commands)
    if out.count("SUCESSO: Login OK") == 1 and out.count("[*] Online:") >= 10:
        print("[OK] C-S Ratchet stable over 10 messages.")
    else:
        print("[FAIL] C-S Ratchet failed or session lost.")

def test_offline_messages():
    print("\n--- TEST: OFFLINE MESSAGES ---")
    # Alice regista-se
    run_client_commands(["/register alice 1"])
    # Bob regista-se e sai
    run_client_commands(["/register bob 2"])
    
    # Alice envia mensagem offline para Bob
    out_a = run_client_commands(["/login alice 1", "/chat bob Olá_Bob_estás_offline"])
    if "está offline. A guardar mensagem segura" in out_a:
        print("[OK] Alice detected Bob offline and stored message.")
    else:
        print("[FAIL] Alice failed to store offline message.")

    # Bob faz login e deve receber a mensagem
    out_b = run_client_commands(["/login bob 2"])
    if "Olá_Bob_estás_offline" in out_b:
        print("[OK] Bob received and decrypted offline message.")
    else:
        print("[FAIL] Bob did not receive offline message.")

def test_p2p_chat_ratchet():
    print("\n--- TEST: P2P CHAT & RATCHET ---")
    # Alice e Bob registados
    run_client_commands(["/register alice 1"])
    run_client_commands(["/register bob 2"])

    # Iniciar Bob em background (vai ficar à espera)
    bob_input = "localhost\n/login bob 2\n"
    bob_proc = subprocess.Popen([VENV_PYTHON, "-m", "client.client"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                text=True,
                                cwd=SRC_DIR)
    bob_proc.stdin.write(bob_input)
    bob_proc.stdin.flush()
    time.sleep(2) # Esperar login

    # Alice envia 10 mensagens para Bob (vai disparar o Ratchet P2P ao fim de 5)
    alice_commands = ["/login alice 1"] + ["/chat bob Msg_" + str(i) for i in range(10)]
    out_alice = run_client_commands(alice_commands)

    time.sleep(2)
    bob_proc.stdin.write("/exit\n")
    bob_proc.stdin.flush()
    stdout_bob, _ = bob_proc.communicate()

    # Verificar se as mensagens chegaram
    if "Msg_9" in stdout_bob:
        print("[OK] P2P Chat successful.")
    else:
        print("[FAIL] P2P Chat failed or Msg_9 not received.")

    # Verificar se o Ratchet aconteceu
    if "Ratchet P2P concluído" in stdout_bob or "Ratchet P2P concluído" in out_alice:
        print("[OK] P2P Ratchet verified.")
    else:
        print("[FAIL] P2P Ratchet not detected.")

if __name__ == "__main__":
    cleanup()
    server = run_server()
    time.sleep(3) # Esperar o servidor arrancar

    try:
        test_register_login()
        test_cs_ratchet()
        test_offline_messages()
        test_p2p_chat_ratchet()
    finally:
        print("\n[*] Stopping Server...")
        server.terminate()
        # Limpar logs temporários
        if os.path.exists("server_test.log"):
            pass # os.remove("server_test.log")
