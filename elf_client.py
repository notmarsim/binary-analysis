import socket
import sys
from pathlib import Path

HOST = "127.0.0.1"
PORT = 9000

def read_response(sock: socket.socket) -> str:
    """Lê linhas do socket até encontrar um bloco vazio terminador (\\n\\n)"""
    lines = []
    buffer = bytearray()
    
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            line = buffer.decode("utf-8", errors="replace").strip()

            if not line and lines:
                break
            if line:
                lines.append(line)
            buffer.clear()
        else:
            buffer.extend(chunk)
            
    return "\n".join(lines)

def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\n").encode("utf-8"))

def handle_local_upload(sock: socket.socket, command_line: str) -> bool:
    parts = command_line.split(maxsplit=1)
    if len(parts) < 2:
        print("Uso correto: /UPLOAD <caminho_do_arquivo>")
        return False

    local_path = Path(parts[1].strip())
    if not local_path.exists() or local_path.is_dir():
        print(f"Erro local: Arquivo inválido ou não encontrado.")
        return False

    filename = local_path.name
    file_bytes = local_path.read_bytes()
    size = len(file_bytes)

    send_line(sock, f"/UPLOAD {filename} {size}")
    sock.sendall(file_bytes)
    return True

def main():
    if len(sys.argv) == 2:
        file_path = Path(sys.argv[1])
        if not file_path.exists(): return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            send_line(sock, "/CONNECT")
            read_response(sock)
            if handle_local_upload(sock, f"/UPLOAD {file_path}"):
                print(read_response(sock))
            send_line(sock, "/QUIT")
            read_response(sock)
        return

    print("[+] Conectando em modo interativo...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            print("[+] Digite os comandos (ex: /CONNECT, /UPLOAD /bin/ls, /LIST, /INFO 1, /QUIT)")
            
            while True:
                user_input = input("> ").strip()
                if not user_input:
                    continue
                
                if user_input.upper().startswith("/UPLOAD"):
                    if handle_local_upload(sock, user_input):
                        print(read_response(sock))
                else:
                    send_line(sock, user_input)
                    response = read_response(sock)
                    print(response)
                    if user_input.upper() == "/QUIT" or "OK BYE" in response:
                        break
                        
    except ConnectionRefusedError:
        print("[-] Servidor offline.")
    except KeyboardInterrupt:
        print("\n[-] Conexão encerrada.")

if __name__ == "__main__":
    main()