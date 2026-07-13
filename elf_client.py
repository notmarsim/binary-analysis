import argparse
import socket
from pathlib import Path
from typing import Sequence

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000


def parse_port(value: str) -> int:
    """Converte e valida uma porta TCP informada pela linha de comando."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("a porta deve ser um número inteiro") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("a porta deve estar entre 1 e 65535")

    return port


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cliente TCP para envio e análise remota de arquivos ELF."
    )
    parser.add_argument(
        "file",
        nargs="?",
        type=Path,
        help="arquivo ELF enviado imediatamente após a conexão",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"endereço IPv4 ou nome do servidor (padrão: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=parse_port,
        default=DEFAULT_PORT,
        help=f"porta TCP do servidor (padrão: {DEFAULT_PORT})",
    )
    return parser.parse_args(argv)


def read_response(sock: socket.socket) -> str:
    """Lê linhas do socket até encontrar um bloco vazio terminador (\n\n)."""
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


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode("utf-8"))


def handle_local_upload(sock: socket.socket, command_line: str) -> bool:
    parts = command_line.split(maxsplit=1)
    if len(parts) < 2:
        print("Uso correto: /UPLOAD <caminho_do_arquivo>")
        return False

    local_path = Path(parts[1].strip())
    if not local_path.is_file():
        print("Erro local: arquivo inválido ou não encontrado.")
        return False

    filename = local_path.name
    file_bytes = local_path.read_bytes()
    size = len(file_bytes)

    send_line(sock, f"/UPLOAD {filename} {size}")
    sock.sendall(file_bytes)
    return True


def run_single_upload(host: str, port: int, file_path: Path) -> None:
    if not file_path.is_file():
        raise FileNotFoundError(f"arquivo inválido ou não encontrado: {file_path}")

    with socket.create_connection((host, port)) as sock:
        send_line(sock, "/CONNECT")
        read_response(sock)

        if handle_local_upload(sock, f"/UPLOAD {file_path}"):
            print(read_response(sock))

        send_line(sock, "/QUIT")
        read_response(sock)


def run_interactive(host: str, port: int) -> None:
    print(f"[+] conectando ao servidor em {host}:{port}")

    with socket.create_connection((host, port)) as sock:
        print(
            "[+] digite os comandos "
            "(ex.: /CONNECT, /UPLOAD /bin/ls, /LIST, /INFO 1, /QUIT)"
        )

        while True:
            user_input = input("> ").strip()
            if not user_input:
                continue

            if user_input.upper().startswith("/UPLOAD"):
                if handle_local_upload(sock, user_input):
                    print(read_response(sock))
                continue

            send_line(sock, user_input)
            response = read_response(sock)
            print(response)

            if user_input.upper() == "/QUIT" or "OK BYE" in response:
                break


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        if args.file is not None:
            run_single_upload(args.host, args.port, args.file)
        else:
            run_interactive(args.host, args.port)
    except FileNotFoundError as exc:
        print(f"[-] {exc}")
        return 2
    except ConnectionRefusedError:
        print(f"[-] conexão recusada por {args.host}:{args.port}")
        return 1
    except socket.gaierror as exc:
        print(f"[-] não foi possível resolver o host '{args.host}': {exc}")
        return 1
    except OSError as exc:
        print(f"[-] erro de rede ao conectar em {args.host}:{args.port}: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[-] conexão encerrada pelo usuário")
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
