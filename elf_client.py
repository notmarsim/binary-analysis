import argparse
import socket
from pathlib import Path
from typing import Sequence

from protocol_limits import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_FILE_SIZE_BYTES,
    SOCKET_IO_TIMEOUT_SECONDS,
)
from wire_protocol import (
    ProtocolError,
    encode_upload_filename,
    read_response,
    send_command,
)

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


def handle_local_upload(sock: socket.socket, command_line: str) -> bool:
    parts = command_line.split(maxsplit=1)
    if len(parts) < 2:
        print("Uso correto: /UPLOAD <caminho_do_arquivo>")
        return False

    local_path = Path(parts[1].strip())
    if not local_path.is_file():
        print("Erro local: arquivo inválido ou não encontrado.")
        return False

    reported_size = local_path.stat().st_size
    if reported_size <= 0:
        print("Erro local: o arquivo está vazio.")
        return False
    if reported_size > MAX_FILE_SIZE_BYTES:
        print(
            "Erro local: arquivo excede o limite de "
            f"{MAX_FILE_SIZE_BYTES} bytes."
        )
        return False

    filename = local_path.name
    try:
        filename_bytes = encode_upload_filename(filename)
    except ValueError as exc:
        print(f"Erro local: {exc}.")
        return False

    file_bytes = local_path.read_bytes()
    size = len(file_bytes)
    if size <= 0:
        print("Erro local: o arquivo ficou vazio durante a leitura.")
        return False
    if size > MAX_FILE_SIZE_BYTES:
        print(
            "Erro local: arquivo excedeu o limite de "
            f"{MAX_FILE_SIZE_BYTES} bytes durante a leitura."
        )
        return False

    send_command(sock, f"/UPLOAD {len(filename_bytes)} {size}")
    readiness = read_response(sock)
    if readiness != "OK READY":
        print(readiness)
        return False

    sock.sendall(filename_bytes)
    sock.sendall(file_bytes)
    return True


def run_interactive(host: str, port: int) -> None:
    print(f"[+] conectando ao servidor em {host}:{port}")

    with socket.create_connection(
        (host, port), timeout=CONNECT_TIMEOUT_SECONDS
    ) as sock:
        sock.settimeout(SOCKET_IO_TIMEOUT_SECONDS)
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

            send_command(sock, user_input)
            response = read_response(sock)
            print(response)

            if user_input.upper() == "/QUIT" or "OK BYE" in response:
                break


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        run_interactive(args.host, args.port)
    except ProtocolError as exc:
        print(f"[-] erro de protocolo: {exc}")
        return 1
    except TimeoutError:
        print(
            "[-] tempo limite excedido ao comunicar com "
            f"{args.host}:{args.port}"
        )
        return 1
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
