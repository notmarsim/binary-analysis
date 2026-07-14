"""Primitivas do protocolo TCP compartilhadas pelo cliente e pelo servidor."""

from __future__ import annotations

import socket

from protocol_limits import MAX_FILENAME_SIZE_BYTES

COMMAND_TERMINATOR = b"\n"
RESPONSE_PREFIX = "RESPONSE"
MAX_CONTROL_LINE_BYTES = 4096
MAX_RESPONSE_SIZE_BYTES = 8 * 1024 * 1024


class ProtocolError(Exception):
    """Indica que uma mensagem recebida viola o protocolo da aplicação."""


def encode_upload_filename(filename: str) -> bytes:
    """Valida e codifica um nome de arquivo usado no protocolo de upload."""
    if not filename or filename in {".", ".."}:
        raise ValueError("nome de arquivo inválido")
    if "/" in filename or "\x00" in filename:
        raise ValueError("o nome deve identificar apenas um arquivo")
    if any(ord(char) < 32 or ord(char) == 127 for char in filename):
        raise ValueError("o nome não pode conter caracteres de controle")

    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > MAX_FILENAME_SIZE_BYTES:
        raise ValueError(
            "nome de arquivo excede o limite de "
            f"{MAX_FILENAME_SIZE_BYTES} bytes"
        )

    return filename_bytes


def decode_upload_filename(data: bytes) -> str:
    """Decodifica e valida um nome recebido no protocolo de upload."""
    try:
        filename = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("nome de arquivo não está em UTF-8") from exc

    try:
        encode_upload_filename(filename)
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc

    return filename


def _decode_control_line(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("linha de controle não está codificada em UTF-8") from exc


def read_control_line(
    sock: socket.socket,
    *,
    max_bytes: int = MAX_CONTROL_LINE_BYTES,
) -> str | None:
    """Lê uma linha de controle terminada por LF sem consumir o payload seguinte."""
    data = bytearray()

    while True:
        chunk = sock.recv(1)
        if not chunk:
            if not data:
                return None
            raise ProtocolError("conexão encerrada antes do terminador da linha")

        if chunk == COMMAND_TERMINATOR:
            return _decode_control_line(bytes(data)).removesuffix("\r")

        data.extend(chunk)
        if len(data) > max_bytes:
            raise ProtocolError(
                f"linha de controle excede o limite de {max_bytes} bytes"
            )


def recv_exactly(sock: socket.socket, size: int) -> bytes:
    """Recebe exatamente size bytes ou sinaliza encerramento prematuro."""
    if size < 0:
        raise ValueError("size não pode ser negativo")

    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(min(4096, size - len(data)))
        if not chunk:
            raise ProtocolError(
                f"payload incompleto: esperados {size} bytes, "
                f"recebidos {len(data)}"
            )
        data.extend(chunk)

    return bytes(data)


def send_command(sock: socket.socket, command: str) -> None:
    """Envia um comando UTF-8 terminado por LF."""
    if "\n" in command or "\r" in command:
        raise ValueError("o comando não pode conter quebras de linha")

    sock.sendall(command.encode("utf-8") + COMMAND_TERMINATOR)


def read_command(sock: socket.socket) -> str | None:
    """Lê um comando enviado pelo cliente."""
    return read_control_line(sock)


def send_response(sock: socket.socket, payload: str) -> None:
    """Envia uma resposta prefixada pelo comprimento exato do payload."""
    payload_bytes = payload.encode("utf-8")
    header = f"{RESPONSE_PREFIX} {len(payload_bytes)}\n".encode("ascii")
    sock.sendall(header + payload_bytes)


def read_response(sock: socket.socket) -> str:
    """Lê e valida uma resposta com framing baseado em comprimento."""
    header = read_control_line(sock)
    if header is None:
        raise ProtocolError("conexão encerrada antes do cabeçalho da resposta")

    parts = header.split()
    if len(parts) != 2 or parts[0] != RESPONSE_PREFIX:
        raise ProtocolError(f"cabeçalho de resposta inválido: {header!r}")

    try:
        payload_size = int(parts[1])
    except ValueError as exc:
        raise ProtocolError("comprimento da resposta não é um inteiro") from exc

    if payload_size < 0:
        raise ProtocolError("comprimento da resposta não pode ser negativo")
    if payload_size > MAX_RESPONSE_SIZE_BYTES:
        raise ProtocolError(
            "resposta excede o limite de "
            f"{MAX_RESPONSE_SIZE_BYTES} bytes"
        )

    payload = recv_exactly(sock, payload_size)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("payload da resposta não está em UTF-8") from exc
