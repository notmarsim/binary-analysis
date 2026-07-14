"""Operações de hash fuzzy usadas na comparação de binários."""

try:
    import ssdeep
except ModuleNotFoundError:  # dependência opcional
    ssdeep = None


def calculate_fuzzy_hash(data: bytes) -> str:
    """Calcula SSDEEP quando a biblioteca opcional está disponível."""
    if ssdeep is None:
        return "N/A"

    try:
        return ssdeep.hash(data)
    except Exception:
        return "N/A"


def calculate_similarity(hash1: str, hash2: str) -> int:
    """Compara dois hashes SSDEEP e retorna um valor de 0 a 100."""
    if ssdeep is None or not hash1 or not hash2:
        return 0

    invalid_values = ("N/A", "Erro")
    if any(value in str(hash1) for value in invalid_values):
        return 0
    if any(value in str(hash2) for value in invalid_values):
        return 0

    try:
        return ssdeep.compare(hash1, hash2)
    except Exception:
        return 0
