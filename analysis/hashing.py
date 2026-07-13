import ssdeep

def calculate_similarity(hash1, hash2):
    """
    Compara dois hashes ssdeep e retorna a porcentagem de similaridade de 0 a 100.
    """
    if not hash1 or not hash2:
        return 0

    invalids = ("N/A", "Erro")
    if any(x in str(hash1) for x in invalids) or any(x in str(hash2) for x in invalids):
        return 0

    try:
        return ssdeep.compare(hash1, hash2)
    
    except Exception:
        return 0