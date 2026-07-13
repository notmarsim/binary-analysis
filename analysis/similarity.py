def jaccard_similarity(a, b):
    if not a or not b:
        return 0.0

    a = set(a)
    b = set(b)

    return round(
        len(a & b) / len(a | b) * 100,
        2
    )

def compare_sections(parser1, parser2):

    sec1 = parser1.get_section_headers()
    sec2 = parser2.get_section_headers()

    def extract_sections(text):
        result = []

        for line in text.splitlines():
            parts = line.split()

            for p in parts:
                if p.startswith("."):
                    result.append(p)

        return result

    return jaccard_similarity(
        extract_sections(sec1),
        extract_sections(sec2)
    )


def compare_symbols(parser1, parser2):

    sym1 = parser1.get_symbols()
    sym2 = parser2.get_symbols()

    def extract_names(text):
        result = []

        for line in text.splitlines():

            parts = line.split()

            if len(parts) > 7:
                result.append(parts[-1])

        return result

    return jaccard_similarity(
        extract_names(sym1),
        extract_names(sym2)
    )


def compare_strings(parser1, parser2):

    str1 = parser1.get_strings()
    str2 = parser2.get_strings()

    return jaccard_similarity(
        str1.splitlines(),
        str2.splitlines()
    )