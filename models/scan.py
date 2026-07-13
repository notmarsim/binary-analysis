# models/scan.py

class Scan:
    def __init__(self, scan_id: int, filename: str, filepath: str):
        self.scan_id = scan_id
        self.filename = filename
        self.filepath = filepath
        
        # Metadados populados pelo parser posterior
        self.header = {}
        self.sections = []
        self.program_headers = []
        self.symbols = []
        self.dynamic_symbols = []
        self.security_info = {}
        self.hashes = {}
        self.file_size = 0