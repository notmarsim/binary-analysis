# analysis/elf_parser.py
import subprocess
import hashlib
import struct
from pathlib import Path

class ElfParser:
    def __init__(self, path: Path):
        self.path = path.resolve()

    def calculate_hashes(self) -> dict:
        try:
            data = self.path.read_bytes()
            return {
                "MD5": hashlib.md5(data).hexdigest(),
                "SHA1": hashlib.sha1(data).hexdigest(),
                "SHA256": hashlib.sha256(data).hexdigest()
            }
        except Exception:
            return {"MD5": "N/A", "SHA1": "N/A", "SHA256": "N/A"}

    def parse_header_with_binutils(self) -> dict:
        """Usa o readelf nativo forçando o idioma padrão (inglês) para evitar falhas de tradução"""
        info = {
            "Class": "Desconhecido", "Endian": "Desconhecido",
            "Machine": "Desconhecido", "Entry": "0x0",
            "Type": "Desconhecido", "shnum": "0", "phnum": "0"
        }
        
        try:
            # Executa com env={"LANG": "C"} para garantir que o output venha em inglês
            result = subprocess.run(
                ["readelf", "-h", str(self.path)],
                capture_output=True,
                text=True,
                check=True,
                env={"LANG": "C"}
            )
            
            for line in result.stdout.splitlines():
                if "Class:" in line:
                    info["Class"] = line.split(":", 1)[1].strip()
                elif "Data:" in line:
                    info["Endian"] = line.split(":", 1)[1].strip()
                elif "Machine:" in line:
                    info["Machine"] = line.split(":", 1)[1].strip()
                elif "Entry point address:" in line:
                    info["Entry"] = line.split(":", 1)[1].strip()
                elif "Type:" in line:
                    info["Type"] = line.split(":", 1)[1].strip()
                elif "Number of section headers:" in line:
                    info["shnum"] = line.split(":", 1)[1].strip()
                elif "Number of program headers:" in line:
                    info["phnum"] = line.split(":", 1)[1].strip()

            # se parsear pelo readelf, retorna ele
            if info["Class"] != "Desconhecido":
                return info

        except Exception:
            pass # Se o readelf falhar, faremos o fallback para leitura binária direta abaixo

        # --- FALLBACK SEGURO: LEITURA DIRETA DOS BYTES DO ARQUIVO ---
        try:
            data = self.path.read_bytes()
            if len(data) >= 64 and data[:4] == b"\x7fELF":
                elf_class = "ELF64" if data[4] == 2 else "ELF32"
                endian = "Little" if data[5] == 1 else "Big"
                
                if elf_class == "ELF64":
                    # No ELF64, lemos a partir do byte 16 a struct estruturada:
                    # e_type(H), e_machine(H), e_version(I), e_entry(Q), e_phoff(Q), e_shoff(Q), e_flags(I), e_ehsize(H), e_phentsize(H), e_phnum(H), e_shentsize(H), e_shnum(H)
                    fields = struct.unpack("<HHIIQQQIHHHHHH", data[16:64])
                    e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields
                else:
                    # Estrutura para ELF32 bits se necessário
                    fields = struct.unpack("<HHIIIIIHHHHHH", data[16:52])
                    e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields

                type_map = {1: "REL (Relocatable file)", 2: "EXEC (Executable file)", 3: "DYN (Shared object file)", 4: "CORE"}
                machine_map = {62: "Advanced Advanced Micro Devices X86-64", 3: "Intel 80386", 40: "ARM", 183: "AArch64"}

                return {
                    "Class": elf_class,
                    "Endian": f"2's complement, {endian} endian",
                    "Machine": machine_map.get(e_machine, f"Unknown ({e_machine})"),
                    "Entry": f"0x{e_entry:x}",
                    "Type": type_map.get(e_type, f"Unknown ({e_type})"),
                    "shnum": str(e_shnum),
                    "phnum": str(e_phnum)
                }
        except Exception:
            pass

        return info