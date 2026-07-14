import subprocess
import hashlib
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"


def has_elf_magic(data: bytes) -> bool:
    """Retorna ``True`` quando o payload possui a assinatura ELF."""
    return data.startswith(ELF_MAGIC)


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
        info = {
            "Class": "Desconhecido", "Endian": "Desconhecido",
            "Machine": "Desconhecido", "Entry": "0x0",
            "Type": "Desconhecido", "shnum": "0", "phnum": "0"
        }
        try:
            result = subprocess.run(
                ["readelf", "-h", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            for line in result.stdout.splitlines():
                if "Class:" in line: info["Class"] = line.split(":", 1)[1].strip()
                elif "Data:" in line: info["Endian"] = line.split(":", 1)[1].strip()
                elif "Machine:" in line: info["Machine"] = line.split(":", 1)[1].strip()
                elif "Entry point address:" in line: info["Entry"] = line.split(":", 1)[1].strip()
                elif "Type:" in line: info["Type"] = line.split(":", 1)[1].strip()
                elif "Number of section headers:" in line: info["shnum"] = line.split(":", 1)[1].strip()
                elif "Number of program headers:" in line: info["phnum"] = line.split(":", 1)[1].strip()
            if info["Class"] != "Desconhecido":
                return info
        except Exception:
            pass

        # fallback 
        try:
            data = self.path.read_bytes()
            if len(data) >= 64 and data[:4] == b"\x7fELF":
                elf_class = "ELF64" if data[4] == 2 else "ELF32"
                endian = "Little" if data[5] == 1 else "Big"
                if elf_class == "ELF64":
                    fields = struct.unpack("<HHIIQQQIHHHHHH", data[16:64])
                    e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields
                else:
                    fields = struct.unpack("<HHIIIIIHHHHHH", data[16:52])
                    e_type, e_machine, _, e_entry, _, _, _, _, _, e_phnum, _, e_shnum, _ = fields
                type_map = {1: "REL", 2: "EXEC", 3: "DYN (Shared object)", 4: "CORE"}
                machine_map = {62: "x86-64", 3: "Intel 80386", 40: "ARM", 183: "AArch64"}
                return {
                    "Class": elf_class, "Endian": endian, "Machine": machine_map.get(e_machine, str(e_machine)),
                    "Entry": f"0x{e_entry:x}", "Type": type_map.get(e_type, str(e_type)),
                    "shnum": str(e_shnum), "phnum": str(e_phnum)
                }
        except Exception: pass
        return info


    def get_section_headers(self) -> str:
        """Etapa 6: Retorna a tabela de seções estruturada do readelf -S"""
        try:
            result = subprocess.run(
                ["readelf", "-S", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
    
            lines = result.stdout.splitlines()
            output = []
            for line in lines:
                if any(x in line for x in ["There are", "Section Headers:", "Key to Flags:"]):
                    continue
                if line.strip():
                    output.append(line)
            return "\n".join(output)
        except Exception as e:
            return f"Erro ao extrair seções: {e}"

    def get_program_headers(self) -> str:
        """Etapa 7: Retorna os segmentos de execução do readelf -l"""
        try:
            result = subprocess.run(
                ["readelf", "-l", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            lines = result.stdout.splitlines()
            output = []
            for line in lines:
                if "Section to Segment mapping" in line:
                    break
                if line.strip():
                    output.append(line)
            return "\n".join(output)
        except Exception as e:
            return f"Erro ao extrair cabeçalhos de programa: {e}"

    def get_strings(self) -> str:
        """Etapa 9: Retorna as strings legíveis do binário (filtrando linhas muito longas para rede)"""
        try:
            result = subprocess.run(
                ["strings", "-n", "4", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            lines = result.stdout.splitlines()[:100]
            if len(result.stdout.splitlines()) > 100:
                lines.append("... [Output truncado nas primeiras 100 strings] ...")
            return "\n".join(lines)
        except Exception as e:
            return f"Erro ao extrair strings: {e}"

    def get_symbols(self) -> str:
        """Etapa 10: Retorna a tabela de símbolos do readelf -s"""
        try:
            result = subprocess.run(
                ["readelf", "-s", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            lines = result.stdout.splitlines()
            output = []
            for line in lines:
                if "Symbol table" in line or "Num:" in line or ("OBJECT" in line or "FUNC" in line or "NOTYPE" in line):
                    if line.strip():
                        output.append(line)
            if len(output) > 120:
                output = output[:120]
                output.append("... [Output truncado por limite de tamanho] ...")
            return "\n".join(output)
        except Exception as e:
            return f"Erro ao extrair símbolos: {e}"