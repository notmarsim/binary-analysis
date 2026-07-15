import subprocess
import hashlib
import struct
from pathlib import Path

from analysis import hashing

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
                "SHA256": hashlib.sha256(data).hexdigest(),
                "SSDEEP": hashing.calculate_fuzzy_hash(data),
            }
        except Exception:
            return {
                "MD5": "N/A",
                "SHA1": "N/A",
                "SHA256": "N/A",
                "SSDEEP": "N/A",
            }

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
        try:
            result = subprocess.run(
                ["readelf", "-S", "-W", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
    
            lines = result.stdout.splitlines()
            output = []
            
            in_key_to_flags = False
            
            for line in lines:
                line_stripped = line.strip()
                
                if any(x in line_stripped for x in ["There are", "Section Headers:"]):
                    continue
                
                if "Key to Flags:" in line_stripped:
                    in_key_to_flags = True
                    output.append(line)
                    continue
                
                if in_key_to_flags:
              
                    output.append(line)
                    continue
                
                if line_stripped:
                    output.append(line)
                    
            return "\n".join(output)
            
        except Exception as e:
            return f"Erro ao extrair seções: {e}"

    def get_program_headers(self) -> str:
        try:

            result = subprocess.run(
                ["readelf", "-l", "-W", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            lines = result.stdout.splitlines()
            output = []
            
            in_program_headers = False
            for line in lines:
                line_stripped = line.strip()
      
                if "Program Headers:" in line_stripped:
                    in_program_headers = True
                    output.append(line)
                    continue
               
                if "Section to Segment mapping" in line_stripped:
                    break
                
                if in_program_headers:
      
                    output.append(line)
                    
            return "\n".join(output)
            
        except Exception as e:
            return f"Erro ao extrair cabeçalhos de programa: {e}"

    def get_strings(self) -> str:
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

    def get_hex_dump(self, offset: int, length: int) -> str:
        """Retorna uma visualização hexadecimal clássica formatada em colunas."""
        try:
            file_bytes = self.path.read_bytes()
            total_size = len(file_bytes)

            if offset < 0 or offset >= total_size:
                return f"ERR: Offset fora dos limites do arquivo (Tamanho: {total_size} bytes)."

            end = min(offset + length, total_size)
            chunk = file_bytes[offset:end]

            lines = []
            for i in range(0, len(chunk), 16):
                line_bytes = chunk[i:i+16]
                line_offset = offset + i

                hex_str = " ".join(f"{b:02x}" for b in line_bytes)
                if len(line_bytes) < 16:
                    hex_str = hex_str.ljust(47)

                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
                lines.append(f"{line_offset:08x}  {hex_str[:23]}  {hex_str[24:]}  |{ascii_str}|")

            return "\n".join(lines)
        except Exception as e:
            return f"Erro ao gerar hex dump: {e}"

    def get_section_dump(self, section_name: str) -> str:
        """Usa 'objdump -s -j <secao>' para extrair os dados puros de uma seção."""
        try:
            result = subprocess.run(
                ["objdump", "-s", "-j", section_name, str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if "protocol" in e.stderr or "not found" in e.stderr:
                return f"ERR: Seção '{section_name}' não encontrada no binário."
            return f"Erro ao executar objdump: {e.stderr.strip()}"
        except Exception as e:
            return f"Erro inesperado no dump de seção: {e}"

    def get_disassembly(self) -> str:
        """Usa 'objdump -d' para desmontar as instruções em assembly das seções executáveis."""
        try:
            result = subprocess.run(
                ["objdump", "-d", str(self.path)],
                capture_output=True, text=True, check=True, env={"LANG": "C"}
            )
            lines = result.stdout.splitlines()
            
            truncated_lines = lines[:150]
            if len(lines) > 150:
                truncated_lines.append("\n... [Output truncado nas primeiras 150 linhas de assembly] ...")
            return "\n".join(truncated_lines)
        except Exception as e:
            return f"Erro ao realizar disassembly: {e}"