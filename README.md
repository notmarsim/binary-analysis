<div align="center">

# Binary Analysis Server

**Sistema cliente-servidor TCP para análise estática remota de executáveis ELF**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Protocol](https://img.shields.io/badge/Protocol-TCP-005571)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![Tests](https://img.shields.io/badge/tests-38%20passing-success)

Projeto acadêmico desenvolvido para a disciplina de **Redes de Computadores I**.

</div>

---

## Visão geral

O projeto implementa um protocolo de aplicação sobre TCP para envio e análise de arquivos executáveis no formato **ELF**.

O cliente localiza o arquivo no computador do usuário, envia seus metadados e conteúdo ao servidor e permite consultar informações extraídas por ferramentas do GNU Binutils. O servidor não executa o binário recebido: toda análise é estática.

Principais recursos:

- servidor TCP multicliente, com uma thread por sessão;
- endpoint do cliente configurável por host e porta;
- upload binário com negociação em duas fases;
- suporte a nomes de arquivo com espaços e UTF-8;
- framing de respostas baseado em comprimento;
- validação do magic number ELF;
- limite de upload de 20 MiB;
- timeouts de conexão, operações e inatividade;
- proteção do estado compartilhado com `threading.RLock`;
- extração de cabeçalhos, seções, segmentos, símbolos e strings;
- cálculo de MD5, SHA-1, SHA-256 e SSDEEP;
- comparação estrutural entre dois binários;
- testes unitários e testes de integração com sockets TCP reais.

## Escopo

O sistema foi projetado para:

- arquivos ELF em sistemas Linux;
- análise estática;
- demonstrações acadêmicas de comunicação cliente-servidor;
- estudo de framing, transferência binária, concorrência e protocolos de aplicação.

O sistema não executa os arquivos enviados, não realiza sandboxing e não substitui ferramentas profissionais de engenharia reversa ou análise de malware.

## Arquitetura

```text
┌────────────────────┐
│     ELF Client     │
│                    │
│ CLI interativa     │
│ leitura do arquivo │
│ framing TCP        │
└─────────┬──────────┘
          │ TCP
          │ porta 9000
          ▼
┌────────────────────┐
│    ELF Server      │
│                    │
│ uma thread/sessão  │
│ validação ELF      │
│ controle de estado │
└─────────┬──────────┘
          │
          ├── GNU readelf
          ├── GNU strings
          ├── hashlib
          └── ssdeep opcional
```

Fluxo de upload:

```text
usuário   -> /UPLOAD /caminho/meu arquivo ELF

cliente   -> /UPLOAD <bytes_nome> <bytes_arquivo>\n
servidor  -> RESPONSE 8\nOK READY
cliente   -> <nome UTF-8><conteúdo binário>
servidor  -> RESPONSE <N>\nOK UPLOADED scan_id=<id> filename=<nome>
```

O usuário informa apenas o caminho local. Os tamanhos são calculados automaticamente pelo cliente.

## Requisitos

- Linux;
- Python 3.10 ou superior;
- GNU Binutils:
  - `readelf`;
  - `strings`;
- `ssdeep` opcional para hash fuzzy e comparação SSDEEP.

O restante da implementação usa apenas a biblioteca padrão do Python.

Verifique as ferramentas:

```bash
python --version
readelf --version
strings --version
```

A ausência da biblioteca Python `ssdeep` não impede o servidor de iniciar. Nesse caso, o campo SSDEEP será exibido como `N/A` e a pontuação SSDEEP da comparação será `0`.

## Estrutura do projeto

```text
binary-analysis/
├── analysis/
│   ├── elf_parser.py
│   ├── hashing.py
│   └── similarity.py
├── models/
│   └── scan.py
├── server/
│   ├── client_session.py
│   └── elf_server.py
├── tests/
│   ├── test_client_session.py
│   ├── test_elf_client.py
│   ├── test_elf_parser.py
│   ├── test_tcp_integration.py
│   └── test_wire_protocol.py
├── elf_client.py
├── protocol_limits.py
├── wire_protocol.py
├── PROTOCOL.md
└── uploads/
```

## Execução local

Na raiz do projeto, abra dois terminais.

### 1. Iniciar o servidor

```bash
python server/elf_server.py
```

Saída esperada:

```text
[+] servidor escutando em 0.0.0.0:9000
```

### 2. Iniciar o cliente

```bash
python elf_client.py
```

O cliente usa por padrão:

```text
host: 127.0.0.1
porta: 9000
```

### 3. Executar uma sessão

```text
/CONNECT
/UPLOAD /bin/ls
/LIST
/INFO 1
/HASHES 1
/SECTION_HEADERS 1
/PROGRAM_HEADERS 1
/SYMBOLS 1
/QUIT
```

## Execução em computadores diferentes

O servidor já escuta em todas as interfaces IPv4:

```text
0.0.0.0:9000
```

No computador servidor, descubra o endereço IP:

```bash
hostname -I
```

No computador cliente:

```bash
python elf_client.py --host 192.168.1.20 --port 9000
```

Substitua `192.168.1.20` pelo endereço real do servidor.

Os dois computadores devem estar na mesma rede ou possuir uma rota válida entre eles. A porta TCP 9000 também precisa estar liberada no firewall.

## Comandos

| Comando | Descrição |
|---|---|
| `/CONNECT` | Inicializa a sessão lógica com o servidor |
| `/UPLOAD <caminho>` | Envia um arquivo ELF local |
| `/LIST` | Lista os scans armazenados |
| `/INFO <id>` | Exibe resumo do cabeçalho ELF |
| `/HASHES <id>` | Exibe MD5, SHA-1, SHA-256 e SSDEEP |
| `/SECTION_HEADERS <id>` | Exibe a tabela de seções |
| `/PROGRAM_HEADERS <id>` | Exibe os segmentos do executável |
| `/STRINGS <id>` | Extrai strings imprimíveis |
| `/SYMBOLS <id>` | Exibe símbolos e funções |
| `/COMPARE <id1> <id2>` | Compara dois binários |
| `/HELP` | Exibe a ajuda no cliente |
| `/QUIT` | Encerra a sessão |

### Exemplo de comparação

Envie duas versões de um executável:

```text
/CONNECT
/UPLOAD /tmp/programa_v1
/UPLOAD /tmp/programa_v2
/LIST
/COMPARE 1 2
```

A comparação considera:

- SSDEEP;
- nomes de seções;
- símbolos;
- strings.

As três comparações estruturais usam similaridade de Jaccard.

## Protocolo de aplicação

O TCP fornece um fluxo contínuo de bytes e não preserva fronteiras entre mensagens. O projeto define explicitamente essas fronteiras.

### Comandos

Comandos são linhas UTF-8 terminadas por `LF`:

```text
/CONNECT\n
/INFO 1\n
/QUIT\n
```

### Respostas

Toda resposta possui um cabeçalho ASCII com o tamanho exato do payload UTF-8:

```text
RESPONSE <tamanho>\n
<payload>
```

Exemplo:

```text
RESPONSE 12\n
OK CONNECTED
```

O tamanho representa bytes, não caracteres.

### Upload

O upload usa negociação em duas fases:

1. o cliente envia os tamanhos;
2. o servidor valida os metadados;
3. o servidor responde `OK READY`;
4. o cliente envia nome e conteúdo;
5. o servidor valida, armazena e analisa o arquivo.

A especificação detalhada está em [`PROTOCOL.md`](PROTOCOL.md).

## Limites e timeouts

| Parâmetro | Valor |
|---|---:|
| Tamanho máximo do arquivo | 20 MiB |
| Tamanho máximo do nome | 255 bytes UTF-8 |
| Linha de controle | 4096 bytes |
| Resposta do servidor | 8 MiB |
| Timeout de conexão do cliente | 5 s |
| Timeout de I/O do cliente | 30 s |
| Timeout de sessão do servidor | 120 s |

Arquivos vazios, arquivos acima do limite e payloads sem o magic number `0x7F 45 4C 46` são rejeitados.

## Testes

Execute toda a suíte:

```bash
python -m unittest discover -s tests -v
```

Estado atual:

```text
Ran 38 tests

OK
```

A suíte cobre:

- parsing dos argumentos do cliente;
- validação de portas;
- limites de upload;
- framing de comandos e respostas;
- nomes com espaços e UTF-8;
- timeouts;
- validação do magic ELF;
- concorrência na geração de IDs;
- cálculo e exposição de hashes;
- conexão, upload, consulta e encerramento via TCP real.

Também é possível verificar a sintaxe de todos os módulos:

```bash
python -m compileall -q \
    elf_client.py \
    wire_protocol.py \
    protocol_limits.py \
    analysis \
    server \
    models \
    tests
```

## Segurança e comportamento

- o servidor não executa o arquivo recebido;
- o nome enviado não pode conter caminhos, byte nulo ou caracteres de controle;
- somente payloads com assinatura ELF são armazenados;
- IDs e scans compartilhados são protegidos por lock;
- uploads rejeitados não deixam bytes residuais no fluxo;
- sessões inativas são encerradas por timeout;
- os scans são mantidos em memória e reiniciados quando o servidor é encerrado;
- os arquivos recebidos são gravados no diretório `uploads/`.

---

<div align="center">

**Binary Analysis Server - Redes de Computadores I**

</div>
