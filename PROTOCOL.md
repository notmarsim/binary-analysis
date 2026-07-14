# Protocolo de aplicação

O sistema usa TCP. Como TCP entrega um fluxo contínuo de bytes, o protocolo
define explicitamente como comandos, uploads e respostas são delimitados.

## Codificação

Linhas de controle, nomes de arquivo e respostas textuais usam UTF-8. Tamanhos
representam quantidades de **bytes**, não quantidades de caracteres.

## Comandos do cliente

Todo comando termina com um byte `LF` (`\n`):

```text
/CONNECT\n
/LIST\n
/INFO 1\n
/QUIT\n
```

## Upload binário

O upload usa uma negociação em duas fases para impedir que bytes rejeitados
permaneçam no fluxo e sejam interpretados como comandos.

### 1. Metadados

O cliente envia somente o comprimento do nome e o comprimento do arquivo:

```text
/UPLOAD <tamanho_nome> <tamanho_arquivo>\n
```

Os dois valores são quantidades de bytes. O nome não aparece na linha de
controle, portanto pode conter espaços e caracteres UTF-8.

### 2. Autorização do servidor

O servidor valida a sessão e os limites antes de aceitar qualquer payload:

```text
RESPONSE 8\n
OK READY
```

Se os metadados forem inválidos, o servidor envia uma resposta `ERR ...` e
continua aguardando comandos. Como o cliente ainda não enviou o payload, a
sessão permanece sincronizada.

### 3. Nome e corpo

Somente depois de receber `OK READY`, o cliente envia:

```text
<exatamente tamanho_nome bytes UTF-8>
<exatamente tamanho_arquivo bytes binários>
```

O nome deve identificar apenas um arquivo, ter de 1 a 255 bytes e não pode
conter `/`, byte nulo ou caracteres de controle.

### 4. Resultado

Depois de armazenar e analisar o arquivo, o servidor retorna uma resposta
normal, por exemplo:

```text
OK UPLOADED scan_id=1 filename=meu programa
```

Se o nome ou o corpo estiver incompleto ou inválido depois de `OK READY`, o
servidor responde com erro e encerra a sessão, pois pode haver bytes residuais
impossíveis de reinterpretar com segurança.

## Respostas do servidor

Toda resposta possui um cabeçalho ASCII e um payload UTF-8:

```text
RESPONSE <tamanho>\n
<payload com exatamente tamanho bytes>
```

Exemplo:

```text
RESPONSE 12\n
OK CONNECTED
```

O payload pode conter múltiplas linhas, inclusive linhas vazias. O cliente não
procura marcadores dentro do conteúdo; ele lê exatamente a quantidade indicada
no cabeçalho.

## Erros de framing

A conexão é considerada inválida quando ocorre uma destas situações:

- cabeçalho diferente de `RESPONSE <inteiro>`;
- linha de controle maior que 4096 bytes;
- nome de arquivo maior que 255 bytes;
- resposta declarada acima de 8 MiB;
- conexão encerrada antes do fim de um nome ou payload;
- conteúdo textual fora de UTF-8;
- envio do nome ou corpo antes de `OK READY`.

Cliente e servidor devem encerrar a sessão quando não for possível recuperar a
sincronização do fluxo.
