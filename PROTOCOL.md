# Protocolo de aplicação

O sistema usa TCP. Como TCP entrega um fluxo contínuo de bytes, o protocolo
define explicitamente como comandos, uploads e respostas são delimitados.

## Codificação

Linhas de controle e respostas textuais usam UTF-8. Tamanhos representam
quantidades de **bytes**, não quantidades de caracteres.

## Comandos do cliente

Todo comando termina com um byte `LF` (`\n`):

```text
/CONNECT\n
/LIST\n
/INFO 1\n
/QUIT\n
```

O comando de upload é seguido imediatamente pelo corpo binário:

```text
/UPLOAD <nome> <tamanho>\n
<exatamente tamanho bytes>
```

A versão atual ainda restringe `<nome>` a um campo sem espaços. O suporte a
nomes com espaços será tratado em uma evolução específica do protocolo.

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
- resposta declarada acima de 8 MiB;
- conexão encerrada antes do fim do payload;
- conteúdo textual fora de UTF-8.

Cliente e servidor devem encerrar a sessão quando não for possível recuperar a
sincronização do fluxo.
