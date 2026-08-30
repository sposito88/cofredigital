# 🔒 Cofre Digital — AES-256-GCM

Criptografa e descriptografa arquivos e pastas com AES-256 em modo GCM, derivando a chave da senha com `bcrypt_pbkdf`. Interface gráfica em Tkinter, sem dependência de servidor — tudo roda local.

## Por que a v2

A versão anterior cifrava **sobrescrevendo o arquivo original**. Uma queda de energia, um disco cheio ou um `Ctrl+C` no meio da operação deixava o arquivo truncado e o conteúdo original perdido — sem backup e sem volta. Como também não pedia confirmação de senha, um erro de digitação ao cifrar uma pasta inteira tornava tudo irrecuperável, inclusive para quem cifrou.

A v2 mantém a mesma escolha criptográfica (que estava correta) e conserta o manuseio dos arquivos em volta dela.

## Garantias

| Garantia | Como |
|---|---|
| O original nunca é sobrescrito | A saída é um arquivo novo (`.cofre`); o original só é removido se você marcar a opção, e só depois que a saída está inteira no disco |
| Escrita atômica | Grava em `.tmp` e faz `os.replace()` no fim. Falhou no meio? O `.tmp` é removido e nada existente foi tocado |
| Senha errada não destrói nada | A tag do GCM é verificada antes do `replace`. Autenticação falhou, nenhum arquivo é escrito |
| Não cifra duas vezes | Todo `.cofre` carrega um cabeçalho mágico; cifrar uma pasta duas vezes pula o que já está cifrado |
| Não sobrescreve destino | Se o `.cofre` já existir, a operação para com erro em vez de apagar o que estava lá |
| Confirmação de senha | Pedida duas vezes ao cifrar, com aviso para senhas com menos de 8 caracteres |
| Arquivos grandes | Processamento em blocos de 1 MiB — não carrega o arquivo inteiro na RAM |
| A janela não congela | Operações de pasta rodam em thread separada, com resumo de sucessos, pulados e erros ao final |

Um arquivo com erro não interrompe o lote: o resumo diz quais falharam e por quê.

## Formato do arquivo `.cofre`

```
offset   tamanho  conteúdo
0        6        magic  "COFRE1"
6        2        rounds do bcrypt_pbkdf (uint16 big endian)
8        16       salt
24       12       nonce (IV do GCM)
36       N        ciphertext
fim-16   16       tag de autenticação
```

Os rounds do KDF ficam gravados no cabeçalho, então aumentar o custo em versões futuras não quebra os arquivos já cifrados.

## Instalação

```bash
pip install cryptography bcrypt
python cofre_digital.py
```

Requer Python 3.10+ e Tkinter (já vem no instalador oficial do Python no Windows; no Debian/Ubuntu, `sudo apt install python3-tk`).

## ⚠️ Arquivos cifrados com a versão antiga

O formato mudou e **a v2 não lê arquivos da v1**. Se você tem arquivos cifrados com a versão anterior, recupere-os antes:

```bash
python descriptografar_legado.py /caminho/da/pasta
```

Ele escreve `<arquivo>.recuperado` ao lado, sem tocar no original. Depois é só cifrar de novo com a v2.

## Limitações conhecidas

- **A senha é a única chave.** Perdeu a senha, perdeu os dados. Não há recuperação, backdoor ou dica — é essa a proposta.
- Não há gerenciamento de múltiplas chaves nem rotação.
- Metadados não são protegidos: nome do arquivo, tamanho aproximado e data de modificação continuam visíveis.
- A senha fica em memória enquanto o app está aberto. Não use em máquina compartilhada.

## Licença

MIT.
