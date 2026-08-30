"""
Cofre Digital - resgate de arquivos da versao antiga.

A versao antiga gravava:  salt(16) + iv(12) + tag(16) + ciphertext
sem cabecalho magico, e sobrescrevia o arquivo original.

O formato novo (.cofre) e incompativel. Use este script UMA VEZ para trazer
os arquivos antigos de volta ao texto claro; depois cifre de novo com a
versao nova.

Uso:
    python descriptografar_legado.py <arquivo-ou-pasta> [--apagar]

O original nunca e alterado: a saida vai para <arquivo>.recuperado.
"""

import os
import sys

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from getpass import getpass

CABECALHO_LEGADO = 44  # 16 salt + 12 iv + 16 tag


def recuperar(caminho: str, senha: str) -> str:
    with open(caminho, "rb") as f:
        dados = f.read()

    if len(dados) < CABECALHO_LEGADO:
        raise ValueError("curto demais para o formato antigo")

    salt, iv, tag, corpo = dados[:16], dados[16:28], dados[28:44], dados[44:]
    chave = bcrypt.kdf(password=senha.encode(), salt=salt, desired_key_bytes=32, rounds=100)

    decryptor = Cipher(algorithms.AES(chave), modes.GCM(iv, tag)).decryptor()
    claro = decryptor.update(corpo) + decryptor.finalize()  # levanta InvalidTag se falhar

    destino = caminho + ".recuperado"
    tmp = destino + ".tmp"
    with open(tmp, "wb") as saida:
        saida.write(claro)
        saida.flush()
        os.fsync(saida.fileno())
    os.replace(tmp, destino)
    return destino


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    alvo = sys.argv[1]
    apagar = "--apagar" in sys.argv
    senha = getpass("Senha usada na versao antiga: ")

    if os.path.isfile(alvo):
        arquivos = [alvo]
    else:
        arquivos = [
            os.path.join(r, n)
            for r, _, fs in os.walk(alvo)
            for n in fs
            if not n.endswith((".recuperado", ".tmp", ".cofre"))
        ]

    ok = falhas = 0
    for caminho in arquivos:
        try:
            destino = recuperar(caminho, senha)
            print(f"  ok      {os.path.basename(destino)}")
            if apagar:
                os.remove(caminho)
            ok += 1
        except InvalidTag:
            print(f"  FALHOU  {os.path.basename(caminho)}: senha incorreta ou nao e do formato antigo")
            falhas += 1
        except Exception as e:
            print(f"  FALHOU  {os.path.basename(caminho)}: {e}")
            falhas += 1

    print(f"\n{ok} recuperado(s), {falhas} falha(s).")


if __name__ == "__main__":
    main()
