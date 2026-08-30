"""
Cofre Digital - AES-256-GCM

Criptografa e descriptografa arquivos e pastas com AES-256 em modo GCM,
derivando a chave da senha com bcrypt_pbkdf.

Garantias de segurança de dados:
  - O arquivo original NUNCA e sobrescrito. A saida e um arquivo novo (.cofre).
  - A escrita e atomica: grava em .tmp e so entao renomeia para o destino final.
  - Se algo falhar no meio, nenhum arquivo existente foi tocado.
  - A senha e pedida duas vezes ao cifrar; um typo nao gera dados perdidos.
  - Arquivos cifrados carregam um cabecalho magico, entao a ferramenta sabe
    distinguir o que ja esta cifrado e nunca cifra duas vezes por acidente.
  - O processamento e em blocos, entao arquivos grandes nao estouram a memoria.

Formato do arquivo .cofre:
  offset  tamanho  conteudo
  0       6        magic  b"COFRE1"
  6       2        rounds do bcrypt_pbkdf (uint16, big endian)
  8       16       salt
  24      12       nonce (IV do GCM)
  36      N        ciphertext
  fim-16  16       tag de autenticacao do GCM

Requisitos: pip install cryptography bcrypt
"""

import os
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ----------------------------------------------------------------------------
# Constantes do formato
# ----------------------------------------------------------------------------

MAGIC = b"COFRE1"
KDF_ROUNDS = 100          # gravado no cabecalho: arquivos antigos seguem legiveis
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_BYTES = len(MAGIC) + 2 + SALT_BYTES + NONCE_BYTES  # 36
CHUNK = 1024 * 1024       # 1 MiB
EXT = ".cofre"


class CofreError(Exception):
    """Erro previsto e explicavel para o usuario."""


# ----------------------------------------------------------------------------
# Núcleo criptográfico
# ----------------------------------------------------------------------------

def derivar_chave(senha: str, salt: bytes, rounds: int = KDF_ROUNDS) -> bytes:
    """Deriva uma chave AES-256 a partir da senha usando bcrypt_pbkdf."""
    if not senha:
        raise CofreError("A senha nao pode ser vazia.")
    return bcrypt.kdf(
        password=senha.encode("utf-8"),
        salt=salt,
        desired_key_bytes=32,
        rounds=rounds,
    )


def esta_cifrado(caminho: str) -> bool:
    """True se o arquivo comeca com o cabecalho magico do Cofre."""
    try:
        with open(caminho, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _escrever_atomico(destino: str, escrever_em):
    """
    Executa escrever_em(handle) sobre um arquivo temporario e so entao move
    para `destino`. Se qualquer excecao ocorrer, o temporario e removido e
    nada no disco do usuario foi alterado.
    """
    if os.path.exists(destino):
        raise CofreError(f"'{os.path.basename(destino)}' ja existe. Nada foi alterado.")

    tmp = destino + ".tmp"
    try:
        with open(tmp, "wb") as saida:
            escrever_em(saida)
            saida.flush()
            os.fsync(saida.fileno())
        os.replace(tmp, destino)
    except BaseException:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise


def criptografar_arquivo(origem: str, senha: str, apagar_original: bool = False) -> str:
    """
    Cifra `origem` gerando `origem + .cofre`. Retorna o caminho gerado.
    O original permanece intacto, a menos que apagar_original seja True — e
    nesse caso ele so e removido depois que o .cofre esta inteiro no disco.
    """
    if not os.path.isfile(origem):
        raise CofreError(f"Arquivo nao encontrado: {origem}")
    if esta_cifrado(origem):
        raise CofreError(f"'{os.path.basename(origem)}' ja esta cifrado.")

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    chave = derivar_chave(senha, salt, KDF_ROUNDS)

    destino = origem + EXT

    def escrever(saida):
        saida.write(MAGIC)
        saida.write(struct.pack(">H", KDF_ROUNDS))
        saida.write(salt)
        saida.write(nonce)

        encryptor = Cipher(algorithms.AES(chave), modes.GCM(nonce)).encryptor()
        with open(origem, "rb") as entrada:
            while True:
                bloco = entrada.read(CHUNK)
                if not bloco:
                    break
                saida.write(encryptor.update(bloco))
        saida.write(encryptor.finalize())
        saida.write(encryptor.tag)

    _escrever_atomico(destino, escrever)

    if apagar_original:
        os.remove(origem)

    return destino


def descriptografar_arquivo(origem: str, senha: str, apagar_cifrado: bool = False) -> str:
    """
    Decifra `origem` (.cofre) e escreve o conteudo original ao lado.
    Retorna o caminho gerado. O .cofre permanece intacto por padrao.

    A verificacao da tag do GCM so acontece no finalize(); por isso o texto
    claro e escrito no temporario e o rename SO ocorre se a autenticacao
    passar. Senha errada ou arquivo corrompido nunca produzem saida.
    """
    if not os.path.isfile(origem):
        raise CofreError(f"Arquivo nao encontrado: {origem}")

    tamanho = os.path.getsize(origem)
    if tamanho < HEADER_BYTES + TAG_BYTES:
        raise CofreError(f"'{os.path.basename(origem)}' e curto demais para ser um .cofre.")

    with open(origem, "rb") as f:
        cabecalho = f.read(HEADER_BYTES)

    if cabecalho[:len(MAGIC)] != MAGIC:
        raise CofreError(f"'{os.path.basename(origem)}' nao e um arquivo do Cofre.")

    rounds = struct.unpack(">H", cabecalho[6:8])[0]
    salt = cabecalho[8:8 + SALT_BYTES]
    nonce = cabecalho[8 + SALT_BYTES:HEADER_BYTES]

    with open(origem, "rb") as f:
        f.seek(tamanho - TAG_BYTES)
        tag = f.read(TAG_BYTES)

    chave = derivar_chave(senha, salt, rounds)

    if origem.endswith(EXT):
        destino = origem[:-len(EXT)]
    else:
        destino = origem + ".decifrado"

    corpo = tamanho - HEADER_BYTES - TAG_BYTES

    def escrever(saida):
        decryptor = Cipher(algorithms.AES(chave), modes.GCM(nonce, tag)).decryptor()
        restante = corpo
        with open(origem, "rb") as entrada:
            entrada.seek(HEADER_BYTES)
            while restante > 0:
                bloco = entrada.read(min(CHUNK, restante))
                if not bloco:
                    raise CofreError("Arquivo truncado.")
                restante -= len(bloco)
                saida.write(decryptor.update(bloco))
        try:
            saida.write(decryptor.finalize())
        except InvalidTag:
            raise CofreError(
                f"Falha ao autenticar '{os.path.basename(origem)}': "
                "senha incorreta ou arquivo corrompido."
            )

    _escrever_atomico(destino, escrever)

    if apagar_cifrado:
        os.remove(origem)

    return destino


def processar_pasta(pasta: str, senha: str, cifrar: bool, apagar_entrada: bool = False):
    """
    Percorre a pasta e cifra (ou decifra) os arquivos elegiveis.
    Retorna (feitos, pulados, erros) — erros e uma lista de (arquivo, motivo).
    Um arquivo com problema nao interrompe os demais.
    """
    feitos, pulados, erros = 0, 0, []

    for raiz, _, arquivos in os.walk(pasta):
        for nome in arquivos:
            caminho = os.path.join(raiz, nome)

            if nome.endswith(".tmp"):
                pulados += 1
                continue

            ja_cifrado = esta_cifrado(caminho)
            if cifrar and ja_cifrado:
                pulados += 1
                continue
            if not cifrar and not ja_cifrado:
                pulados += 1
                continue

            try:
                if cifrar:
                    criptografar_arquivo(caminho, senha, apagar_entrada)
                else:
                    descriptografar_arquivo(caminho, senha, apagar_entrada)
                feitos += 1
            except CofreError as e:
                erros.append((nome, str(e)))
            except OSError as e:
                erros.append((nome, f"erro de disco: {e}"))

    return feitos, pulados, erros


# ----------------------------------------------------------------------------
# Interface gráfica
# ----------------------------------------------------------------------------

class CofreApp:
    def __init__(self, root):
        self.root = root
        self.ocupado = False

        root.title("Cofre Digital - AES-256-GCM")
        root.geometry("470x520")
        root.configure(bg="#f8f9fa")

        estilo = ttk.Style()
        estilo.configure("TButton", font=("Segoe UI", 11), padding=8)
        estilo.configure("TLabel", font=("Segoe UI", 10), background="#f8f9fa")
        estilo.configure("Titulo.TLabel", font=("Segoe UI", 16, "bold"), background="#f8f9fa")
        estilo.configure("Aviso.TLabel", font=("Segoe UI", 9), background="#f8f9fa",
                         foreground="#6c757d")

        ttk.Label(root, text="Cofre Digital", style="Titulo.TLabel").pack(pady=(16, 4))
        ttk.Label(root, text="AES-256-GCM · o original nunca e sobrescrito",
                  style="Aviso.TLabel").pack(pady=(0, 12))

        ttk.Label(root, text="Senha:").pack()
        self.senha = ttk.Entry(root, show="*", width=34, font=("Segoe UI", 11))
        self.senha.pack(pady=(2, 8))

        ttk.Label(root, text="Confirme a senha (ao cifrar):").pack()
        self.senha2 = ttk.Entry(root, show="*", width=34, font=("Segoe UI", 11))
        self.senha2.pack(pady=(2, 12))

        self.apagar_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            root,
            text="Apagar o arquivo de entrada apos concluir",
            variable=self.apagar_var,
        ).pack(pady=(0, 12))

        ttk.Button(root, text="Cifrar arquivo",
                   command=lambda: self._arquivo(cifrar=True)).pack(pady=3)
        ttk.Button(root, text="Decifrar arquivo",
                   command=lambda: self._arquivo(cifrar=False)).pack(pady=3)
        ttk.Button(root, text="Cifrar pasta",
                   command=lambda: self._pasta(cifrar=True)).pack(pady=3)
        ttk.Button(root, text="Decifrar pasta",
                   command=lambda: self._pasta(cifrar=False)).pack(pady=3)

        self.status = ttk.Label(root, text="", style="Aviso.TLabel", wraplength=420,
                                justify="center")
        self.status.pack(pady=(16, 8))

    # -- helpers ------------------------------------------------------------

    def _obter_senha(self, cifrar: bool):
        senha = self.senha.get()
        if not senha:
            messagebox.showerror("Erro", "Digite uma senha.")
            return None
        if cifrar:
            if senha != self.senha2.get():
                messagebox.showerror("Erro", "As duas senhas nao conferem.")
                return None
            if len(senha) < 8:
                if not messagebox.askyesno(
                    "Senha curta",
                    "Essa senha tem menos de 8 caracteres e e facil de quebrar.\n"
                    "Continuar mesmo assim?",
                ):
                    return None
        return senha

    def _set_status(self, texto):
        self.status.config(text=texto)
        self.root.update_idletasks()

    def _em_thread(self, alvo):
        """Roda a operacao fora da thread da GUI para a janela nao congelar."""
        if self.ocupado:
            return
        self.ocupado = True

        def runner():
            try:
                alvo()
            finally:
                self.ocupado = False

        threading.Thread(target=runner, daemon=True).start()

    # -- ações --------------------------------------------------------------

    def _arquivo(self, cifrar: bool):
        senha = self._obter_senha(cifrar)
        if senha is None:
            return

        titulo = "Selecione o arquivo para cifrar" if cifrar else "Selecione o .cofre para decifrar"
        caminho = filedialog.askopenfilename(title=titulo)
        if not caminho:
            return

        def tarefa():
            self._set_status("Processando...")
            try:
                if cifrar:
                    destino = criptografar_arquivo(caminho, senha, self.apagar_var.get())
                else:
                    destino = descriptografar_arquivo(caminho, senha, self.apagar_var.get())
                self._set_status(f"Pronto: {os.path.basename(destino)}")
                messagebox.showinfo("Sucesso", f"Gerado:\n{destino}")
            except CofreError as e:
                self._set_status("")
                messagebox.showerror("Erro", str(e))
            except OSError as e:
                self._set_status("")
                messagebox.showerror("Erro de disco", str(e))

        self._em_thread(tarefa)

    def _pasta(self, cifrar: bool):
        senha = self._obter_senha(cifrar)
        if senha is None:
            return

        pasta = filedialog.askdirectory(title="Selecione a pasta")
        if not pasta:
            return

        acao = "cifrar" if cifrar else "decifrar"
        if not messagebox.askyesno(
            "Confirmar",
            f"Vai {acao} todos os arquivos elegiveis em:\n{pasta}\n\n"
            + ("Os originais serao APAGADOS apos a conclusao."
               if self.apagar_var.get() else "Os originais serao mantidos."),
        ):
            return

        def tarefa():
            self._set_status(f"Processando pasta ({acao})...")
            feitos, pulados, erros = processar_pasta(
                pasta, senha, cifrar, self.apagar_var.get()
            )
            resumo = f"{feitos} arquivo(s) processado(s), {pulados} pulado(s)."
            if erros:
                detalhe = "\n".join(f"- {n}: {m}" for n, m in erros[:10])
                extra = f"\n... e mais {len(erros) - 10}." if len(erros) > 10 else ""
                self._set_status(resumo + f" {len(erros)} com erro.")
                messagebox.showwarning(
                    "Concluido com erros",
                    f"{resumo}\n\n{len(erros)} falharam:\n{detalhe}{extra}",
                )
            else:
                self._set_status(resumo)
                messagebox.showinfo("Sucesso", resumo)

        self._em_thread(tarefa)


def main():
    root = tk.Tk()
    CofreApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
