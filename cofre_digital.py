import os
import bcrypt
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Função para derivar chave usando bcrypt
def derivar_chave(senha: str, salt: bytes) -> bytes:
    return bcrypt.kdf(password=senha.encode(), salt=salt, desired_key_bytes=32, rounds=100)

# Função para criptografar um arquivo
def criptografar_arquivo(arquivo, senha):
    if not os.path.exists(arquivo):
        return

    salt = os.urandom(16)  # Gerar salt aleatório
    chave = derivar_chave(senha, salt)  # Derivar chave AES-256
    iv = os.urandom(12)  # Gerar IV aleatório

    cipher = Cipher(algorithms.AES(chave), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(arquivo, "rb") as file:
        dados = file.read()

    dados_criptografados = encryptor.update(dados) + encryptor.finalize()

    # Salvar os dados criptografados no próprio arquivo, incluindo salt, IV e tag
    with open(arquivo, "wb") as file:
        file.write(salt + iv + encryptor.tag + dados_criptografados)

# Função para descriptografar um arquivo
def descriptografar_arquivo(arquivo, senha):
    if not os.path.exists(arquivo):
        return

    with open(arquivo, "rb") as file:
        dados = file.read()

    salt = dados[:16]  # O primeiro bloco de 16 bytes é o salt
    iv = dados[16:28]  # Os próximos 12 bytes são o IV
    tag = dados[28:44]  # Os próximos 16 bytes são a tag de autenticação
    dados_criptografados = dados[44:]  # O restante são os dados reais

    chave = derivar_chave(senha, salt)  # Derivar chave AES-256

    cipher = Cipher(algorithms.AES(chave), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        dados_descriptografados = decryptor.update(dados_criptografados) + decryptor.finalize()

        with open(arquivo, "wb") as file:
            file.write(dados_descriptografados)
    except:
        messagebox.showerror("Erro", f"Falha ao descriptografar '{os.path.basename(arquivo)}'! Senha incorreta ou arquivo corrompido.")

# Função para criptografar uma pasta inteira
def criptografar_pasta():
    pasta = filedialog.askdirectory(title="Selecione uma pasta para criptografar")
    if not pasta:
        return

    senha = senha_entry.get()
    if not senha:
        messagebox.showerror("Erro", "Por favor, insira uma senha!")
        return

    arquivos = [os.path.join(root_dir, file) for root_dir, _, files in os.walk(pasta) for file in files]

    for arquivo in arquivos:
        criptografar_arquivo(arquivo, senha)

    messagebox.showinfo("Sucesso", f"Pasta '{os.path.basename(pasta)}' criptografada!")

# Função para descriptografar uma pasta inteira
def descriptografar_pasta():
    pasta = filedialog.askdirectory(title="Selecione uma pasta para descriptografar")
    if not pasta:
        return

    senha = senha_entry.get()
    if not senha:
        messagebox.showerror("Erro", "Por favor, insira a senha!")
        return

    arquivos = [os.path.join(root_dir, file) for root_dir, _, files in os.walk(pasta) for file in files]

    for arquivo in arquivos:
        descriptografar_arquivo(arquivo, senha)

    messagebox.showinfo("Sucesso", f"Pasta '{os.path.basename(pasta)}' descriptografada!")

# Criar interface gráfica moderna com Tkinter e ttk (estilo Bootstrap 5)
root = tk.Tk()
root.title("Cofre Digital - AES-256")
root.geometry("450x450")
root.configure(bg="#f8f9fa")  # Fundo inspirado no Bootstrap 5

# Estilo dos botões usando ttk
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TLabel", font=("Arial", 12), background="#f8f9fa")

# Rótulo principal
ttk.Label(root, text="Cofre Digital", font=("Arial", 16, "bold")).pack(pady=10)

# Rótulo e entrada para senha
ttk.Label(root, text="Digite uma senha segura:").pack(pady=5)
senha_entry = ttk.Entry(root, show="*", width=30, font=("Arial", 12))
senha_entry.pack(pady=5)

# Botão para criptografar um único arquivo
btn_criptografar = ttk.Button(root, text="🔒 Criptografar Arquivo", command=lambda: criptografar_arquivo(filedialog.askopenfilename(), senha_entry.get()))
btn_criptografar.pack(pady=5)

# Botão para descriptografar um único arquivo
btn_descriptografar = ttk.Button(root, text="🔓 Descriptografar Arquivo", command=lambda: descriptografar_arquivo(filedialog.askopenfilename(), senha_entry.get()))
btn_descriptografar.pack(pady=5)

# Botão para criptografar uma pasta inteira
btn_criptografar_pasta = ttk.Button(root, text="🗂️ Criptografar Pasta", command=criptografar_pasta)
btn_criptografar_pasta.pack(pady=5)

# Botão para descriptografar uma pasta inteira
btn_descriptografar_pasta = ttk.Button(root, text="🗂️ Descriptografar Pasta", command=descriptografar_pasta)
btn_descriptografar_pasta.pack(pady=5)

# Rodar interface
root.mainloop()
