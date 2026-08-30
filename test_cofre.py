import os, shutil, tempfile, sys
sys.modules['tkinter'] = type(sys)('tkinter')  # stub para importar sem display
for sub in ('filedialog','messagebox','ttk'):
    setattr(sys.modules['tkinter'], sub, type(sys)('tkinter.'+sub))
    sys.modules['tkinter.'+sub] = getattr(sys.modules['tkinter'], sub)
sys.modules['tkinter'].Tk = object
sys.modules['tkinter'].BooleanVar = object

import cofre_digital as c

d = tempfile.mkdtemp()
def p(n): return os.path.join(d, n)

# 1. round-trip básico
orig = b"conteudo secreto\n" * 1000
open(p("a.txt"), "wb").write(orig)
enc = c.criptografar_arquivo(p("a.txt"), "senha-forte-123")
assert enc == p("a.txt.cofre"), enc
assert os.path.exists(p("a.txt")), "original foi apagado sem pedir"
assert c.esta_cifrado(enc)
os.rename(p("a.txt"), p("a.orig"))
dec = c.descriptografar_arquivo(enc, "senha-forte-123")
assert open(dec,"rb").read() == orig, "round-trip falhou"
print("1 ok  round-trip preserva conteudo e mantem o original")

# 2. senha errada não gera saída
os.remove(dec)
try:
    c.descriptografar_arquivo(enc, "senha-errada")
    raise AssertionError("aceitou senha errada")
except c.CofreError as e:
    assert "senha incorreta" in str(e).lower(), e
assert not os.path.exists(dec), "escreveu arquivo com senha errada!"
assert not os.path.exists(dec + ".tmp"), "deixou .tmp para tras"
print("2 ok  senha errada nao produz saida nem lixo .tmp")

# 3. arquivo corrompido é detectado
shutil.copy(enc, p("corrompido.cofre"))
with open(p("corrompido.cofre"), "r+b") as f:
    f.seek(c.HEADER_BYTES + 5); f.write(b"\xff")
try:
    c.descriptografar_arquivo(p("corrompido.cofre"), "senha-forte-123")
    raise AssertionError("nao detectou corrupcao")
except c.CofreError:
    pass
assert not os.path.exists(p("corrompido"))
print("3 ok  corrupcao detectada pela tag do GCM")

# 4. não cifra duas vezes
try:
    c.criptografar_arquivo(enc, "senha-forte-123")
    raise AssertionError("cifrou duas vezes")
except c.CofreError as e:
    assert "ja esta cifrado" in str(e)
print("4 ok  recusa cifrar um .cofre")

# 5. não sobrescreve destino existente
open(p("b.txt"),"wb").write(b"x")
open(p("b.txt.cofre"),"wb").write(b"NAO ME APAGUE")
try:
    c.criptografar_arquivo(p("b.txt"), "senha-forte-123")
    raise AssertionError("sobrescreveu destino")
except c.CofreError as e:
    assert "ja existe" in str(e)
assert open(p("b.txt.cofre"),"rb").read() == b"NAO ME APAGUE"
print("5 ok  nunca sobrescreve um destino existente")

# 6. senha vazia
try:
    c.derivar_chave("", b"0"*16); raise AssertionError("aceitou senha vazia")
except c.CofreError: pass
print("6 ok  senha vazia rejeitada")

# 7. pasta: cifra, pula os já cifrados, decifra de volta
sub = p("pasta"); os.makedirs(sub)
esperado = {}
for i in range(5):
    nome = f"f{i}.bin"; dados = os.urandom(20000 + i)
    open(os.path.join(sub, nome),"wb").write(dados); esperado[nome] = dados
f,pl,er = c.processar_pasta(sub, "senha-forte-123", cifrar=True, apagar_entrada=True)
assert (f,pl,er) == (5,0,[]), (f,pl,er)
f2,pl2,er2 = c.processar_pasta(sub, "senha-forte-123", cifrar=True)   # segunda passada
assert f2 == 0 and pl2 == 5 and not er2, (f2,pl2,er2)
f3,pl3,er3 = c.processar_pasta(sub, "senha-forte-123", cifrar=False, apagar_entrada=True)
assert (f3,pl3,er3) == (5,0,[]), (f3,pl3,er3)
for nome, dados in esperado.items():
    assert open(os.path.join(sub,nome),"rb").read() == dados, nome
print("7 ok  pasta: 5 cifrados, 2a passada pula todos, 5 decifrados intactos")

# 8. arquivo grande (multi-chunk) e arquivo vazio
big = os.urandom(3*1024*1024 + 777)
open(p("big.bin"),"wb").write(big)
e8 = c.criptografar_arquivo(p("big.bin"), "s3nha", apagar_entrada if False else False)
os.remove(p("big.bin"))
assert open(c.descriptografar_arquivo(e8,"s3nha"),"rb").read() == big
open(p("vazio.txt"),"wb").close()
e9 = c.criptografar_arquivo(p("vazio.txt"), "s3nha"); os.remove(p("vazio.txt"))
assert open(c.descriptografar_arquivo(e9,"s3nha"),"rb").read() == b""
print("8 ok  3MB multi-chunk e arquivo vazio ok")

# 9. rounds vem do cabecalho (compatibilidade futura)
import struct
hdr = open(enc,"rb").read(c.HEADER_BYTES)
assert hdr[:6] == b"COFRE1" and struct.unpack(">H", hdr[6:8])[0] == c.KDF_ROUNDS
print("9 ok  cabecalho grava magic + rounds")

shutil.rmtree(d)
print("\nTODOS OS TESTES PASSARAM")
