import random
from arquivo64 import controle

# Realiza o teste de Miller-Rabin
def primo(n, k=40):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Euclides máximo divisor comum
def gcd(a, b): 
    while b != 0:
        a, b = b, a % b
    return a

# Gerar Chave Pública e Chave Privada
# tam_chave = 1024

def gerarchaves(tam_chave):
    d = 0
    p = 0
    q = 0

    while d != 2:
        if d == 0:
            p = random.getrandbits(tam_chave)
            if primo(p):
                d += 1
        elif d == 1:
            q = random.getrandbits(tam_chave)
            if primo(q):
                d += 1

    n = p * q # calcula n
    phi = (p - 1) * (q - 1) # totiente de Euler

    e = random.randrange(2**16 + 1, phi) 
    while gcd(e, phi) != 1:             # verifica se 'e' e 'phi'são primos entre si, gcd tem que ser = 1
        e = random.randrange(2**16 + 1, phi)

    d = pow(e, -1, phi) # inverso modular de e

    if (e * d) % phi == 1: # Confere o inverso modular
        chave_publica = (e, n)
        chave_privada = (d, n) # RSA padrão PKCS #1 
    else:
        print("Erro na geração das chaves")

    # Controle
    texto = "P"
    controle(texto, p)
    texto = "Q"
    controle(texto, q)
    texto = "Chave Publica"
    controle(texto, chave_publica)
    texto = "Chave Privada"
    controle(texto, chave_privada)

    return n, chave_publica, chave_privada
