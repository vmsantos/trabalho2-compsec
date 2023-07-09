import string
import hashlib
import random
import math

def SHA3(sequencia_bytes: bytes, tam_msg, tam_int):   # Função para hash SHA3
    tam_bit = 8
    hash_inicial = hashlib.sha3_256(b'')
    tam_hash = len(hash_inicial.digest())
    limite_hash = math.ceil(tam_msg/tam_hash)
    hashes = []

    for i in range(0, limite_hash):
        j = i.to_bytes(tam_int//tam_bit, byteorder='big', signed = False)
        j_hash = hashlib.sha3_256(sequencia_bytes + j)
        hashes.append(j_hash.digest())
        
    string_hash = b''.join(hashes)
    hash_final = string_hash[:tam_msg]
    return hash_final

def xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

def substitui(v, atual, novo, ocorrencia): # 0
    lista = v.rsplit(atual, ocorrencia)
    return novo.join(lista)

# Cifra
def cifraOAEP(tam_primo: int, texto: string, tam_int: int): # OAEP para cifrar
    zeros = 0
    zero = '0'
    z0 = tam_primo // tam_int
    z1 = tam_primo // (2*tam_int)
    while True:
        zeros+= 1
        texto+=zero
        if zeros == z1:
            break
    
    r_lista = []
    r = ''
    r_grupo = string.digits + string.ascii_lowercase
    r_lista = random.choices(r_grupo, k = z0)
    for i in r_lista:
        r += i
    
    r = r.encode() 
    s = SHA3(r, tam_primo-z0, tam_int)
    texto = texto.encode() 
    x = xor(s, texto)
    h = hashlib.sha3_256(x)
    x0 = xor(r, h.digest())    

    tam_x = len(x)
    tam_x0 = len(x0)
    tam_p = len(x+x0)
    return x + x0, tam_x, tam_x0, tam_p

def cifra_rsa(tam_primo: int, texto: string, e, n, tam_int: int): # Cifra RSA com OAEP
    padding_texto, tam_x, tam_x0, tam_p = cifraOAEP(tam_primo, texto, tam_int)
    aux = int.from_bytes(padding_texto, byteorder='big', signed = False)
    hash_texto = pow(aux, e, n)
    return tam_x, tam_x0, tam_p, hash_texto


# Decifra 
def decifraOAEP(tam_primo: int, bloco_x: bytes, bloco_x0:bytes, zeros, tam_int): # OAEP para decifrar faz o inverso da OAEP para cifrar
    h = hashlib.sha3_256(bloco_x)
    r = xor(bloco_x0, h.digest())
    g = SHA3(r, tam_primo-(tam_primo//tam_int), tam_int)
    texto = xor(bloco_x, g)
    texto = texto.decode('utf-8')

    if texto.count('0') >= zeros:
        texto = substitui(texto, '0', '', texto.count('0') - zeros)
    else:
        return None

    return texto

def decifra(tam_primo: int, tam_x, zeros, tam_p, texto_cifrado, d, n, tam_int: int): # Decifra RSA com OAEP
    padding_texto = pow(texto_cifrado, d, n)
    aux = padding_texto.to_bytes(tam_p, byteorder='big', signed = False)
    pri_bloco = aux[0:tam_x]
    seg_bloco = aux[tam_x:tam_p]
    original_texto = decifraOAEP(tam_primo, pri_bloco, seg_bloco, zeros, tam_int)
    return original_texto