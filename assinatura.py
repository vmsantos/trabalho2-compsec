import hashlib
import math
from arquivo64 import controle

def assinar(texto: bytes, d, n):
    h = hashlib.sha3_256(texto)
    m = int.from_bytes(h.digest(), byteorder='big', signed = False)
    s = pow(m, d, n)
    assinatura = s.to_bytes(math.ceil(n.bit_length() / 8), byteorder='big', signed = False)

    #controle
    txt = "Assinatura em binario"
    controle(txt, assinatura)

    return assinatura
    
def checarAssinatura(tam_int: int, texto: bytes, assinatura: bytes, e, n):
    aux = int.from_bytes(assinatura, byteorder='big', signed = False)
    k = pow(aux, e, n)
    hashr = k.to_bytes(tam_int, byteorder='big', signed = False)
    h = hashlib.sha3_256(texto)
    hasho = h.digest()

    # controle
    texto = "Hash Recuperado"
    controle(texto, hashr)
    texto = "Hash Original"
    controle(texto, hasho)

    return hashr == hasho