import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_256
import base64
from case import TAM_PRIMO
from chaves import gerarchaves
#from aes import AES
import chardet

from oaep import cifra_rsa, decifra, SHA3
from assinatura import assinar, checarAssinatura
#chave = get_random_bytes(16)
#aesObject = AES(chave)


# Cifração AES
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

# Decifração AES
def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Caso de uso 1: Cifração de uma mensagem com AES
def case_1():
    message = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    ciphertext = aes_encrypt(key, message)
    print("Caso de uso 1:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Mensagem cifrada:", ciphertext)
    decrypted_text = aes_decrypt(key, ciphertext)
    print('Mensagem decifrada: ', decrypted_text)

# #Caso de uso 2: Cifra híbrida
def case_2():
    n, chave_publica, chave_privada = gerarchaves(TAM_PRIMO)
    message = "Exemplo de mensagem"
    key = get_random_bytes(16)
    ciphertext_aes = aes_encrypt(key, message.encode())
    ciphertext_rsa = cifra_rsa(TAM_PRIMO, str(key), chave_publica[0], n, 32)
    print("Caso de uso 2:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Mensagem cifrada híbrida:", ciphertext_aes, ciphertext_rsa)
    print("Chave RSA publica ", chave_publica[0])

# Caso de uso 3: Cifra híbrida (autenticação mútua)
def case_3():
    n, chave_publica, chave_privada = gerarchaves(TAM_PRIMO)
    n_b, chave_publica_b, chave_privada_b = gerarchaves(TAM_PRIMO)
    message = b"Exemplo de mensagem"
    messageString = 'Exemplo de mensagem'
    key = get_random_bytes(16)

    ciphertext_aes = aes_encrypt(key, message)

    ciphertext_rsa_b = cifra_rsa(TAM_PRIMO, str(key), chave_publica[0], n, 32)
    control = 0
    if str(key).count('0') > 0:
            control += str(key).count('0')
 
    
    decryptedSession= decifra(TAM_PRIMO, ciphertext_rsa_b[0], control,ciphertext_rsa_b[2],ciphertext_rsa_b[3], chave_privada[0], chave_privada[1], 32)
    decryptedSession.lstrip('b')
    decyptedMessage = aes_decrypt(decryptedSession, ciphertext_aes)

    print("Caso de uso 3:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA pública A:", chave_publica)
    print("Chave RSA pública B:", chave_publica_b)
    #print("Mensagem cifrada híbrida:", ciphertext_aes, ciphertext_rsa_a, ciphertext_rsa_b)
    print("Mensagem decryptada",decyptedMessage)

# # Caso de uso 4: Geração de Assinatura de A
def case_4():
    message = b"Exemplo de mensagem"
    messageString = 'Exemplo 2'
    key = get_random_bytes(16)
    n, chave_publica,chave_privada = gerarchaves(TAM_PRIMO)
    ciphertext_aes = aes_encrypt(key, message)
    assinatura = assinar(ciphertext_aes, chave_privada[0], chave_privada[1])



    print("Caso de uso 4:")
    print("Mensagem criptografada aes:",ciphertext_aes)
    print("Assinatura:", assinatura)
    print("Chave publica:", chave_publica[0])
    assinatura = checarAssinatura(32,  ciphertext_aes, assinatura, chave_publica[0], n)
    print('\n\x1b[0;0;92m' + 'Assinatura Verificada: ' + '\x1b[0m', assinatura)
    

    

# Executar todos os casos de uso
def run_all_cases():
    case_1()
    case_2()
    #case_3()
    case_4()

# Executar todos os casos de uso
run_all_cases()
