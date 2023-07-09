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

from oaep import cifra_rsa, decifra
#chave = get_random_bytes(16)
#aesObject = AES(chave)


# Geração de chave RSA
def generate_rsa_key():
    key = RSA.generate(2048)
    return key

# Cifração RSA
def rsa_encrypt(key, plaintext):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Decifração RSA
def rsa_decrypt(key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

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

#Caso de uso 2: Cifra híbrida
def case_2():
    n, chave_publica, chave_privada = gerarchaves(TAM_PRIMO)
    message = "Exemplo de mensagem"
    messageBytes = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    ciphertext_aes = aes_encrypt(key, messageBytes)
    ciphertext_rsa = cifra_rsa(TAM_PRIMO, message, chave_publica[0], n, 32)
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
    ciphertext_rsa_b = cifra_rsa(TAM_PRIMO, messageString, chave_publica[0], n_b, 32)

    decryptedSession= decifra(TAM_PRIMO, ciphertext_rsa_b[0], ciphertext_rsa_b[1],ciphertext_rsa_b[2],ciphertext_rsa_b[3], chave_privada[0], chave_privada[1], 32)

    decyptedMessage = aes_decrypt(key, decryptedSession)

    print("Caso de uso 3:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA pública A:", chave_publica)
    print("Chave RSA pública B:", chave_publica_b)
    #print("Mensagem cifrada híbrida:", ciphertext_aes, ciphertext_rsa_a, ciphertext_rsa_b)
    print("Mensagem decryptada",decyptedMessage)

# # Caso de uso 4: Geração de Assinatura de A
# def case_4():
#     message = b"Exemplo de mensagem"
#     key = get_random_bytes(16)
#     rsa_key_a = generate_rsa_key()
#     hash_message = SHA3_256.new(message).digest()
#     ciphertext_aes = aes_encrypt(key, message)
#     ciphertext_rsa = rsa_encrypt(rsa_key_a, hash_message)
#     print("Caso de uso 4:")
#     print("Mensagem original:", message)
#     print("Chave AES:", key)
#     print("Chave RSA privada A:", rsa_key_a.export_key())
#     print("Hash da mensagem:", hash_message)
#     print("Assinatura gerada:", ciphertext_aes, ciphertext_rsa)

# # Caso de uso 5: Verificação da assinatura
# def case_5():
#     message = b"Exemplo de mensagem"
#     key = get_random_bytes(16)
#     rsa_key_a = generate_rsa_key()
#     hash_message = SHA3_256.new(message).digest()
#     ciphertext_aes = aes_encrypt(key, message)
#     ciphertext_rsa = rsa_encrypt(rsa_key_a, hash_message)

#     deciphered_message = aes_decrypt(key, ciphertext_aes)
#     deciphered_hash = rsa_decrypt(rsa_key_a, ciphertext_rsa)
#     hash_message_deciphered = SHA3_256.new(deciphered_message).digest()

#     print("Caso de uso 5:")
#     print("Mensagem original:", message)
#     print("Chave AES:", key)
#     print("Chave RSA privada A:", rsa_key_a.export_key())
#     print("Hash da mensagem original:", hash_message)
#     print("Mensagem decifrada:", deciphered_message)
#     print("Hash da mensagem decifrada:", hash_message_deciphered)
#     print("Assinatura verificada:", hash_message == hash_message_deciphered)

# Executar todos os casos de uso
def run_all_cases():
    #case_1()
    #case_2()
    case_3()
   #case_4()
    #case_5()

# Executar todos os casos de uso
run_all_cases()
