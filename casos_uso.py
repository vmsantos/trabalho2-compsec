from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_256
import base64

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

# Caso de uso 2: Cifra híbrida
def case_2():
    message = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    rsa_key = generate_rsa_key()
    ciphertext_aes = aes_encrypt(key, message)
    ciphertext_rsa = rsa_encrypt(rsa_key.publickey(), key)
    print("Caso de uso 2:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA pública:", rsa_key.publickey().export_key())
    print("Mensagem cifrada híbrida:", ciphertext_aes, ciphertext_rsa)

# Caso de uso 3: Cifra híbrida (autenticação mútua)
def case_3():
    message = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    rsa_key_a = generate_rsa_key()
    rsa_key_b = generate_rsa_key()
    ciphertext_aes = aes_encrypt(key, message)
    ciphertext_rsa_a = rsa_encrypt(rsa_key_a.publickey(), rsa_encrypt(rsa_key_b.publickey(), key))
    ciphertext_rsa_b = rsa_encrypt(rsa_key_b.publickey(), key)
    print("Caso de uso 3:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA pública A:", rsa_key_a.publickey().export_key())
    print("Chave RSA pública B:", rsa_key_b.publickey().export_key())
    print("Mensagem cifrada híbrida:", ciphertext_aes, ciphertext_rsa_a, ciphertext_rsa_b)

# Caso de uso 4: Geração de Assinatura de A
def case_4():
    message = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    rsa_key_a = generate_rsa_key()
    hash_message = SHA3_256.new(message).digest()
    ciphertext_aes = aes_encrypt(key, message)
    ciphertext_rsa = rsa_encrypt(rsa_key_a, hash_message)
    print("Caso de uso 4:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA privada A:", rsa_key_a.export_key())
    print("Hash da mensagem:", hash_message)
    print("Assinatura gerada:", ciphertext_aes, ciphertext_rsa)

# Caso de uso 5: Verificação da assinatura
def case_5():
    message = b"Exemplo de mensagem"
    key = get_random_bytes(16)
    rsa_key_a = generate_rsa_key()
    hash_message = SHA3_256.new(message).digest()
    ciphertext_aes = aes_encrypt(key, message)
    ciphertext_rsa = rsa_encrypt(rsa_key_a, hash_message)

    deciphered_message = aes_decrypt(key, ciphertext_aes)
    deciphered_hash = rsa_decrypt(rsa_key_a, ciphertext_rsa)
    hash_message_deciphered = SHA3_256.new(deciphered_message).digest()

    print("Caso de uso 5:")
    print("Mensagem original:", message)
    print("Chave AES:", key)
    print("Chave RSA privada A:", rsa_key_a.export_key())
    print("Hash da mensagem original:", hash_message)
    print("Mensagem decifrada:", deciphered_message)
    print("Hash da mensagem decifrada:", hash_message_deciphered)
    print("Assinatura verificada:", hash_message == hash_message_deciphered)

# Executar todos os casos de uso
def run_all_cases():
    case_1()
    case_2()
    case_3()
    case_4()
    case_5()

# Executar todos os casos de uso
run_all_cases()
