from Crypto.Cipher import AES

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext
##
# Utilize a função rsa_encrypt já implementada para cifrar a chave simétrica
k = generate_aes_key()
ciphertext_key = rsa_encrypt(KA_p, k)

# Utilize a função aes_encrypt da biblioteca para cifrar a mensagem
ciphertext_message = aes_encrypt(k, M)

# Combine os resultados em um único ciphertext
C = ciphertext_message + ciphertext_key
##
# Utilize as funções rsa_encrypt e rsa_decrypt já implementadas para cifrar as chaves simétricas
k_A = generate_aes_key()
ciphertext_key_A = rsa_encrypt(KB_s, rsa_encrypt(KA_p, k_A))
ciphertext_key_B = rsa_encrypt(KA_s, rsa_encrypt(KB_p, k_A))

# Utilize a função aes_encrypt da biblioteca para cifrar a mensagem
ciphertext_message = aes_encrypt(k_A, M)

# Combine os resultados em um único ciphertext
C = ciphertext_message + ciphertext_key_A + ciphertext_key_B
##
from Crypto.Hash import SHA3_256

# Utilize a função aes_encrypt da biblioteca para cifrar a mensagem
ciphertext_message = aes_encrypt(k, M)

# Calcule o hash da mensagem cifrada
hash_message = SHA3_256.new(ciphertext_message).digest()

# Cifre o hash com a chave privada de A
ciphertext_hash = rsa_encrypt(KA_s, hash_message)

# Combine os resultados em um único ciphertext
Sign = ciphertext_message + ciphertext_hash + KA_p
##
from Crypto.Hash import SHA3_256

# Extraia os componentes do Sign
ciphertext_message = Sign[:16]  # Tamanho do ciphertext_message AES
ciphertext_hash = Sign[16:272]  # Tamanho do ciphertext_hash RSA
KA_p = Sign[272:]

# Decifre o hash com a chave pública de A
deciphered_hash = rsa_decrypt(KA_p, ciphertext_hash)

# Utilize a função aes_encrypt da biblioteca para cifrar a mensagem
deciphered_message = aes_decrypt(k, ciphertext_message)

# Calcule o hash da mensagem decifrada
hash_message = SHA3_256.new(deciphered_message).digest()

# Verifique se o hash decifrado é igual ao hash calculado
if deciphered_hash == hash_message:
    print("Assinatura válida.")
else:
    print("Assinatura inválida.")
##
