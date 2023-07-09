from chaves import gerarchaves
from oaep import cifra, decifra
from assinatura import assinar, checarAssinatura
from arquivo64 import gerarArquivo, formato64, controle
import binascii


TAM_PRIMO = 1024
TAM_INT = 32
DEBUG = False

def mostrar_menu():
    print('\x1b[0;5;90mCIC0201 - Segurança Computacional - 2023/1\x1b[0m')
    print('\n\n\t\t\t\t\x1b[0;3;97mGerador e Verificador de Assinaturas\x1b[0m')  

def executa():
    control = 0
    if not DEBUG:
        texto = input('\n\n\x1b[0;0;97m Qual é a mensagem?: \x1b[0m')
        if texto.count('0') > 0:
            control += texto.count('0')
    else:
        texto = 'Capivaras no topo'
    
    # controle
    txt = "Mensagem Digitada"
    controle(txt, texto)

    n, chave_publica, chave_privada = gerarchaves(TAM_PRIMO)

    if DEBUG:
        print('Chave Pública (e,n) = ', chave_publica)
        print('\nChave Privada (d,n) = ', chave_privada)

        e = chave_publica[0]
        tam_x, tam_x0, tam_p, hash_texto = cifra(TAM_PRIMO, texto, e, n, TAM_INT)

        print('\nHash do Texto: ', hash_texto)
        

    else:
        e = chave_publica[0]
        tam_x, tam_x0, tam_p, hash_texto = cifra(TAM_PRIMO, texto, e, n, TAM_INT)

        hash_cifratexto = hash_texto.to_bytes(TAM_PRIMO, byteorder='big', signed = False)

        # controle
        txt = "hash do texto cifrado em bytes"
        controle(txt, hash_cifratexto)

        hash_cifratexto = binascii.b2a_base64(hash_cifratexto, newline = False)


        tam_hash_texto = len(hash_cifratexto)
        for i in range(tam_hash_texto):
            if hash_cifratexto[i] != 65:
                salva_i = i
                break

        # controle
        txt = "hash do texto cifrado BASE64"
        controle(txt, hash_cifratexto[salva_i:tam_hash_texto].decode('utf-8'))

        print('\n\x1b[0;1;91m<<BASE64>> \x1b[0m'+'\x1b[0;0;94mHASH DO TEXTO CIFRADO: \x1b[0m', hash_cifratexto[salva_i:tam_hash_texto].decode('utf-8'))

        d = chave_privada[0]
        texto_decifrado = decifra(TAM_PRIMO, tam_x, control, tam_p, hash_texto, d, n, TAM_INT)

        print('\n\x1b[0;0;92m' + 'MENSAGEM DECIFRADA: ' + '\x1b[0m', str(texto_decifrado)[2:-1].strip('"\''))

        # Assinatura
        texto_cifrado = texto.encode()
        assinatura = assinar(texto_cifrado, d, n)
                
        assinaturaB = binascii.b2a_base64(assinatura, newline = False)

        tam_assinatura = len(assinaturaB)
        for i in range(tam_assinatura):
            if assinaturaB[i] != 65:
                salva_i = i
                break

        print('\n\x1b[0;1;91m<<BASE64>> \x1b[0m'+'\x1b[0;0;94mHASH DA ASSINATURA: \x1b[0m', assinaturaB[salva_i:tam_assinatura].decode('utf-8'))
                
        # Checa assinatura e gera o arquivo saida.md 

        checandoAssinatura = checarAssinatura(TAM_INT, texto_cifrado, assinatura, e, n)
        print('\n\x1b[0;0;92m' + 'Assinatura Verificada: ' + '\x1b[0m', checandoAssinatura)

        chave_publica64, chave_privada64, assinatura64 = formato64(e, d, assinatura, n)
        gerarArquivo(chave_publica64, chave_privada64, assinatura64)
        # controle
        txt = "Assinatura BASE 64"
        controle(txt, assinatura64)
        
        