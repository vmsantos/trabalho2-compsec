import base64

def gerarArquivo(chave_publica, chave_privada, assinatura):
    filename = "saida.md"
    
    chave_publica_str = str(chave_publica)
    chave_privada_str = str(chave_privada)
    assinatura_str = str(assinatura)
    
    with open(filename, 'wb') as f:
        
        f.write("\nCHAVE PÚBLICA".encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())
        f.write(chave_publica_str.encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())

        f.write("\nCHAVE PRIVADA".encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())
        f.write(chave_privada_str.encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())

        f.write("\nASSINATURA".encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())
        f.write(assinatura_str.encode())
        f.write("\n----------------------------------------------------------------------------------------------------------------------------------------\n".encode())
        
    print(f"\nInformações salvas no arquivo \x1b[0;1;95m{filename}\x1b[0m")
   
def formato64(chave_publica, chave_privada, assinatura, n):
    chave_publica64 = str(chave_publica)
    chave_privada64 = str(chave_privada)

    chave_publica64 = base64.b64encode(chave_publica64.encode())
    chave_privada64 = base64.b64encode(chave_privada64.encode())
    assinatura64 = base64.b64encode(assinatura)

    return chave_publica64, chave_privada64, assinatura64

def controle(texto, conteudo):
    filename = "controle.md"
    
    with open(filename, 'a') as f:
        
        f.write(texto)
        f.write("\n---------------------------------------\n")
        f.write(str(conteudo))
        f.write("\n---------------------------------------\n")