import random
import datetime

def menu():
    nome_arq = 'log.txt'
    while True:
        print('MENU\n') 
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - SAIR')
        opc = int(input('Escolha uma opção: '))
        if opc == 1:
            try:
                qtd = int(input('Qauntidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
            except:
                print('Entrada inválida.')
        elif opc == 2:
            analisarLogs(nome_arq)
        elif opc == 3:
            try:
                qtd = int(input('Qauntidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
                analisarLogs(nome_arq)
            except:
                print('Entrada inválida.')
        elif opc == 4:
            print('Até mais')
            break
        else:
            print('Opção inválida')

def gerarArquivo(nome_arq, qtd):
    with open(nome_arq, 'w', encoding='UTF-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print('Log gerado')
    
def montarLog(i):
    data = gerarData(i)
    ip = gerarIp(i)
    recurso = gerarRecurso(i)
    metodo = gerarMetodo(i)
    status = gerarStatus(i)
    tempo = gerarTempo(i)
    agente = gerarAgente(i)
    protocolo = gerarProtocolo(i)
    tamanho = gerarTamanho(i)
    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho} - {protocolo} - {agente} - /home'

def gerarData(i):
    base = datetime.datetime.now()
    delta = datetime.timedelta(seconds= i * random.randint(5,20))
    return (base + delta).strftime('%d/%m/%Y %H:%M:%S')

def gerarIp(i):
    r = random.randint(1,6)
    if i >= 20 and i <= 50:
        return '203.120.45.7'
    else:
        return f'{random.randint(10,200)}.{random.randint(100,200)}.{random.randint(0,250)}.{random.randint(1,250)}'



def gerarRecurso(i):
    if i % 10 == 0:
        return '/admin'
    elif i % 15 == 0:
        return '/login'
    elif i % 7 == 0:
        return '/produtos'
    elif i % 9 == 0:
        return '/backup'
    elif i % 11 == 0:
        return '/config'
    else:
        return '/home'

def gerarMetodo(i):
    if i % 2 == 0:
        return 'GET'
    return 'POST'

def gerarStatus(i):
    if 30 <= i <= 35:
        return 500
    if i % 10 == 0:
        return 403
    if i % 8 == 0:
        return 404
    return 200

def gerarTempo(i):
    if 60 <= i <= 65:
        return 200 + (i - 60) * 200
    return random.randint(50, 1000)

def gerarAgente(i):
    if i % 12 == 0:
        return 'Bot'
    elif i % 13 == 0:
        return 'Crawler'
    elif i % 14 == 0:
        return 'Spider'
    return 'Chrome'

def gerarProtocolo(i):
    if i % 3 == 0:
        return 'HTTP/1.0'
    elif i % 3 == 1:
        return 'HTTP/1.1'
    return 'HTTP/2'

def gerarTamanho(i):
    return f'{random.randint(100,5000)}B'

def extrair(linha):
    campos = []
    atual = ''
    i = 0

    while i < len(linha):
        if linha[i] == '[':
            i += 1
            while linha[i] != ']':
                atual += linha[i]
                i += 1
            campos.append(atual)
            atual = ''
        elif linha[i] == '-':
            if atual.strip() != '':
                campos.append(atual.strip())
                atual = ''
        else:
            atual += linha[i]
        i += 1

    if atual.strip() != '':
        campos.append(atual.strip())

    data = campos[0]
    ip = campos[1]
    metodo = campos[2]
    status = campos[3]
    recurso = campos[4]

    tempo_str = campos[5]
    tempo = ''
    j = 0
    while j < len(tempo_str):
        if tempo_str[j].isdigit():
            tempo += tempo_str[j]
        j += 1

    user_agent = campos[8]

    return [data, ip, metodo, status, recurso, tempo, '', '', user_agent]

def analisarLogs(nome):
    total = sucesso = erros = erro500 = 0
    soma_tempo = maior = 0
    menor = 999999

    rap = nor = len_t = 0
    s200 = s403 = s404 = s500 = 0

    recurso_cont = {}
    ip_cont = {}
    ip_erro = {}

    brute = 0
    brute_ip = ''
    seq_brute = 0
    last_ip_brute = ''

    admin_err = 0

    degr = 0
    prev_t = -1
    seq_deg = 0

    falha = 0
    seq_500 = 0

    bot = 0
    bot_ip = ''
    seq_ip = 0
    last_ip_bot = ''

    sens = 0
    sens_err = 0

    with open(nome, 'r', encoding='UTF-8') as arq:
        for linha in arq:
            total += 1
            dados = extrair(linha)

            ip = dados[1]
            status = int(dados[3])
            recurso = dados[4]
            tempo = int(dados[5])

            soma_tempo += tempo

            if tempo > maior:
                maior = tempo
            if tempo < menor:
                menor = tempo

            if tempo < 200:
                rap += 1
            elif tempo < 800:
                nor += 1
            else:
                len_t += 1

            if status == 200:
                sucesso += 1
                s200 += 1
            elif status == 403:
                erros += 1
                s403 += 1
            elif status == 404:
                erros += 1
                s404 += 1
            elif status == 500:
                erros += 1
                erro500 += 1
                s500 += 1

            if recurso not in recurso_cont:
                recurso_cont[recurso] = 0
            recurso_cont[recurso] += 1

            if ip not in ip_cont:
                ip_cont[ip] = 0
                ip_erro[ip] = 0
            ip_cont[ip] += 1
            if status != 200:
                ip_erro[ip] += 1

            if recurso == '/login' and status == 403:
                if ip == last_ip_brute:
                    seq_brute += 1
                    if seq_brute == 3:
                        brute += 1
                        brute_ip = ip
                else:
                    seq_brute = 1
            else:
                seq_brute = 0
            last_ip_brute = ip

            if recurso == '/admin' and status != 200:
                admin_err += 1

            if tempo > prev_t:
                seq_deg += 1
                if seq_deg == 3:
                    degr += 1
            else:
                seq_deg = 0
            prev_t = tempo

            if status == 500:
                seq_500 += 1
                if seq_500 == 3:
                    falha += 1
            else:
                seq_500 = 0

            if ip == last_ip_bot:
                seq_ip += 1
                if seq_ip == 5:
                    bot += 1
                    bot_ip = ip
            else:
                seq_ip = 1
            last_ip_bot = ip

            if 'Bot' in dados[8] or 'Crawler' in dados[8] or 'Spider' in dados[8]:
                bot += 1
                bot_ip = ip

            if recurso == '/admin' or recurso == '/backup' or recurso == '/config' or recurso == '/private':
                sens += 1
                if status != 200:
                    sens_err += 1

    disp = (sucesso / total) * 100
    taxa = (erros / total) * 100
    media = soma_tempo / total

    mais_rec = max(recurso_cont, key=recurso_cont.get)
    ip_ativo = max(ip_cont, key=ip_cont.get)
    ip_err = max(ip_erro, key=ip_erro.get)

    estado = classificar_estado(disp, len_t, bot, falha)

    print('\nRELATÓRIO\n')
    print('Total:', total)
    print('Sucesso:', sucesso)
    print('Erros:', erros)
    print('Erro 500:', erro500)
    print('Disponibilidade:', disp)
    print('Taxa erro:', taxa)
    print('Tempo médio:', media)
    print('Maior:', maior)
    print('Menor:', menor)
    print('Rápidos:', rap)
    print('Normais:', nor)
    print('Lentos:', len_t)
    print('200:', s200)
    print('403:', s403)
    print('404:', s404)
    print('500:', s500)
    print('Recurso mais acessado:', mais_rec)
    print('IP mais ativo:', ip_ativo)
    print('IP mais erros:', ip_err)
    print('Força bruta:', brute)
    print('Último IP força bruta:', brute_ip)
    print('Admin indevido:', admin_err)
    print('Degradação:', degr)
    print('Falha crítica:', falha)
    print('Bots:', bot)
    print('Último bot:', bot_ip)
    print('Rotas sensíveis:', sens)
    print('Falhas sensíveis:', sens_err)
    print('Estado:', estado)

def classificar_estado(disp, lentos, bot, falha):
    if falha > 0 or disp < 70:
        return 'CRITICO'
    elif disp < 85 or lentos > 10:
        return 'INSTAVEL'
    elif disp < 95 or bot > 0:
        return 'ATENCAO'
    return 'SAUDAVEL'

menu()
