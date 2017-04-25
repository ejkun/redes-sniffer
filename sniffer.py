# -*- coding: utf-8 -*-
from scapy.all import *
from pyx import *

def capturePkts():
    filtro = raw_input("Entre com o filtro: ")
    iface = raw_input("Entre com a interface (padrao eth0): ") or "eth0"
    count = int(raw_input("Entre com a quantidade de pacotes (deixe em branco para infinito): ") or 0) 
    if count == 0:
        pkts = sniff(iface="eth0", prn=lambda x: x.summary(), filter=filtro)    
    else:
        pkts = sniff(iface="eth0", prn=lambda x: x.summary(), count=count, filter=filtro)
    print("\n{} pacotes foram capturados".format(len(pkts)))
    return pkts

def pktChoice(pkt):
    print("Pacote escolhido: {}".format(pkt.summary()))
    acao = 0
    while (acao is 0):
        acao = int(raw_input("Escolha uma das seguintes ações:\n\t[1] Mostrar o pacote completo\n\t[2] Gravar dados do pacotes em arquivo EPS\n\t[3] HexDump\n\t[0] Sair\n") or 0)
        if acao is 0:
            print("Opção inválida, tente novamente")
    if acao is 1:
        pkt.show()
    elif acao is 2:
        pkt.psdump("./pkt.eps", layer_shift=1)
    elif acao is 3:
        print("HEXDUMP")
        hexdump(pkt)

main = -1
while (main is not 0):
    main = -1
    while (main is -1):
        main = int(raw_input("\n\nEscolha uma ferramenta:\n\t[1] Sniffer\n\t[2] SYN Scan\n\t[3] Traceroute\n\t[0] Sair\n") or 0)
        if main is -1:
            print("Opção inválida, tente novamente")
    if main is 1:
        pkts = capturePkts()
        acao = -1
        while (acao is not 0):
            acao = -1
            while (acao is -1):
                acao = int(raw_input("\n\nEscolha uma das seguintes ações:\n\t[1] Listar todos os pacotes capturados\n\t[2] Escolher um pacote\n\t[0] Sair\n") or -1)
                if acao is -1:
                    print("Opção inválida, tente novamente")

            if acao is 1:
                print("\nListando todos os pacotes capturados")
                pkts.summary()
            elif acao is 2:
                pktChosen = 0
                while (pktChosen is 0):
                    pktChosen = int(raw_input("Escolha um pacote (de 1 a {}): ".format(len(pkts))) or 0)
                    if pktChosen > (len(pkts)) or pktChosen is 0:
                        print("ERRO! Valor inválido, tente novamente")
                        pktChosen = 0        
                pktChoice(pkts[pktChosen-1])
    elif main is 2:
        addr = raw_input("Entre com o IP: ")
        portStart = 0
        while (portStart is 0):
            portStart = int(raw_input("Entre com o o limite inicial do range de portas: ") or 0)
            if portStart is 0:
                print("Porta inválida")
        portEnd = int(raw_input("Entre com o o limite final do range de portas (deixe vazio para usar o mesmo do limite inicial): ") or 0)
        portClient = int(raw_input("Entre com a sua porta: ") or RandShort())
        if portEnd is 0:
            portEnd = portStart
        ans,unans = sr(IP(dst=addr)/TCP(sport=portClient,dport=(portStart, portEnd),flags="S"))
        ans.summary()
    elif main is 3:
        addr = raw_input("Entre com o IP: ")
        ans,unans=sr(IP(dst=addr, ttl=(4,25),id=RandShort())/TCP(flags=0x2))
        for snd,rcv in ans:
            print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)