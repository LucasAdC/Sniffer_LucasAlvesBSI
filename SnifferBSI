from collections import defaultdict
import pyshark
import sys
def liveCapture(ips):
    filtro = []
    for ip in ips:
        filtro.append('ip.addr == ' + ip)
    capture = pyshark.LiveCapture(interface='eno1', display_filter=" or ".join(filtro))
    return capture


def extrairAtributos(pacote):
    atributos = defaultdict(lambda: "Nenhum")
    atributos["number"] = pacote.number
    if hasattr(pacote, "ip"):
        atributos["ipDest"] = pacote.ip.dst
        atributos["ipSource"] = pacote.ip.src
    if hasattr(pacote, "tcp"):
        atributos["portaDest"] = pacote.tcp.dstport
        atributos["portaSource"] = pacote.tcp.srcport
    if hasattr(pacote, "udp"):
        atributos["portaDest"] = pacote.udp.dstport
        atributos["portaSource"] = pacote.udp.srcport

    atributos["protocolo"] = pacote.layers[-1].layer_name
    return(atributos)

def printarPacote(pacote):
    atributos = extrairAtributos(pacote)

    print("Numero:", atributos["number"], "Origem:", atributos["ipSource"])
    print("Destino:", atributos["ipDest"], "Protocolo", atributos["protocolo"])
    print("Porta origem:", atributos["portaSource"], "Porta destino:", atributos["portaDest"])
    print()



    # print(dir(pacote.udp))

def main(args):
    capture = liveCapture(args[1:])
    for pacote in capture.sniff_continuously():
        printarPacote(pacote)

if name == 'main':
main(sys.argv)
