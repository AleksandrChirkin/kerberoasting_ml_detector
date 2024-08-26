from argparse import ArgumentParser
from scapy.layers.kerberos import Kerberos
from scapy.packet import Packet
from scapy.sendrecv import sniff


def process_pack(pack: Packet):
    krb_layer = pack[Kerberos]
    # TODO что-то делать с kerberos-данными при помощи ML
    # пока просто выводим тип kerberos-сообщения
    return krb_layer.summary()


if __name__ == '__main__':
    parser = ArgumentParser(description='Детектор атаки Kerberoasting')
    parser.add_argument('--iface', required=False, help='Отслеживаемый интерфейс')
    args = parser.parse_args()
    sniff(lfilter=lambda pack: pack.haslayer(Kerberos),
          prn=lambda pack: process_pack(pack),
          iface=args.iface)
