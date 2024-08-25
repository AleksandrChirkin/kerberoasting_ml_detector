from argparse import ArgumentParser
from scapy.layers.kerberos import Kerberos
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff


def process_pack(pack: Packet):
    raw_content = pack[Raw]
    try:
        krb_layer = Kerberos(raw_content)
        # TODO что-то делать с kerberos-данными при помощи ML
        return krb_layer.summary()
    # если не получилось спарсить в kerberos-пакет, то считаем, что это не kerberos-пакет, и ничего не делаем
    except Exception as e:
        return e


if __name__ == '__main__':
    parser = ArgumentParser(description='Детектор атаки Kerberoasting')
    parser.add_argument('--iface', required=False, help='Отслеживаемый интерфейс')
    args = parser.parse_args()
    sniff(lfilter=lambda pack: pack.haslayer(Raw),
          prn=lambda pack: process_pack(pack),
          iface=args.iface)
