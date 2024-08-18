from argparse import ArgumentParser
from scapy.layers.kerberos import Kerberos
from scapy.packet import Packet
from scapy.sendrecv import sniff


def process_pack(pack: Packet):
    krb_layer = pack.getlayer(Kerberos)
    # TODO что-то делать с kerberos-данными при помощи ML
    return pack.summary()


if __name__ == '__main__':
    parser = ArgumentParser(description='Kerberoasting detector')
    parser.add_argument('iface', help='An interface to sniff')
    args = parser.parse_args()
    sniff(lfilter=lambda pack: pack.getlayer(Kerberos) is not None,
          prn=lambda pack: process_pack(pack),
          iface=args.iface)
