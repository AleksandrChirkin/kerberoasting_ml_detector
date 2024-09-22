#!/usr/bin/env python3
from argparse import ArgumentParser
from scapy.layers.kerberos import KRB_TGS_REQ, EncryptedData, KRB_Ticket, KRB_AP_REQ, PADATA
from scapy.packet import Packet
from scapy.sendrecv import sniff

rc4_hmac_signature = '0x17'

def process_pack(pack: Packet):
    # обнаруживаем шифрование слабым алгоритмом RC4 (etype = 0x17)
    # находим алгоритм шифрования у TGT
    krb_ticket_etype = repr(pack[KRB_Ticket][EncryptedData].etype)
    # находим алгоритм шифрования во вложенном AP_REQ
    krb_ap_req_etype = repr(pack[KRB_AP_REQ][EncryptedData].etype)
    # находим алгоритм шифрования в PADATA
    padata_etype = repr(pack[PADATA][EncryptedData].etype)
    if (rc4_hmac_signature in krb_ticket_etype or rc4_hmac_signature in krb_ap_req_etype or
            rc4_hmac_signature in padata_etype):
        print('WARNING: RC4-ENCRYPTED PACKET FOUND!')
    # TODO обнаруживать аномальное количество TGS_REQ при помощи ML


if __name__ == '__main__':
    parser = ArgumentParser(description='Детектор атаки Kerberoasting')
    parser.add_argument('--iface', required=False, help='Отслеживаемый интерфейс')
    args = parser.parse_args()
    sniff(lfilter=lambda pack: pack.haslayer(KRB_TGS_REQ),
          prn=lambda pack: process_pack(pack),
          iface=args.iface)
