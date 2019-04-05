#!/usr/bin/env python

from scapy.all import *
import argparse


class MNDP(Packet):
    name = "MNDP"

    fields_desc = [ShortField("header", 0),
                   ShortField("SeqNo", 0),
                   ShortField("TlvTypeIdentity", 5),
                   ShortField("TlvLengthIdentity", 4),
                   StrField("Identity", "test"),
                   ShortField("TlvTypeVersion", 7),
                   ShortField("TlvLengthVersion", 4),
                   StrField("Version", "test"),
                   ShortField("TlvTypePlatform", 8),
                   ShortField("TlvLengthPlatform", 4),
                   StrField("Platform", "test"),
                   ShortField("TlvTypeSoftware-ID", 11),
                   ShortField("TlvLengthSoftware", 4),
                   StrField("Software", "test"),
                   ShortField("TlvTypeBoard", 12),
                   ShortField("TlvLengthBoard", 4),
                   StrField("Board", "test"),
                   ShortField("TlvTypeMAC-Address", 1),
                   ShortField("TlvLengthMAC", 6),
                   MACField("MAC",  "ca:fe:ca:fe:ca:fe")]


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--identity", default="test", help="Identity, default test")
    parser.add_argument("-v", "--version", default="test", help="Version, default test")
    parser.add_argument("-p", "--platform", default="test", help="Platform, default test")
    parser.add_argument("-s", "--software-id", default="test", help="Software-ID, default test")
    parser.add_argument("-b", "--board", default="test", help="Board, default test")
    parser.add_argument("-m", "--mac", default="ca:fe:ca:fe:ca:fe", help="MAC-Address, default ca:fe:ca:fe:ca:fe")
    args = parser.parse_args()

    return args


def get_ip_packet():
    pkt = IP()
    pkt.dst = "255.255.255.255"
    pkt.ihl = 5

    return pkt


def get_udp_packet():
    pkt = UDP()
    pkt.sport = 5678
    pkt.dport = 5678

    return pkt


def get_mndp_packet(args):
    pkt = MNDP()

    pkt.Identity = args.identity
    pkt.TlvLengthIdentity = len(args.identity)
    pkt.Version = args.version
    pkt.TlvLengthVersion = len(args.version)
    pkt.Platform = args.platform
    pkt.TlvLengthPlatform = len(args.platform)
    pkt.Software = args.software_id
    pkt.TlvLengthSoftware = len(args.software_id)
    pkt.Board = args.board
    pkt.TlvLengthBoard = len(args.board)
    pkt.MAC = args.mac

    return pkt

if __name__ == '__main__':
    args = get_args()
    pkt_ip = get_ip_packet()
    pkt_udp = get_udp_packet()
    pkt_mndp = get_mndp_packet(args)

    pkt = pkt_ip/pkt_udp/pkt_mndp
    send(pkt)
