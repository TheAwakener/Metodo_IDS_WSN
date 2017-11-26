from zrules import ZigbeeIDSRules
from zlogger import ZigbeeIDSLogger
from zsignatures import ZigbeeSignaturesDB
import hashlib
import multiprocessing
import argparse
import time
import logging
import sys
from scapy.all import (Dot15d4,
                       ZigbeeNWK,
                       ZigbeeNWKCommandPayload,
                       Dot15d4Data,
                       wrpcap,
                       LinkStatusEntry,
                       rdpcap)
from killerbee import scapy_extensions as zcapy


class PktAttrExtractor(object):
    def __init__(self, pkt):
        command_numbers = {
            1: "route request",
            2: "route reply",
            3: "network status",
            4: "leave",
            5: "route record",
            6: "rejoin request",
            7: "rejoin response",
            8: "link status",
            9: "network report",
            10: "network update"
        }
        self.nwk_address = format(pkt['ZigbeeNWK'].source, 'x')
        self.mac_address = format(pkt['ZigbeeNWK'].ext_src, 'x')
        if pkt.haslayer('ZigbeeNWKCommandPayload'):
            command = 'ZigbeeNWKCommandPayload'
            self.cmdtype = command_numbers[pkt[command].cmd_identifier]
        else:
            self.cmdtype = 'NWK_Raw'

        if self.cmdtype == 'link status':
            self.neighbor_lst = []
            self.neighbor_count = pkt[command].entry_count
            for nbor in pkt[command].link_status_list:
                neighbor = format(nbor.neighbor_network_address, 'x')
                self.neighbor_lst.append(neighbor)
        elif self.cmdtype == 'route request':
            if pkt[command].many_to_one == 1\
                    or pkt[command].many_to_one == 2:
                self.l2_src = format(pkt['Dot15d4Data'].src_addr, 'x')
                self.l3_src = format(pkt['ZigbeeNWK'].source, 'x')
                self.l3_ext_src = format(pkt['ZigbeeNWK'].ext_src, 'x')
                self.m2o_value = pkt[command].many_to_one
        elif self.cmdtype == 'route record':
            self.l2_dest = format(pkt['Dot15d4Data'].dest_addr, 'x')
            self.l3_dest = format(pkt['ZigbeeNWK'].destination, 'x')
            self.l3_dst_ext = format(pkt['ZigbeeNWK'].ext_dst, 'x')
            self.l3_src_ext = format(pkt['ZigbeeNWK'].ext_src, 'x')
            self.relay_lst = pkt[command].rr_relay_list
            self.route_lenght = len(pkt[command].rr_relay_list)


def SignatureCalc(pkt_attr):
    signature = ''
    if pkt_attr.cmdtype == 'route record':
        signature = pkt_attr.l3_dst_ext\
            + pkt_attr.l3_src_ext\
            + str(pkt_attr.relay_lst) + str(pkt_attr.route_lenght)
        signature = hashlib.sha256(signature).hexdigest()
    elif pkt_attr.cmdtype == 'route request':
        signature = pkt_attr.l3_ext_src + \
                    str(pkt_attr.m2o_value)
        signature = hashlib.sha256(signature).hexdigest()
    return signature


def RuleProcessor(pkt_cap, ids, ids_logger, ids_sign):

    pkt_attr = PktAttrExtractor(pkt_cap[0])

    lst_result = ids.WhiteListCheck(pkt_attr.nwk_address, pkt_attr.mac_address)
    ids_logger.ConsoleHandler(lst_result)
    ids_logger.FileHandler(lst_result)

    if lst_result[0] == 50 and pkt_attr.cmdtype == 'route request':
        if pkt_attr.m2o_value == 1 or pkt_attr.m2o_value == 2:
            m2osignature = SignatureCalc(pkt_attr)
            m2oresult = ids_sign.CheckM2OPatterns(pkt_attr, m2osignature)
            ids_logger.ConsoleHandler(m2oresult)
            ids_logger.FileHandler(m2oresult)

    elif pkt_attr.cmdtype == 'link status':
        nresult = ids.NeighborlistCheck(pkt_attr.nwk_address,
                                        pkt_attr.neighbor_count,
                                        pkt_attr.neighbor_lst)
        ids_logger.ConsoleHandler(nresult)
        ids_logger.FileHandler(nresult)
        return

    elif pkt_attr.cmdtype == 'route record':
        rrsignature = ''
        if pkt_attr.l2_dest == pkt_attr.l3_dest and pkt_attr.route_lenght == 0:
            for nrule in ids.neighbor_list:
                if nrule['id'] == pkt_attr.l3_dest\
                        and pkt_attr.nwk_address not in nrule['neighbors']:
                    rrsignature += SignatureCalc(pkt_attr)
                    break

        elif pkt_attr.l2_dest == pkt_attr.l3_dest and pkt_attr.route_lenght > 0:
            for nrule in ids.neighbor_list:
                if nrule['id'] == pkt_attr.l3_dest\
                        and pkt_attr.nwk_address in nrule['neighbors']:
                    rrsignature += SignatureCalc(pkt_attr)
                    break

        if len(rrsignature):
            rr_result = ids_sign.CheckRRPatterns(pkt_attr, rrsignature)
            ids_logger.ConsoleHandler(rr_result)
            ids_logger.FileHandler(rr_result)


def PktFilter(pkt_filter):

    if pkt_filter == 'NWK':
        return lambda pkt: pkt.haslayer('ZigbeeNWKCommandPayload')


def NetworkSniffer(netchannel, sniff_interval):
    ids = ZigbeeIDSRules('IDS_Rules.dat')
    ids_sign = ZigbeeSignaturesDB('IDSdatabase.db')
    ids_sign.CreateSignatureTables()
    ids_logger = ZigbeeIDSLogger()
    ids_logger.CreateLogHandlers()

    while True:
        pkt = zcapy.kbsniff(channel=netchannel,
                            lfilter=PktFilter('NWK'),
                            count=1,
                            verbose=0)
        pthread = multiprocessing.Process(target=RuleProcessor,
                                          args=(pkt,
                                                ids,
                                                ids_logger,
                                                ids_sign))
        pthread.start()
        time.sleep(sniff_interval)


def main():
    args = argparse.ArgumentParser(description='Zigbee IDS network')
    args.add_argument('netchannel', type=int, help='Network channel')
    args.add_argument('--sniff_interval', '-t',
                      type=int,
                      default=0,
                      help='Packet capture interval')
    args_values = args.parse_args()

    netchannel = args_values.netchannel
    sniff_interval = args_values.sniff_interval

    NetworkSniffer(netchannel, sniff_interval)


if __name__ == '__main__':
    main()
