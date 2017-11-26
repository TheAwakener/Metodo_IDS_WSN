from json import loads
import sys


class ZigbeeIDSRules(object):
    def __init__(self, rules_file):
        try:
            with open(rules_file, 'r') as file_descriptor:
                pyformat_rules = loads(file_descriptor.read())
        except IOError as file_error:
            print 'Rule file error: ', file_error
            sys.exit(1)
        except ValueError as json_error:
            print 'Rule format error: ', json_error
            sys.exit(1)

        self.white_list = pyformat_rules['white_list_rules']
        self.black_list = pyformat_rules['black_list_rules']
        self.neighbor_list = pyformat_rules['neighbor_list_rules']

    def WhiteListCheck(self, *pkt_data):
        nwk_address = pkt_data[0]
        mac_address = pkt_data[1]
        white_list_len = len(self.white_list)
        rule_counter = 0
        while rule_counter < white_list_len:
            try:
                if self.white_list[rule_counter][nwk_address] == mac_address:
                    return (20, 'White list match OK - '
                                'NWK source: {:s} -> MAC source: '
                                '{:s}'.format(nwk_address,
                                              mac_address))
                elif self.white_list[rule_counter][nwk_address] == 'ALL':
                    return (20, 'White list match OK - '
                                'NWK source:{:s}'
                                '-> MAC_ALL'.format(nwk_address))
                elif self.white_list[rule_counter][nwk_address] != mac_address:
                    return (50, 'White list NWK/MAC address mismatch - '
                                'possible sinkhole attack with - NWK source:'
                                '{:s}/MAC source:{:s}'.format(nwk_address,
                                                              mac_address))
            except KeyError:
                pass
            try:
                if self.white_list[rule_counter]['ALL'] == 'ALL':
                    return (30, 'White list match OK -> ALL_ALL - '
                                'risky rule')
                elif self.white_list[rule_counter]['ALL'] == mac_address:
                    return (20, 'White list match OK {:s}'
                                ' -> NWK_ALL'.format(mac_address))
            except KeyError:
                pass

            rule_counter += 1
        return (30, 'White list - no rule for: '
                    'NWK address:{:s} -> MAC address:{:s}'.format(nwk_address,
                                                                  mac_address))

    def BlackListCheck(self, *pkt_data):
        nwk_address = pkt_data[0]
        mac_address = pkt_data[1]
        black_list_len = len(self.black_list)
        rule_counter = 0
        while rule_counter < black_list_len:
            try:
                if self.black_list[rule_counter][nwk_address] == mac_address:
                    return (50, 'black-list-malicious_node_found!')
                elif self.black_list[rule_counter][nwk_address] == 'ALL':
                    return (50, 'black-list-malicious_node_found!')
                elif self.black_list[rule_counter][nwk_address] != mac_address:
                    return (50, 'black-list-mac_addr_changed!')
            except KeyError:
                pass
            try:
                if self.black_list[rule_counter]['ALL'] == 'ALL':
                    return (20, 'black-list-malicious_node_found!_ALL_ALL')
                elif self.black_list[rule_counter]['ALL'] == mac_address:
                    return (20, 'black-list-malicious_node_found!_NWK_ALL')
            except KeyError:
                pass

            rule_counter += 1
        return (False, 'Black-list-Not_matching_rule_trusted_ID')

    def NeighborlistCheck(self, *pkt_data):
        node_nwk_addr = pkt_data[0]
        node_ncount = pkt_data[1]
        neighbors_id = pkt_data[2]
        rule_msg = [20, '']

        for nrule in self.neighbor_list:
            if nrule['id'] == node_nwk_addr:
                if nrule['count'] >= node_ncount:
                    rule_msg[1] += 'Neighbor count OK'
                else:
                    rule_msg[1] += 'Neighbor_count_mismatch'
                    rule_msg[0] = 40

                if sorted(nrule['neighbors']) != sorted(neighbors_id):

                    rule_msg[1] += (' / Neighbor list mismatch for {:s}:'
                                    ' - expected: {:s}'
                                    ' - given: {:s}'.format(node_nwk_addr,
                                                            nrule['neighbors'],
                                                            neighbors_id))
                    rule_msg[0] = 50
                else:
                    rule_msg[1] += (' / Neighbor list OK '
                                    'for {:s}'.format(node_nwk_addr))
                return rule_msg
        return (30, 'Not matching neighbor rule for:'
                    ' {:s}'.format(node_nwk_addr))
