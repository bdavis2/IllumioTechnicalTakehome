import argparse

# sample flow log:
test_log_str = """
version,account-id,interface-id,srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes,start,end,action,log-status
2,123456789012,eni-0a1b2c3d,10.0.1.201,198.51.100.2,443,49153,6,25,20000,1620140761,1620140821,ACCEPT,OK
2,123456789012,eni-4d3c2b1a,192.168.1.100,203.0.113.101,23,49154,6,15,12000,1620140761,1620140821,REJECT,OK
2,123456789012,eni-5e6f7g8h,192.168.1.101,198.51.100.3,25,49155,6,10,8000,1620140761,1620140821,ACCEPT,OK
2,123456789012,eni-9h8g7f6e,172.16.0.100,203.0.113.102,110,49156,6,12,9000,1620140761,1620140821,ACCEPT,OK
2,123456789012,eni-7i8j9k0l,172.16.0.101,192.0.2.203,993,49157,6,8,5000,1620140761,1620140821,ACCEPT,OK
2,123456789012,eni-6m7n8o9p,10.0.2.200,198.51.100.4,143,49158,6,18,14000,1620140761,1620140821,ACCEPT,OK
2,123456789012,eni-1a2b3c4d,192.168.0.1,203.0.113.12,1024,80,6,10,5000,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-1a2b3c4d,203.0.113.12,192.168.0.1,80,1024,6,12,6000,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-1a2b3c4d,10.0.1.102,172.217.7.228,1030,443,6,8,4000,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-5f6g7h8i,10.0.2.103,52.26.198.183,56000,23,6,15,7500,1620140661,1620140721,REJECT,OK
2,123456789012,eni-9k10l11m,192.168.1.5,51.15.99.115,49321,25,6,20,10000,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-1a2b3c4d,192.168.1.6,87.250.250.242,49152,110,6,5,2500,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-2d2e2f3g,192.168.2.7,77.88.55.80,49153,993,6,7,3500,1620140661,1620140721,ACCEPT,OK
2,123456789012,eni-4h5i6j7k,172.16.0.2,192.0.2.146,49154,143,6,9,4500,1620140661,1620140721,ACCEPT,OK
"""



class FlowLogLine:
    def __init__(self, fields: list[str], *args):
        # self.version = args[0]
        # self.account_id = args[1]
        # self.interface_id = args[2]
        # self.srcaddr = args[3]
        # self.distaddr = args[4]
        # self.srcport = args[5]
        self.dstport = args[fields.index("dstport")]
        self.protocol = args[fields.index("protocol")]
        # self.packets = args[8]
        # self._bytes = args[9]
        # self.start = args[10]
        # self.end = args[11]
        # self.action = args[12]
        self.log_status = args[fields.index("log-status")]


# lookup table
test_table_str = """
25,tcp,sv_P1
68,udp,sv_P2
23,tcp,sv_P1
31,udp,SV_P3
443,tcp,sv_P2
22,tcp,sv_P4
3389,tcp,sv_P5
0,icmp,sv_P5
110,tcp,email
993,tcp,email
143,tcp,email"""


# dstport,protocol,tag
# 25,tcp,sv_P1
# 68,udp,sv_P2
# 23,tcp,sv_P1
# 31,udp,SV_P3
# 443,tcp,sv_P2
# 22,tcp,sv_P4
# 3389,tcp,sv_P5
# 0,icmp,sv_P5
# 110,tcp,email
# 993,tcp,email
# 143,tcp,email

class LookupTableRow:
    def __init__(self, *args):
        self.dstport = args[0][0]
        self.protocol = args[0][1]
        self.tag = args[0][2]


class ProtocolTableRow:
    def __init__(self, *args):
        self.num = args[0][0]
        self.keyword = args[0][1]


def list_of_protocol_rows_to_dict(protocol_table_rows):
    protocol_dict = dict()
    for row in protocol_table_rows:
        protocol_dict[row.num] = row.keyword
    return protocol_dict


def list_of_lookup_rows_to_dict(lookup_table_rows: list[LookupTableRow]):
    lookup_dict = dict()
    for row in lookup_table_rows:
        lookup_dict[row.dstport] = {"protocol": row.protocol, "tag": row.tag}
    return lookup_dict


class ProtocolTable:
    def __init__(self, protocol_table_rows: list[ProtocolTableRow]):
        self.table = list_of_protocol_rows_to_dict(protocol_table_rows)


class LookupTable:
    def __init__(self, lookup_table_rows: list[LookupTableRow]):
        self.table = list_of_lookup_rows_to_dict(lookup_table_rows)


def update_tag_counts(tag_count_dict, line, lookup_dict):
    # get tag from lookup table
    line_tag = lookup_dict[line.dstport]['tag'] if line.dstport in lookup_dict else "untagged"
    # update tag_counts dict {tag: count..}
    if line_tag in tag_count_dict:
        tag_count_dict[line_tag] += 1
    else:
        tag_count_dict[line_tag] = 1

    return tag_count_dict


def update_port_protocol_combo_counts(port_protocol_combo_counts, protocol_dict, line):
    # get protocol keyword from protocol lookup table
    keyword = protocol_dict[line.protocol]
    # see if key exists in combo dict
    if (line.dstport, keyword) in port_protocol_combo_counts:
        port_protocol_combo_counts[(line.dstport, keyword)] += 1
    else:
        port_protocol_combo_counts[(line.dstport, keyword)] = 1
    return port_protocol_combo_counts


def parse_flow_log(flow_log_lines: list, lookup_dict: dict, protocol_dict: dict):
    # dict of {tag: count}
    tag_count_dict = dict()
    # dict of {(port, protocol): count}
    port_protocol_combo_counts = dict()
    # gather list of fields from first line of file
    fields = flow_log_lines[0].replace("\n", "").split(",")
    assert("dstport" in fields and "protocol" in fields and "log-status" in fields)
    flow_log_lines = flow_log_lines[1:]
    for i in flow_log_lines:
        line = FlowLogLine(fields, *i.replace("\n", "").split(","))
        if line.log_status == "NODATA" or line.log_status == "SKIPDATA":
            continue
        tag_count_dict = update_tag_counts(tag_count_dict, line, lookup_dict)
        port_protocol_combo_counts = update_port_protocol_combo_counts(port_protocol_combo_counts, protocol_dict,
                                                                       line)
    return tag_count_dict, port_protocol_combo_counts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="vpcFlowLogParser",
        description="parses VPC flow logs",
    )
    parser.add_argument('logfile')
    parser.add_argument('lookup_table')
    parser.add_argument('--output', default="output.txt", required=False)
    args = parser.parse_args()
    with open(args.output, 'w') as out, open(args.lookup_table, 'r') as lookup, open(args.logfile) as log, open(
            "res/protocol-numbers-1.csv") as protocol:

        lookup_table = LookupTable([LookupTableRow(i.replace("\n", "").split(",")) for i in lookup.readlines()[1:]])
        protocol_table = ProtocolTable([ProtocolTableRow(i.replace("\n", "").split(",")) for i in protocol.readlines()[1:]])
        tag_counts, ppc_counts = parse_flow_log(log.readlines(), lookup_table.table, protocol_table.table)

        lookup.close()
        log.close()
        protocol.close()

        out.write("Tag Counts:\nTag,Count\n")
        for k, v in tag_counts.items():
            out.write('%s,%s\n' % (k, v))
        out.write("Port/Protocol Combination Counts:\nPort,Protocol,Count\n")
        for k, v in ppc_counts.items():
            out.write('%s,%s,%s\n' % (k[0], k[1], v))
        out.close()

