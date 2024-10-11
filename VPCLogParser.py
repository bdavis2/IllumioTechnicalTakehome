import argparse

class FlowLogLine:
    def __init__(self, fields: list[str], *args):
        self.dstport = args[fields.index("dstport")]
        self.protocol = args[fields.index("protocol")]
        self.log_status = args[fields.index("log-status")]


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
    fields = flow_log_lines[0].replace("\n", "").lower().split(",")
    assert("dstport" in fields and "protocol" in fields and "log-status" in fields)
    flow_log_lines = flow_log_lines[1:]
    for i in flow_log_lines:
        line = FlowLogLine(fields, *i.replace("\n", "").lower().split(","))
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
    parser.add_argument('--output', default="example_output.txt", required=False)
    args = parser.parse_args()
    with open(args.output, 'w') as out, open(args.lookup_table, 'r') as lookup, open(args.logfile) as log, open(
            "res/protocol-numbers-1.csv") as protocol:

        lookup_table = LookupTable([LookupTableRow(i.replace("\n", "").lower().split(",")) for i in lookup.readlines()[1:]])
        protocol_table = ProtocolTable([ProtocolTableRow(i.replace("\n", "").lower().split(",")) for i in protocol.readlines()[1:]])
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
