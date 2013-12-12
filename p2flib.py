from __future__ import print_function, division
from subprocess import check_call
# from CythonUtil import c_parse_records_tshark

def parse_records_tshark(f_name):
    records = []
    NAME = ['start_time', 'src_ip', 'dst_ip', 'protocol', 'length',
            'src_port', 'dst_port']
    with open(f_name, 'r') as infile:
        for line in infile:
            line = line.strip()
            items = line.split()
            rec = (float(items[1]), items[2], items[4], items[5], items[6],
                    int(items[7]), int(items[8]))
            records.append(rec)
    return records, NAME

def export_to_txt(f_name, txt_f_name):
    cmd = """tshark -o column.format:'"No.", "%%m", "Time", "%%t", "Source", "%%s", "Destination", "%%d", "Protocol", "%%p", "len", "%%L", "srcport", "%%uS", "dstport", "%%uD"' -r %s > %s""" % (f_name, txt_f_name)

    print('--> ', cmd)
    check_call(cmd, shell=True)


def change_to_flows(records, name, time_out):
    t_seq = name.index('start_time')
    length_seq = name.index('length')
    # five_tuple_seq = [name.index(k) for k in ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol']]
    five_tuple_seq = [name.index(k) for k in ['src_ip', 'dst_ip', 'protocol']]
    open_flows = dict()
    res_flow = []
    for rec in records:
        # five_tuple = get_five_tuple(rec)
        five_tuple = tuple(rec[seq] for seq in five_tuple_seq)
        t = rec[t_seq]
        length = rec[length_seq]
        # check time out
        remove_flows = []
        for f_tuple, (st_time, last_time, fs) in open_flows.iteritems():
            if t - last_time > time_out: # time out
                fd = t - st_time
                res_flow.append( (st_time, ) + f_tuple + (fs, fd))
                remove_flows.append(f_tuple)
        for f_tuple in remove_flows:
            del open_flows[f_tuple]

        stored_rec = open_flows.get(five_tuple, None)
        if stored_rec is not None: # if already exists
            (st_time_old, last_time_old, fs_old) = stored_rec
            open_flows[five_tuple] = (st_time_old, t, fs_old + length)
        else: # not exisit
            open_flows[five_tuple] = (t, t, length)

    print("""
Totoal Packets: [%i]
Exported Flows: [%i]
Open Flows: [%i]
            """%(len(records), len(res_flow), len(open_flows)))

    return res_flow

def write_flow(flows, f_name):
    fid = open(f_name, 'w')
    for f in flows:
        fid.write(' '.join([str(v) for v in f]) + '\n')
    fid.close()

def pcap2flow(pcap_file_name, flow_file_name, time_out):
    txt_f_name = pcap_file_name.rsplit('.pcap')[0] + '_tshark.txt'
    export_to_txt(pcap_file_name, txt_f_name)
    records, name = parse_records_tshark(txt_f_name)
    res_flows = change_to_flows(records, name, time_out)
    write_flow(res_flows, flow_file_name)


