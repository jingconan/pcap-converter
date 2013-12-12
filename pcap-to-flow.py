#!/usr/bin/env python
""" An simple script to convert pcap files to netflows.
"""
from __future__ import print_function, division
from p2flib import *
import os
def loop_folder(folder_name, time_out):
    """is not quite sucessful right now"""
    import glob
    for pcap_file_name in glob.glob( os.path.join(folder_name, '*.pcap') ):
        print("--> start to process pcap_file_nam: [%s]"%(pcap_file_name))
        pcap2flow(
                pcap_file_name,
                pcap_file_name.rsplit('.pcap')[0] + '.flow',
                time_out
                )


if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='convert txt file to flows')
    parser.add_argument('-p', '--pcap', default=None,
            help='specify the pcap file you want to process')
    parser.add_argument('-f', '--folder', default=None,
            help='specify the folder you want to loop through')

    parser.add_argument('-t', '--time_out', default=10, type=float,
            help='time out time')

    args = parser.parse_args()

    if args.pcap:
        pcap2flow(args.pcap, args.pcap.rsplit('.pcap')[0] + '.flow', args.time_out)
    elif args.folder:
        loop_folder(args.folder, args.time_out)
    else:
        parser.print_help()



    # export_to_txt('./best_malware_protection.pcap')
    # records, name = parse_txt('./best_malware_protection_tshark.txt')
    # res_flows = change_to_flows(records, name, 0.1)
    # write_flow(res_flows, './best_malware_protection_tshark.flow')

