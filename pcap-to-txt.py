#!/usr/bin/env python
""" An simple script to export flow, for test use only
"""
from __future__ import print_function, division
from p2flib import *

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='convert pcap file to txt. require tshark')
    parser.add_argument('-i', '--input', default=None,
                        help='specify the pcap file you want to process')
    parser.add_argument('-o', '--output', default=None,
                        help='output file, default value is '
                        'output will be <input_file_path>_tshark.txt')

    args = parser.parse_args()
    if args.input:
        if args.output:
            export_to_txt(args.input, args.output)
        else:
            txt_f_name = args.input.rsplit('.pcap')[0] + '_tshark.txt'
            export_to_txt(args.input, txt_f_name)
    else:
        parser.print_help()
