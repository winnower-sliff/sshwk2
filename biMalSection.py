#!/usr/bin/python

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite

args = argparse.ArgumentParser(
    "Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path", help="directory with malware samples")
args.add_argument("output_file", help="file to write DOT file to")
args.add_argument("wares_projection", help="file to write DOT file to")
args.add_argument("sectionName_projection", help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()

valid_hostname_suffixes = [
    string.strip() for string in open("domain_suffixes.txt")
]
valid_hostname_suffixes = set(valid_hostname_suffixes)


def find_hostnames(string):
    possible_hostnames = re.findall(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',
        string)
    valid_hostnames = [
        hostname for hostname in possible_hostnames
        if hostname.split(".")[-1].lower() in valid_hostname_suffixes
    ]
    return valid_hostnames


def get_peSection_names(path: str):
    secName = []
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return []
    else:
        for section in pe.sections:
            secName += [str(section.Name, 'utf-8').strip()]
    return secName


# search the target directory for valid Windows PE executable files
for root, dirs, files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root, path))
        except pefile.PEFormatError:
            continue
        fullpath = os.path.join(root, path)
        # extract printable strings from the target sample
        strings = os.popen("strings '{0}'".format(fullpath)).read()
        # use the search_doc function in the included reg module to find hostnames
        hostnames = find_hostnames(strings)
        secNames = get_peSection_names(fullpath)
        if len(hostnames):
            # add the nodes and edges for the bipartite network
            network.add_node(path,
                             label=path[:32],
                             color='black',
                             penwidth=5,
                             bipartite=0)
            for sec in secNames:
                network.add_node(sec,
                                 label=sec,
                                 color='blue',
                                 penwidth=10,
                                 bipartite=1)
                network.add_edge(sec, path, penwidth=2)
        # if hostnames:
            # print("Extracted hostnames from:", path)
            # pprint.pprint(secNames)
# write the dot file to disk
write_dot(network, args.output_file)
wares = set(n for n, d in network.nodes(data=True) if d['bipartite'] == 0)
sectionNames = set(network) - wares

# use NetworkX's bipartite network projection function to produce the malware
# and hostname projections
wares_network = bipartite.projected_graph(network, wares)
sectionName_network = bipartite.projected_graph(network, sectionNames)

# write the projected networks to disk as specified by the user
write_dot(wares_network, args.wares_projection)
write_dot(sectionName_network, args.sectionName_projection)
