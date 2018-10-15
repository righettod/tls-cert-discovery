#!/usr/bin/env python
"""
    Tool to identify new host using the "subjectAltName" (SAN) extension of a x509 HTTP TLS certificate.
"""
import ssl
import sys
import socket
import OpenSSL
import argparse
import colorama
import xlsxwriter
import networkx as nx
import matplotlib.pyplot as plt
import os
from termcolor import colored
from IPy import IP
from tqdm import tqdm
from pathlib import Path
import warnings
import matplotlib.cbook

# Cache dictionary used to avoid to send IP lookup when IP has been already retrieived for a SAN.
# The KEY is the SAN and the VALUE is the IP address or 0.0.0.0 IP address for SAN with a wildcard or if IP cannot be resolved
SAN_CACHE_DICT = {}
warnings.filterwarnings("ignore",category=matplotlib.cbook.mplDeprecation)


def extract_tls_cert(host):
    """
    Extract the HTTP TLS certificate of the specified host targeting port 443
    :param host: Host (or IP) to check
    :return: The certificate of None if no HTTP TLS certificate is available
    """
    cert = None
    try:
        cert = ssl.get_server_certificate((host, 443))
    except:
        pass
    return cert


def extract_subject_alternate_name_list(cert):
    """
    Extract the list of the subject alternate name (SAN) of HTTP TLS certificate
    :param cert: HTTP TLS certificate source
    :return: The list of SAN of None if the source certificate do not have this extension
    """
    san = None
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for i in range(0, x509.get_extension_count()):
            ext = x509.get_extension(i)
            if "subjectAltName" in str(ext.get_short_name()):
                san = []
                content = ext.__str__()
                for d in content.split(","):
                    san.append(d.strip()[4:])
    except:
        pass
    return san


def extract_san_ip(san_list):
    """
    Extract for each SAN in the provided list the associated IP address if applicable
    :param san_list: List of SAN to process
    :return: A dict in which the KEY is the SAN and the VALUE is the IP address or 0.0.0.0 IP address for SAN with a wildcard or if IP cannot be resolved
    """
    result = {}
    for san_item in san_list:
        result[san_item] = "0.0.0.0"
        if "*" not in san_item:
            try:
                if san_item not in SAN_CACHE_DICT:
                    result[san_item] = socket.gethostbyname(san_item)
                    SAN_CACHE_DICT[san_item] = result[san_item]
                else:
                    result[san_item] = SAN_CACHE_DICT[san_item]
            except:
                pass
    return result


if __name__ == "__main__":
    colorama.init()
    # Define Socket global timeout
    socket.setdefaulttimeout(5)

    # Define parser for command line arguments
    parser = argparse.ArgumentParser(description="Tool to identify new host using the 'subjectAltName' (SAN) extension of a x509 HTTP TLS certificate.")
    parser.add_argument('-r', action="store", dest="ip_range", default=None, help="IP range to analyze in the CDIR format.")
    parser.add_argument('-f', action="store", dest="ip_file", default=None, help="IP range to analyze in which each line of the file contains a IP.")
    parser.add_argument('-o', action="store", dest="result_file", default="result.xlsx", help="Output file in which result must be stored.")
    args = parser.parse_args()

    # Verify arguments
    if args.ip_range is None and args.ip_file is None:
        print(colored("[!] An IP range or an IP file must be specified !", "red", attrs=[]))
        sys.exit(1)
    if args.ip_range is not None and args.ip_file is not None:
        print(colored("[!] An IP range and an IP file cannot be specified in the same time !", "red", attrs=[]))
        sys.exit(2)
    if args.ip_file is not None and not Path(args.ip_file).is_file():
        print(colored("[!] IP file must be a valid existing file !", "red", attrs=[]))
        sys.exit(3)

    # Extract the IP range to scan according to the method of providing used
    targets = []
    if args.ip_range is not None:
        for ip in IP(args.ip_range.strip()):
            targets.append(ip.__str__().strip())
    else:
        with open(args.ip_file, "r") as ipf:
            lines = ipf.readlines()
            for line in lines:
                targets.append(line.strip())

    # Display information about the targets range to scan
    print("[*] %s IP addresse(s) to process." % len(targets))

    # Process the targets range and gather data
    print("[*] Process the targets range and gather data...")
    data = {}
    for i in tqdm(range(0, len(targets))):
        current_ip = targets[i]
        data_key = current_ip + ":443"
        x509_cert = extract_tls_cert(current_ip)
        if x509_cert is not None:
            x509_cert_san = extract_subject_alternate_name_list(x509_cert)
            if x509_cert_san is not None and len(x509_cert_san) > 0:
                data[data_key] = []
                x509_cert_san_ip = extract_san_ip(x509_cert_san)
                for x509_cert_san_item in x509_cert_san:
                    san_infos = {}
                    san_ip = x509_cert_san_ip[x509_cert_san_item]
                    san_infos["SAN"] = x509_cert_san_item
                    san_infos["IP"] = san_ip
                    if san_ip == "0.0.0.0":
                        san_infos["IS_NEW_HOST"] = False
                    elif san_ip not in targets:
                        # Case in which the IP of the SAN is not in the initial list of IP to scan
                        san_infos["IS_NEW_HOST"] = True
                    else:
                        san_infos["IS_NEW_HOST"] = False
                    data[data_key].append(san_infos)

    # Generate the network graph
    print("[*] Generate the network graph...")
    san_added_nodes_no_linked_to_src_ip = []
    san_added_nodes_linked_to_src_ip = []
    src_ip_added_nodes = []
    graph = nx.Graph()
    for ip in data:
        san_infos_list = data[ip]
        ip_node_name = "IP Source\n%s" % ip
        graph.add_node(ip_node_name)
        src_ip_added_nodes.append(ip_node_name)
        for san_infos in san_infos_list:
            san_node_name = "%s\n%s" % (san_infos["SAN"], san_infos["IP"])
            san_ip_port = san_infos["IP"] + ":443"
            if san_ip_port in data:
                graph.add_edge(ip_node_name, san_node_name)
                san_added_nodes_linked_to_src_ip.append(san_node_name)
            else:
                graph.add_node(san_node_name)
                san_added_nodes_no_linked_to_src_ip.append(san_node_name)
    pos = nx.spring_layout(graph, k=3, scale=1000)
    nx.draw_networkx_nodes(graph, pos, node_size=400, node_color='orange', nodelist=src_ip_added_nodes)
    nx.draw_networkx_nodes(graph, pos, node_size=400, node_color='yellow', nodelist=san_added_nodes_no_linked_to_src_ip)
    nx.draw_networkx_nodes(graph, pos, node_size=400, node_color='green', nodelist=san_added_nodes_linked_to_src_ip)
    nx.draw_networkx_edges(graph, pos, width=2, alpha=0.5, edge_color='green', style='solid')
    nx.draw_networkx_labels(graph, pos, font_size=4, font_family='sans-serif')
    plt.axis('off')
    plt.savefig("graph.png", format="png", dpi=200, orientation="landscape")

    # Consolidate the result in a Excel worksbook
    print("[*] Consolidate the results in a Excel workbook...")
    workbook = xlsxwriter.Workbook(args.result_file)
    format_header = workbook.add_format({'bold': True, 'valign': 'vcenter', 'align': 'center'})
    worksheet = workbook.add_worksheet("Host founds")
    worksheet.write("A1", "Source", format_header)
    worksheet.write("B1", "Subject Alternate Name (SAN)", format_header)
    worksheet.write("C1", "SAN IP", format_header)
    worksheet.write("D1", "Was discovered", format_header)
    row = 1
    for ip in data:
        san_infos_list = data[ip]
        for san_infos in san_infos_list:
            if san_infos["IS_NEW_HOST"]:
                format_new_host = workbook.add_format({'bold': True, 'bg_color': 'green', 'font_color': 'white', 'valign': 'vcenter', 'align': 'right'})
                was_disco = "Yes"
            else:
                format_new_host = workbook.add_format({'valign': 'vcenter', 'align': 'right'})
                was_disco = "No"
            worksheet.write(row, 0, ip, format_new_host)
            worksheet.write(row, 1, san_infos["SAN"], format_new_host)
            worksheet.write(row, 2, san_infos["IP"], format_new_host)
            worksheet.write(row, 3, was_disco, format_new_host)
            row += 1
    worksheet.autofilter("A1:D" + str(row))
    worksheet.set_column(0, 3, 50)
    worksheet = workbook.add_worksheet("Network Graph")
    format_header = workbook.add_format({'bold': True, 'valign': 'vcenter', 'align': 'left'})
    format_text = workbook.add_format({'bold': False, 'valign': 'vcenter', 'align': 'left'})
    worksheet.write("A1", "Legend:", format_header)
    worksheet.write("A2", "Circle in orange", format_header)
    worksheet.write("B2", "Source IP included in the IP range to analyze", format_text)
    worksheet.write("A3", "Circle in green + linked line", format_header)
    worksheet.write("B3", "Relation between a source IP and a Subject Alternate Name", format_text)
    worksheet.write("A4", "Circle in yellow", format_header)
    worksheet.write("B4", "Subject Alternate Name without relation with a source IP", format_text)
    worksheet.insert_image("A5", "graph.png", {'x_offset': 5, 'y_offset': 5, 'x_scale': 2, 'y_scale': 2})
    worksheet.set_column(0, 2, 57)
    workbook.close()
    os.remove("graph.png")
    print(colored("[!] Results consolidated in file '%s' !" % args.result_file, "green"))
