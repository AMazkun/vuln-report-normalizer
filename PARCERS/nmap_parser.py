import os
import json
import shutil
import xmltodict
import xml.etree.ElementTree as ET
from datetime import datetime


def nmap_reports_parse_ge(nmap_report_path):

    # Assume nmap_report_path is the path to your Nmap XML file
    tree = ET.parse(nmap_report_path)
    root = tree.getroot()

    # Scan metadata
    scan_begin_str = root.get('startstr')
    scan_begin = datetime.strptime(scan_begin_str, '%a %b %d %H:%M:%S %Y') if scan_begin_str else None
    scan_end_str = root.find('runstats/finished').get('timestr')
    scan_end = datetime.strptime(scan_end_str, '%a %b %d %H:%M:%S %Y') if scan_end_str else None

    scanned_events = []
    for host in root.findall('host'):
        host_ip = host.find('address').get('addr')
        hostnames = [h.get('name') for h in host.findall('hostnames/hostname')]

        for port in host.findall('ports/port'):
            port_num = port.get('portid')
            protocol = port.get('protocol')
            service = port.find('service')
            service_name = service.get('name') if service is not None else 'unknown'

            event = {
                "Host": host_ip,
                "Hostname": hostnames,
                "Port": port_num,
                "Protocol": protocol,
                "Service": service_name,

                "scan_tool": "NMAP",
                "scan_type": "network_scan",
                "scan_begin": scan_begin,
                "scan_end":   scan_end,
                "scan_id":    scan_id,  # or hash of file
                "event_id":   one_result.get('@id'),

                # Additional fields to be filled if available from Nmap's script output
                "Plugin Output": None,
                "CVE": None
            }
            scanned_events.append(event)

    # Insert scanned_events into MongoDB

def nmap_reports_parse_cg(file_path, report_hash):
    with open(file_path, "r", encoding="utf-8") as f:
        data = xmltodict.parse(f.read())

    results = []
    hosts = data.get("nmaprun", {}).get("host", [])
    if not isinstance(hosts, list):
        hosts = [hosts]

    for host in hosts:
        ip = host.get("address", {}).get("@addr")
        hostnames = host.get("hostnames", {}).get("hostname", [])
        if isinstance(hostnames, dict):
            hostnames = [hostnames]

        ports = host.get("ports", {}).get("port", [])
        if isinstance(ports, dict):
            ports = [ports]

        for port in ports:
            results.append({
                "Host": ip,
                "Protocol": port.get("@protocol"),
                "Port": port.get("@portid"),
                "Hostname": hostnames[0].get("@name") if hostnames else None,
                "Service": port.get("service", {}).get("@name"),
                "Plugin ID": port.get("script", {}).get("@id") if port.get("script") else None,
                "Plugin Name": port.get("script", {}).get("@id") if port.get("script") else None,
                "Plugin Output": port.get("script", {}).get("@output") if port.get("script") else None,

                "scan_tool": "NMAP",
                "scan_type": "network_scan",
                "scan_begin": scan_begin,
                "scan_end": scan_end,
                "scan_id": scan_id,  # or hash of file
                "event_id": one_result.get('@id'),
            })
    return results