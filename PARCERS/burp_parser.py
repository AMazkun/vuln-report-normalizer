import hashlib
import xml.etree.ElementTree as ET
import xmltodict
from datetime import datetime


def burp_reports_parse_ge(burp_report_path):
    # Assume burp_report_path is the path to your Burp Suite XML file
    tree = ET.parse(burp_report_path)
    root = tree.getroot()

    scanned_events = []
    for issue in root.findall('issue'):
        host = issue.find('host').text
        url = issue.find('url').text
        protocol = issue.find('protocol').text
        path = issue.find('path').text
        port = issue.find('port').text
        name = issue.find('name').text
        severity = issue.find('severity').text
        description = issue.find('issueBackground').text
        solution = issue.find('remediationBackground').text

        # Optional: Find CVEs and other references
        cve_tags = issue.findall(".//vulnerabilityClassifications/classification[@type='cve']/identifier")
        cves = [c.text for c in cve_tags]

        event = {
            "Host": host,
            "Hostname": host,  # Can use the same value
            "Port": port,
            "Protocol": protocol,
            "Plugin Name": name,
            "Risk": severity,
            "Description": description,
            "Solution": solution,
            "CVE": cves,
            "scan_tool": "BURP",
            "scan_type": "Web application scan",
            # scan_begin and scan_end would need to be added manually or derived
        }
        scanned_events.append(event)

def burp_reports_parse_cg(file_path, report_hash):
    with open(file_path, "r", encoding="utf-8") as f:
        data = xmltodict.parse(f.read())

    results = []
    issues = data.get("issues", {}).get("issue", [])
    if not isinstance(issues, list):
        issues = [issues]

    for issue in issues:
        event = {
            "Host": issue.get("host", {}).get("#text"),
            "Protocol": issue.get("protocol"),
            "Port": issue.get("port"),
            "Hostname": issue.get("host"),
            "Service": "HTTP" if issue.get("protocol") == "http" else "HTTPS",
            "Plugin ID": issue.get("type"),
            "Plugin Name": issue.get("name"),
            "Plugin Output": f"{issue.get('issueDetail', '')}\n{issue.get('issueBackground', '')}\n{issue.get('remediationBackground', '')}",
            "CVE": issue.get("references"),
            "Risk": issue.get("severity"),
            "Synopsis": issue.get("issueBackground"),
            "Description": issue.get("issueDetail"),
            "Solution": issue.get("remediationBackground"),
            "See Also": issue.get("references"),

            "scan_type": "Web application scan",
            "scan_tool": "BURP",
            "scan_begin": scan_begin,
            "scan_end": scan_end,
            "scan_id": scan_id,  # or hash of file
            "event_id": one_result.get('@id'),

        }
        event = {k: v for k, v in event.items() if v != '' and v is not None}
        results.append(event)

    generated_time = "None"
    burp_version = "None"

    scan_info = {
        "scanner_type": "BURP",
        "creator": burp_version,
        #"version": wizard_uuid,

        "scan_type": "Web Application Security",
        "scan_file": file_path,
        "hash_stamp": report_hash,
        "scan_begin": generated_time,
        "scan_end": None,  # ZAP не предоставляет modification time
        # "scan_duration": None,
        'scan_id': generated_time,

        "total_vulnerabilities": len(results),
        "import_timestamp": datetime.now(),
    }

    return results, scan_info
