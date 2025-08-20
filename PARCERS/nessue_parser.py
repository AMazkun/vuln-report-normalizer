import xmltodict
import uuid
from datetime import datetime

def transform_xml_properties(xml_tag_array, name = "name", value = "value") -> dict:
    transformed_tags = {}
    for item in xml_tag_array:
        if isinstance(item, dict) and name in item and value in item:
            transformed_tags[item[name]] = item[value]
    return transformed_tags

def parse_nessus_report(nessus_file, report_hash):
    with open(nessus_file, "r", encoding="utf-8") as f:
        xml_data = f.read()

    report_dict = xmltodict.parse(xml_data)
    # Извлекаем версию GVM и вычисляем хеш
    report_info = report_dict.get('get_reports_response', {}).get('report', {})
    policy = report_dict.get('NessusClientData_v2', {}).get('Policy', {})
    policy_name = policy.get('policyName', "")
    preferences = policy.get('Preferences', {}).get('ServerPreferences', {}).get('preference', {})
    preferences = transform_xml_properties(preferences)
    loaded_plugin_set = preferences.get('loaded_plugin_set', "")
    now = datetime.timestamp(datetime.now())
    scan_begin = datetime.fromtimestamp(float(preferences.get('scan_start_timestamp', now)))
    scan_end = datetime.fromtimestamp(float(preferences.get('scan_end_timestamp', now)))
    scan_id = preferences.get('report_task_id', str(uuid.uuid1()))
    wizard_uuid = preferences.get('wizard_uuid', "")

    reports = report_dict.get("NessusClientData_v2", {}).get("Report", {}).get("ReportHost", [])
    if isinstance(reports, dict):
        reports = [reports]

    mapped_docs = []

    for host_entry in reports:
        host_ip = host_entry.get("@name")
        host_props = host_entry.get("HostProperties", {}).get("tag", [])
        if isinstance(host_props, dict):
            host_props = [host_props]

        hostname = None
        for tag in host_props:
            if tag.get("@name") in ("host-fqdn", "hostname"):
                hostname = tag.get("#text")

        findings = host_entry.get("ReportItem", [])
        if isinstance(findings, dict):
            findings = [findings]

        for item in findings:
            see_also = item.get("see_also")
            doc = {
                "Host": host_ip,
                "Protocol": item.get("@protocol"),
                "Port": item.get("@port"),
                "Hostname": hostname,
                "Service": item.get("@svc_name"),

                "Plugin ID": item.get("@pluginID"),
                "Plugin Ver": item.get("script_version"),
                "Plugin Publication Date": item.get("plugin_publication_date"),
                "Plugin Modification Date": item.get("plugin_modification_date"),
                "Plugin Name": item.get("@pluginName"),
                "Plugin Output": item.get("plugin_output"),

                "CVE": item.get("cve", ""),
                "Risk": item.get("@severity"),  # numeric severity

                "Synopsis": item.get("synopsis"),
                "Description": item.get("description"),
                "Solution": item.get("solution"),
                "See Also": see_also,

                "CVSS Base Type": f"CVSS{item.get('@cvss_version', '2')}",
                "CVSS Base Vector": item.get("cvss_vector"),
                "CVSS Base Score": item.get("cvss_base_score"),

                "CVSS Temporal Score": item.get("cvss_temporal_score"),
                "CVSS Temporal Vector": item.get("cvss_temporal_vector"),

                "STIG Severity": item.get("@stig_severity"),
                "VPR Score": item.get("vpr_score"),
                "EPSS Score": item.get("epss_score"),
                "Risk Factor": item.get("risk_factor"),

                "BID": item.get("bid"),
                "XREF": item.get("xref"),
                "MSKB": item.get("msftkb"),
                "Metasploit": item.get("metasploit_name"),
                "Core Impact": item.get("core_impact"),
                "CANVAS": item.get("canvas"),

                "scan_type": "Policy Scan",
                "scan_tool": "NESSUS",
                "scan_begin": scan_begin,
                "scan_end": scan_end,
                "scan_id": nessus_file,
                "event_id": None,

                # NESSUS SPECIFIC
                "threat_intensity_last_28": item.get('threat_intensity_last_28'),
                "threat_recency": item.get('threat_recency'),
                "threat_sources_last_28": item.get('threat_sources_last_28'),
                "product_coverage": item.get('product_coverage'),
                "exploit_available": item.get('exploit_available'),
                "exploit_code_maturity": item.get('exploit_code_maturity'),
                "exploitability_ease": item.get('exploitability_ease'),
            }

            # delete empty fields
            doc = {k: v for k, v in doc.items() if v != '' and v is not None}

            # if item.get("cvss_temporal_vector") or item.get("cvss_vector"):
            #     print(item.get("cvss_temporal_vector"), item.get("cvss_vector"))
            #     print()
            mapped_docs.append(doc)

    # Обновление MongoDB
    scan_info = {
        "scanner_type": "NESSUS",
        "creator": loaded_plugin_set,
        "version": wizard_uuid,

        "scan_type": "Net Security",
        "scan_file": nessus_file,
        "hash_stamp": report_hash,
        "scan_begin":scan_begin,
        "scan_end": scan_end,
        #"scan_duration": None,
        'scan_id': scan_id,

        "import_timestamp": datetime.now(),
        "policy": policy,
        "policy_name": policy_name,
        "report_info": report_info,
        "total_hosts": len(set(r["Host"] for r in mapped_docs if r["Host"])),
        "total_vulnerabilities": len(mapped_docs)
    }

    return mapped_docs, scan_info

