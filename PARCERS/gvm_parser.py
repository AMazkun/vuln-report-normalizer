import re
import uuid

from lib_etc.logger_helper import logger
import xmltodict
from datetime import datetime

def parse_datetime_string(datetime_str):
    """Парсит строку даты и времени в datetime объект"""
    if not datetime_str:
        return None

    try:
        # Формат: 2025-07-28T12:45:37Z
        if datetime_str.endswith('Z'):
            return datetime.fromisoformat(datetime_str[:-1])
        else:
            return datetime.fromisoformat(datetime_str)
    except Exception as e:
        logger.warning(f"Не удалось парсить дату {datetime_str}: {e}")
        return None

def extract_gvm_version(data):
    """Извлекает версию GVM из отчета"""
    try:
        # Пытаемся найти версию в различных местах отчета
        scanner_info = data.get('get_reports_response', {}).get('report', {}).get('report', {}).get('gmp', {})
        if scanner_info:
            scanner_name = scanner_info.get('name', 'GVM')
            scanner_version = scanner_info.get('version', '')
            if scanner_name or scanner_version:
                return f"{scanner_name} {scanner_version}".strip()

        # Альтернативный поиск версии
        gmp_info = data.get('get_reports_response', {}).get('@version', '')
        if gmp_info:
            return f"GVM GMP {gmp_info}".strip()

        # Если не найдено, возвращаем общее название
        return "GVM OpenVAS"
    except Exception as e:
        logger.warning(f"Не удалось извлечь версию GVM: {e}")
        return "GVM OpenVAS"


def parse_gvm_xml_report(xml_file_path):
    """Парсинг XML отчета GVM"""
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
            data = xmltodict.parse(xml_content)

        # Извлекаем результаты из отчета

        source = data.get('get_reports_response') or data
        results = source.get('report', {}).get('report', {}).get('results', {})

        if not results:
            logger.warning("Результаты не найдены в XML отчете")
            return [], data, xml_content

        result_list = results.get("result", [])
        if isinstance(result_list, dict):
            result_list = [result_list]

        return result_list, data, xml_content

    except Exception as e:
        logger.error(f"Ошибка парсинга XML: {e}")
        raise

def extract_cve_from_refs(nvt_data):
    """Извлекает CVE из ссылок"""
    refs = nvt_data.get("refs", {})
    if not refs:
        return None

    ref_list = refs.get("ref", [])
    if isinstance(ref_list, dict):
        ref_list = [ref_list]

    cve_list = []
    for ref in ref_list:
        if isinstance(ref, dict) and ref.get("@type") == "cve":
            cve = ref.get("@id")
            if cve:
                cve_list.append(cve)

    return cve_list if len(cve_list)>0 else None


def parse_tags(tag_string):
    """
    Parse GVM tag string: key1=value1|key2=value2|...
    Returns dict of {key: value}.
    """
    tags = {}
    if not tag_string:
        return tags

    for part in tag_string.split("|"):
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip()] = val.strip()
    return tags

def extract_see_also_from_refs(nvt_data):
    """Извлекает ссылки 'See Also' из refs"""
    refs = nvt_data.get("refs", {})
    if not refs:
        return ""

    ref_list = refs.get("ref", [])
    if isinstance(ref_list, dict):
        ref_list = [ref_list]

    url_list = []
    for ref in ref_list:
        if isinstance(ref, dict) and ref.get("@type") == "url":
            url_list.append(ref.get("@id", ""))

    return ", ".join(url_list) if url_list else ""


def parse_gvm_report(xml_file, report_hash):
    """
    Parse GVM report XML → dict (ready for MongoDB).
    """
    with open(xml_file, "r", encoding="utf-8") as f:
        xml_data = f.read()

    report_dict = xmltodict.parse(xml_data)

    # Navigate into report
    report = report_dict.get("report", {})
    if not report:
        report_response = report_dict.get("get_reports_response", {})
        report = report_response.get("report", {})

    results = report.get("report").get("results")
    scan_id = report.get('@id', str(uuid.uuid1()))

    # Ensure results is a list
    if isinstance(results, dict):
        results = [results]

    events = []

    for res in results:
        the_results = res.get("result")
        if not the_results:
            continue
        if isinstance(the_results, dict):
            the_results = [the_results]
        for one_result in the_results:
            host = one_result.get("host", {}).get("#text", one_result.get("host", {}).get("hostname"))

            port_info = one_result.get("port", "")
            threat = one_result.get("threat")
            description = one_result.get("description")
            scan_begin_event = one_result.get("creation_time")
            scan_end_event = one_result.get("modification_time")

            # Port and protocol split
            port = None
            proto = None
            if port_info and "/" in port_info:
                port, proto = port_info.split("/", 1)

            nvt = one_result.get("nvt", {})
            plugin_id = nvt.get("@oid")
            plugin_name = nvt.get("name")
            severities = nvt.get('severities', {})
            # tags field is a long string with key=value|key=value...
            tags = parse_tags(nvt.get("tags"))

            # CVEs
            cves = extract_cve_from_refs(nvt)
            if isinstance(cves, str):
                cves = [cves]

            # XREFs
            xrefs = nvt.get("xref", [])
            if isinstance(xrefs, str):
                xrefs = [xrefs]

            event = {
                # Host info
                "Host": host,
                "Protocol": proto,
                "Port": port,
                "Service": nvt.get("family"),

                # Plugin info
                "Plugin ID": plugin_id,
                "Plugin Ver": None,  # GVM doesn't give direct plugin version
                "Plugin Publication Date": tags.get("creation_date"),
                "Plugin Modification Date": tags.get("modification_date"),
                "Plugin Name": plugin_name,
                "Plugin Output": description,

                # Vulnerability metadata
                "CVE": cves,
                "Risk": threat,
                "Synopsis": tags.get("summary"),
                "Description": tags.get("insight") or tags.get("summary"),
                "Solution": tags.get("solution"),
                "See Also": extract_see_also_from_refs(nvt),

                # CVSS
                "CVSS Base Type": severities.get('severity',{}).get('@type'),
                "CVSS Base Vector": severities.get('severity',{}).get("value"),
                "CVSS Base Score": nvt.get("cvss_base"),

                # Extra severity
                "STIG Severity": tags.get("stig_severity"),
                "VPR Score": None,   # Not in GVM
                "EPSS Score": None,  # Not in GVM
                "Risk Factor": threat,

                # References
                "BID": [x for x in xrefs if x.startswith("BID-")],
                "XREF": xrefs,
                "MSKB": [x for x in xrefs if x.startswith("MS")],
                "Metasploit": tags.get("metasploit_name"),
                "Core Impact": None,
                "CANVAS": None,

                # Scan metadata
                "scan_type": "Full Scan",  # could be adjusted
                "scan_tool": "GVM",
                "scan_begin": scan_begin_event,
                "scan_end": scan_end_event,
                "scan_id": scan_id,  # or hash of file
                "event_id": one_result.get('@id'),

                # Дополнительные поля специфичные для GVM
                "Hostname": one_result.get("host", {}).get("hostname", ""),
                "Asset ID": one_result.get("host", {}).get("asset", {}).get("@asset_id", ""),
                "NVT Family": one_result.get("nvt", {}).get("family", ""),
                "NVT": one_result.get("nvt", {}),
                "TAGS": tags,
                "QoD": one_result.get("qod", {}).get("value", ""),
                "QoD Type": one_result.get("qod", {}).get("type", ""),
                "Scan NVT Version": one_result.get("scan_nvt_version", ""),
                "Original Threat": one_result.get("original_threat", ""),
                "Original Severity": one_result.get("original_severity", ""),
                "Compliance": one_result.get("compliance", "")
            }

            event = {k: v for k, v in event.items() if v != '' and v is not None}
            events.append(event)

    # Извлекаем информацию из отчета для scan_info
    scan_begin = report.get('creation_time', '')
    scan_end = report.get('modification_time', '')


    # Извлекаем версию GVM и вычисляем хеш
    gvm_version = extract_gvm_version(report_dict)

    scan_info = {
        "scanner_type": "GVM",
        "creator": gvm_version,
        #"version": None,
        "scan_type": "Net Security",
        "scan_file": xml_file,
        "hash_stamp": report_hash,
        "scan_begin":scan_begin,
        "scan_end": scan_end,
        #"scan_duration": None,
        'scan_id': scan_id,

        "import_timestamp": datetime.now(),
        "total_hosts": len(set(r["Host"] for r in events if r["Host"])),
        "total_vulnerabilities": len(events)
    }

    return events, scan_info
