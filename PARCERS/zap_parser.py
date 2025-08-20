import datetime
import re
from urllib.parse import urlparse

import socket
import ipaddress
import xmltodict

from MAVERICK.lib_etc.logger_helper import logger

def get_ipv4_from_uri(uri: str) -> str:
    try:
        # Извлекаем hostname из URI
        parsed = urlparse(uri)
        hostname = parsed.hostname or uri

        # Проверка: это уже IP?
        try:
            ip = ipaddress.ip_address(hostname)
            if isinstance(ip, ipaddress.IPv4Address):
                return str(ip)  # Уже IPv4
            else:
                return f"Это IPv6: {ip}"
        except ValueError:
            pass  # Не IP, продолжаем

        # DNS lookup
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"Ошибка: {e}"


def map_zap_risk_to_risk_factor(risk_desc):
    """Мапит ZAP риск в Risk Factor"""
    if not risk_desc:
        return "None"

    risk_lower = risk_desc.lower()
    if "high" in risk_lower:
        return "Critical"
    elif "medium" in risk_lower:
        return "High"
    elif "low" in risk_lower:
        return "Medium"
    elif "informational" in risk_lower or "info" in risk_lower:
        return "None"
    else:
        return "None"


def extract_protocol_from_url(url):
    """Извлекает протокол из URL"""
    if not url:
        return "tcp"  # По умолчанию для веб-приложений

    try:
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme.lower()
        if protocol in ["http", "https"]:
            return "tcp"
        return protocol
    except:
        return "tcp"


def extract_port_from_url(url):
    """Извлекает порт из URL"""
    if not url:
        return "80"

    try:
        parsed_url = urlparse(url)
        if parsed_url.port:
            return str(parsed_url.port)
        elif parsed_url.scheme.lower() == "https":
            return "443"
        else:
            return "80"
    except:
        return "80"


def extract_cve_from_zap_desc(description):
    """Извлекает CVE из описания ZAP"""
    if not description:
        return ""

    # Регулярное выражение для поиска CVE
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cves = re.findall(cve_pattern, description, re.IGNORECASE)
    return list(set(cves)) if cves else None


def extract_references_from_zap(reference_str):
    """Извлекает ссылки из поля reference ZAP"""
    if not reference_str:
        return ""

    # ZAP часто хранит ссылки разделенные переносами строк
    refs = reference_str.split('\n')
    valid_refs = [ref.strip() for ref in refs if ref.strip().startswith('http')]
    return ", ".join(valid_refs) if valid_refs else reference_str


def extract_xref_from_zap(reference_str):
    """Извлекает XREF из ссылок ZAP"""
    if not reference_str:
        return ""

    # Ищем специфичные идентификаторы
    xrefs = []
    if "OWASP" in reference_str:
        owasp_matches = re.findall(r'OWASP[^,\n]*', reference_str)
        xrefs.extend([f"OWASP:{match.strip()}" for match in owasp_matches])

    return ", ".join(xrefs) if xrefs else ""


def format_zap_plugin_output(alert):
    """Форматирует вывод плагина для ZAP"""
    output_parts = []

    if alert.get("uri"):
        output_parts.append(f"URL: {alert['uri']}")

    if alert.get("method"):
        output_parts.append(f"Method: {alert['method']}")

    if alert.get("param"):
        output_parts.append(f"Parameter: {alert['param']}")

    if alert.get("attack"):
        output_parts.append(f"Attack: {alert['attack']}")

    if alert.get("evidence"):
        output_parts.append(f"Evidence: {alert['evidence']}")

    if alert.get("otherinfo"):
        output_parts.append(f"Other Info: {alert['otherinfo']}")

    return "\n".join(output_parts)


def extract_request_header(alert):
    """Извлекает заголовки запроса"""
    # В ZAP может храниться в различных местах
    instances = alert.get("instances", {})
    if isinstance(instances, dict):
        instance = instances.get("instance", {})
        if isinstance(instance, list) and instance:
            return instance[0].get("requestheader", "")
        elif isinstance(instance, dict):
            return instance.get("requestheader", "")
    return ""


def extract_response_header(alert):
    """Извлекает заголовки ответа"""
    instances = alert.get("instances", {})
    if isinstance(instances, dict):
        instance = instances.get("instance", {})
        if isinstance(instance, list) and instance:
            return instance[0].get("responseheader", "")
        elif isinstance(instance, dict):
            return instance.get("responseheader", "")
    return ""


def extract_request_body(alert):
    """Извлекает тело запроса"""
    instances = alert.get("instances", {})
    if isinstance(instances, dict):
        instance = instances.get("instance", {})
        if isinstance(instance, list) and instance:
            return instance[0].get("requestbody", "")
        elif isinstance(instance, dict):
            return instance.get("requestbody", "")
    return ""


def extract_response_body(alert):
    """Извлекает тело ответа"""
    instances = alert.get("instances", {})
    if isinstance(instances, dict):
        instance = instances.get("instance", {})
        if isinstance(instance, list) and instance:
            return instance[0].get("responsebody", "")
        elif isinstance(instance, dict):
            return instance.get("responsebody", "")
    return ""


def extract_message_id(alert):
    """Извлекает Message ID из instances"""
    instances = alert.get("instances", {})
    if isinstance(instances, dict):
        instance = instances.get("instance", {})
        if isinstance(instance, list) and instance:
            return instance[0].get("messageid", "")
        elif isinstance(instance, dict):
            return instance.get("messageid", "")
    return ""


def determine_input_vector(alert):
    """Определяет вектор ввода на основе параметров"""
    method = alert.get("method", "").upper()
    param = alert.get("param", "")

    if method == "GET" and param:
        return "URL Parameter"
    elif method == "POST" and param:
        return "POST Parameter"
    elif "cookie" in param.lower():
        return "Cookie"
    elif "header" in param.lower():
        return "HTTP Header"
    else:
        return "Unknown"


def extract_webapp_info(url):
    """Извлекает информацию о веб-приложении из URL"""
    if not url:
        return ""

    try:
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}"
    except:
        return url


def extract_zap_version_info(xml_data):
    """Извлекает информацию о версии ZAP"""
    try:
        # Ищем версию в атрибутах отчета
        owaspzap_report = xml_data.get('OWASPZAPReport', {})
        version = owaspzap_report.get('@version', '')

        if version:
            return f"OWASP ZAP {version}"
        else:
            return "OWASP ZAP"
    except Exception as e:
        logger.warning(f"Не удалось извлечь версию ZAP: {e}")
        return "OWASP ZAP"


def parse_zap_xml_report(xml_file_path):
    """Парсинг XML отчета ZAP"""
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
            data = xmltodict.parse(xml_content)

        # Извлекаем алерты из отчета ZAP
        owaspzap_report = data.get('OWASPZAPReport', {})
        sites_list = owaspzap_report.get('site', [])

        if not isinstance(sites_list, list):
            sites_list = [sites_list]

        return sites_list, owaspzap_report, data, xml_content

    except Exception as e:
        logger.error(f"Ошибка парсинга ZAP XML: {e}")
        raise

def parse_zap_report_cg(zap_file, report_hash):
    with open(zap_file, "r", encoding="utf-8") as f:
        xml_data = f.read()

    report_dict = xmltodict.parse(xml_data)

    report = report_dict.get("OWASPZAPReport", {})
    scan_begin = report.get("@generated")
    scan_end = scan_begin  # ZAP doesn’t log end, reuse timestamp
    # zap_version = owaspzap_report.get('@version', '')
    zap_version = extract_zap_version_info(report_dict)
    # Парсим дату генерации
    generated_time = report.get('@generated', '')

    sites = report.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    events = []

    for site in sites:
        host = site.get("@host")
        ip = site.get("@ip")
        port = site.get("@port")
        alerts = site.get("alerts", {}).get("alertitem", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            other_info = alert.get("otherinfo", "")
            cve = extract_cve_from_zap_desc(other_info)

            pluging_output = format_zap_plugin_output(alert)
            event = {
                "Host": host or ip,
                # "Host": get_ipv4_from_uri(alert.get("host", "")),
                # "Protocol": "tcp",
                "Protocol": extract_protocol_from_url(alert.get("name", "")),
                "Port": port,
                "Hostname": host,
                "Service": "http",
                # "Port": alert.get("port", ""),
                "URI": alert.get("uri", ""),
                "Method": alert.get("method", ""),

                "Plugin ID": alert.get("pluginid"),
                "Plugin Ver": None,
                "Plugin Publication Date": None,
                "Plugin Modification Date": None,
                "Plugin Name": alert.get("name"),
                "Plugin Output": pluging_output,

                "CVE": cve,
                "Risk": alert.get("riskdesc"),
                "Synopsis": alert.get("name"),
                "Description": alert.get("desc"),
                "Solution": alert.get("solution"),
                "See Also": alert.get("reference"),

                "CVSS Base Type": "CVSS3" if alert.get("cvssv3") else None,
                "CVSS Base Vector": alert.get("cvssv3_vector"),
                "CVSS Base Score": alert.get("cvssv3"),

                "STIG Severity": None,
                "VPR Score": None,
                "EPSS Score": None,
                "Risk Factor": alert.get("riskdesc"),
                #"Risk Factor_": map_zap_risk_to_risk_factor(alert.get("riskdesc", "")),

                "BID": [],
                #"XREF": [],
                "XREF": extract_xref_from_zap(alert.get("reference", "")),
                "MSKB": [],
                "Metasploit": None,
                "Core Impact": None,
                "CANVAS": None,

                "scan_type": "ZAP Scan",
                "scan_tool": "ZAP",
                "scan_begin": scan_begin,
                "scan_end": scan_end,
                "scan_id": zap_file,
                "event_id": None,

                # Специфичные для ZAP поля
                "Parameter": alert.get("param", ""),
                "Attack": alert.get("attack", ""),
                "Evidence": alert.get("evidence", ""),
                "CWE ID": alert.get("cweid", ""),
                "WASC ID": alert.get("wascid", ""),
                "Source ID": alert.get("sourceid", ""),
                "Other Info": other_info,
                "Request Header": extract_request_header(alert),
                "Response Header": extract_response_header(alert),
                "Request Body": extract_request_body(alert),
                "Response Body": extract_response_body(alert),
                "Confidence": alert.get("confidence", ""),
                "Risk Code": alert.get("riskcode", ""),
                "Reliability": alert.get("reliability", ""),
                "Message ID": extract_message_id(alert),
                "Input Vector": determine_input_vector(alert),
                #"Web Application": host,
            }

            event = {k: v for k, v in event.items() if v != '' and v is not None}
            events.append(event)

    # Создаем scan_info
    unique_hosts = set()
    unique_webapps = set()
    for result in events:
        if result.get("Host"):
            unique_hosts.add(result["Host"])
        # if result.get("Web Application"):
        #     unique_webapps.add(result["Web Application"])

    scan_info = {
        "scanner_type": "ZAP",
        "creator": zap_version,

        "scan_type": "Web Application Security",
        "scan_file": zap_file,
        "hash_stamp": report_hash,
        "scan_begin": generated_time,
        #"scan_end": None,  # ZAP не предоставляет modification time
        #"scan_duration": None,
        'scan_id': zap_file,

        "total_hosts": len(unique_hosts),
        #"total_webapps": len(unique_webapps),
        "total_vulnerabilities": len(events),
        "import_timestamp": datetime.datetime.now(),
    }

    return events, scan_info