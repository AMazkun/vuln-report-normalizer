import xmltodict
import json
from urllib.parse import urlparse
from datetime import datetime
import re
from lib_etc.logger_helper import logger

def extract_cve_from_nikto_desc(description):
    """Извлекает CVE из описания Nikto"""
    if not description:
        return ""

    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cves = re.findall(cve_pattern, description, re.IGNORECASE)
    return ", ".join(set(cves)) if cves else ""


def map_nikto_osvdb_to_risk(osvdb_id):
    """Мапит OSVDB ID в уровень риска (приблизительно)"""
    if not osvdb_id:
        return None

    # Логика может быть улучшена на основе базы данных OSVDB
    try:
        osvdb_num = int(osvdb_id)
        # Примерная логика (может потребовать настройки)
        if osvdb_num > 50000:  # Более новые и потенциально критичные
            return "Medium"
        else:
            return "Low"
    except:
        return "Low"


def map_nikto_osvdb_to_risk_factor(osvdb_id):
    """Мапит OSVDB ID в Risk Factor"""
    risk = map_nikto_osvdb_to_risk(osvdb_id)
    if not risk:
        return None
    risk_mapping = {
        "High": "Critical",
        "Medium": "High",
        "Low": "Medium",
        "None": "None"
    }
    return risk_mapping.get(risk, "None")


def extract_port_from_nikto_uri(uri):
    """Извлекает порт из URI Nikto"""
    if not uri:
        return "80"

    try:
        parsed_url = urlparse(uri)
        if parsed_url.port:
            return str(parsed_url.port)
        elif parsed_url.scheme.lower() == "https":
            return "443"
        else:
            return "80"
    except:
        return "80"


def extract_host_from_nikto_uri(uri):
    """Извлекает хост из URI Nikto"""
    if not uri:
        return ""

    try:
        parsed_url = urlparse(uri)
        return parsed_url.hostname or ""
    except:
        return ""


def generate_nikto_name(item):
    """Генерирует название уязвимости на основе данных Nikto"""
    desc = item.get("description", "")
    if len(desc) > 50:
        return desc[:50] + "..."
    return desc or f"Nikto Finding #{item.get('id', 'Unknown')}"


def extract_solution_from_nikto_desc(description):
    """Извлекает решение из описания Nikto"""
    if not description:
        return ""

    # Ищем ключевые слова для решений
    solution_keywords = [
        "should be", "configure", "disable", "remove", "update",
        "patch", "fix", "secure", "restrict", "block"
    ]

    sentences = description.split('. ')
    for sentence in sentences:
        if any(keyword in sentence.lower() for keyword in solution_keywords):
            return sentence.strip()

    return ""


def format_nikto_plugin_output(item):
    """Форматирует вывод плагина для Nikto"""
    output_parts = []

    if item.get("uri"):
        output_parts.append(f"URI: {item['uri']}")

    if item.get("method"):
        output_parts.append(f"Method: {item['method']}")

    if item.get("httpcode"):
        output_parts.append(f"HTTP Response: {item['httpcode']}")

    if item.get("contentlength"):
        output_parts.append(f"Content Length: {item['contentlength']}")

    if item.get("contenttype"):
        output_parts.append(f"Content Type: {item['contenttype']}")

    if item.get("osvdbid"):
        output_parts.append(f"OSVDB ID: {item['osvdbid']}")

    if item.get("description"):
        output_parts.append(f"Description: {item['description']}")

    return "\n".join(output_parts)

def extract_server_banner(item):
    """Извлекает информацию о сервере из описания"""
    desc = item.get("description", "")
    # Поиск информации о сервере в описании
    server_patterns = [
        r'Server: ([^\n\r,]+)',
        r'server is ([^\n\r,]+)',
        r'running ([^\n\r,]+)',
    ]

    for pattern in server_patterns:
        match = re.search(pattern, desc, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return ""


def determine_nikto_category(item):
    """Определяет категорию находки Nikto"""
    desc = item.get("description", "").lower()

    if any(keyword in desc for keyword in ["directory", "file", "path"]):
        return "Information Disclosure"
    elif any(keyword in desc for keyword in ["header", "response", "banner"]):
        return "Configuration"
    elif any(keyword in desc for keyword in ["script", "cgi", "php"]):
        return "Script Analysis"
    elif any(keyword in desc for keyword in ["authentication", "login", "password"]):
        return "Authentication"
    elif any(keyword in desc for keyword in ["ssl", "certificate", "tls"]):
        return "SSL/TLS"
    else:
        return "General"


def determine_finding_type(description):
    """Определяет тип находки"""
    desc = description.lower()

    if any(keyword in desc for keyword in ["vulnerable", "exploit", "attack"]):
        return "Vulnerability"
    elif any(keyword in desc for keyword in ["misconfiguration", "configuration", "setting"]):
        return "Misconfiguration"
    elif any(keyword in desc for keyword in ["information", "disclosure", "leak"]):
        return "Information Disclosure"
    elif any(keyword in desc for keyword in ["outdated", "version", "old"]):
        return "Version Detection"
    else:
        return "Informational"


def extract_server_info(item):
    """Извлекает информацию о веб-сервере"""
    server_banner = extract_server_banner(item)
    if server_banner:
        return server_banner

    # Попытка извлечь из URI
    uri = item.get("uri", "")
    if uri:
        parsed_url = urlparse(uri)
        return f"{parsed_url.scheme.upper()} Server at {parsed_url.netloc}"

    return ""


def determine_ssl_from_uri(uri):
    """Определяет использование SSL из URI"""
    if not uri:
        return "false"

    try:
        parsed_url = urlparse(uri)
        return "true" if parsed_url.scheme.lower() == "https" else "false"
    except:
        return "false"

def extract_nikto_scan_info(xml_data):
    """Извлекает информацию о сканировании Nikto"""
    try:
        niktoscan = xml_data.get('niktoscan', {})
        scandetails = niktoscan.get('scandetails', {})

        # Извлекаем базовую информацию
        sitename = scandetails.get('@sitename', '')
        siteid = scandetails.get('@siteid', '')
        hostip = scandetails.get('@hostip', '')
        starttime = scandetails.get('@starttime', '')
        endtime = scandetails.get('@endtime', '')

        return {
            'sitename': sitename,
            'siteid': siteid,
            'hostip': hostip,
            'starttime': starttime,
            'endtime': endtime
        }
    except Exception as e:
        logger.warning(f"Не удалось извлечь информацию о сканировании Nikto: {e}")
        return {}


def extract_nikto_version_info(xml_data):
    """Извлекает версию Nikto"""
    try:
        niktoscan = xml_data.get('niktoscan', {})
        version = niktoscan.get('@version', '')

        if version:
            return f"Nikto {version}"
        else:
            return "Nikto Web Scanner"
    except Exception as e:
        logger.warning(f"Не удалось извлечь версию Nikto: {e}")
        return "Nikto Web Scanner"

def calculate_nikto_scan_duration(scan_info_data):
    """Вычисляет продолжительность сканирования Nikto"""
    try:
        start_time = scan_info_data.get('starttime', '')
        end_time = scan_info_data.get('endtime', '')

        if start_time and end_time:
            start_dt = datetime.strptime(start_time, "%a %b %d %H:%M:%S %Y")
            end_dt = datetime.strptime(end_time, "%a %b %d %H:%M:%S %Y")
            duration = end_dt - start_dt
            return str(duration)
    except Exception as e:
        logger.warning(f"Не удалось вычислить продолжительность сканирования: {e}")

    return ""


def parse_nikto_report_cg(nikto_file, report_hash):
    with open(nikto_file, "r", encoding="utf-8") as f:
        xml_data = f.read()

    report_dict = xmltodict.parse(xml_data)

    # Извлекаем информацию из отчета для scan_info
    scan_info_data = extract_nikto_scan_info(report_dict)
    nikto_version = extract_nikto_version_info(report_dict)
    # Парсим время сканирования
    creation_time = datetime.now()
    if scan_info_data.get('starttime'):
        try:
            # Nikto время обычно в формате "Mon Jul 28 12:45:37 2025"
            creation_time = datetime.strptime(scan_info_data['starttime'], "%a %b %d %H:%M:%S %Y")
        except:
            logger.warning(f"Не удалось парсить время начала: {scan_info_data['starttime']}")

    scans = report_dict.get("niktoscans", {})
    if not isinstance(scans,list):
        scans = [scans]

    for scan in scans:
        scan = scan.get('niktoscan', {})
        scan_begin = scan.get("@scanstart")
        scan_end = scan.get("@scanend")
        scan_details = scan.get("scandetails", {})

        host = scan_details.get("@targethostname")
        ip = scan_details.get("@targetip")
        port = scan_details.get("@targetport")
        items = scan_details.get("item", [])
        if isinstance(items, dict):
            items = [items]

        events = []

        for item in items:
            event = {
                "Host": host or ip,
                "Protocol": "tcp",
                "Port": port,
                "Hostname": host,
                "URL": item.get("namelink", "") or generate_nikto_name(item),
                "Service": "http",
                "Method": item.get("@method", ""),
                "SSL": determine_ssl_from_uri(item.get("iplink", "")),

                "Plugin ID": item.get("@id"),
                "Plugin Ver": None,
                "Plugin Publication Date": None,
                "Plugin Modification Date": None,
                "Plugin Name": None,
                "Plugin Output": format_nikto_plugin_output(item),

                "CVE": [item.get("osvdbid")] if item.get("osvdbid") else extract_cve_from_nikto_desc(item.get("description", "")),

                "Risk": map_nikto_osvdb_to_risk(item.get("osvdbid", "")),
                "Synopsis": item.get("description", "")[:100] + "..." if len(
                    item.get("description", "")) > 100 else item.get("description", ""),
                "Description": item.get("description"),
                "Solution": item.get("recommendation"),
                "See Also": item.get("references"),
                #"See Also": item.get("namelink", ""),

                "CVSS Base Type": None,
                "CVSS Base Vector": None,
                "CVSS Base Score": None,

                "STIG Severity": None,
                "VPR Score": None,
                "EPSS Score": None,
                "Risk Factor": map_nikto_osvdb_to_risk_factor(item.get("osvdbid", "")),

                "BID": [],
                "XREF": [],
                "MSKB": [],
                "Metasploit": None,
                "Core Impact": None,
                "CANVAS": None,

                "scan_type": "Nikto Web Scan",
                "scan_tool": "NIKTO",
                "scan_begin": scan_begin,
                "scan_end": scan_end,
                "scan_id": nikto_file,
                "event_id": None,

                # Специфичные для Nikto поля
                "OSVDB ID": item.get("osvdbid", ""),
                "Test ID": item.get("id", ""),
                "HTTP Response":  item.get("httpcode", ""),
                "Content Length":  item.get("contentlength", ""),
                "Content Type":  item.get("contenttype", ""),
                "Server Banner": extract_server_banner(item),
                "Nikto Category":  determine_nikto_category(item),
                "Finding Type": determine_finding_type(item.get("description", "")),
                "Web Server":  extract_server_info(item),
            }
            event = {k: v for k, v in event.items() if v != '' and v is not None}
            events.append(event)

    # Определяем уникальные хосты и веб-приложения
    unique_url = set()
    unique_webapps = set()
    for result in events:
        if result.get("Hostname"):
            unique_url.add(result["Hostname"])
        if result.get("URL"):
            try:
                parsed_url = urlparse(result["URL"])
                webapp = f"{parsed_url.scheme}://{parsed_url.netloc}"
                unique_webapps.add(webapp)
            except:
                pass

    scan_info = {
        "scanner_type": "NIKTO",
        "creator": nikto_version,

        "scan_type": "Web Application Security",
        "scan_file": nikto_file,
        "hash_stamp": report_hash,
        "scan_begin": creation_time,
        #$"scan_end": None,
        "scan_duration": calculate_nikto_scan_duration(scan_info_data),
        'scan_id': nikto_file,

        "total_urls": len(unique_url),
        "total_webapps": len(unique_webapps),
        "total_vulnerabilities": len(events),
        "import_timestamp": datetime.now(),
        "target_site": scan_info_data.get('sitename', ''),
        "target_ip": scan_info_data.get('hostip', ''),
    }

    return events, scan_info
