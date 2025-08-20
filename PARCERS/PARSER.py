import hashlib
import os
import json
import shutil
import datetime
import time

import xmltodict
import pymongo

from PARCERS.burp_parser import burp_reports_parse_cg
from PARCERS.gvm_parser import parse_gvm_report
from PARCERS.mongodb_store import mongo_collection_add_report
from PARCERS.nessue_parser import parse_nessus_report
from PARCERS.nikto_parser import parse_nikto_report_cg
from PARCERS.nmap_parser import nmap_reports_parse_cg
from PARCERS.zap_parser import parse_zap_report_cg
from lib_etc.logger_helper import logger
from lib_etc.os_utils import collect_files_in_folder

# Подключение к MongoDB
def connect_to_mongodb(mongo_uri, db_name):
    """Подключение к MongoDB"""
    try:
        client = pymongo.MongoClient(mongo_uri)
        db = client[db_name]
        reports = db.csr_scans
        reports_cve = db.csr_events
        return client, reports, reports_cve
    except Exception as e:
        logger.error(f"Ошибка подключения к MongoDB: {e}")
        raise

def detect_scanner_type(xml_dict):
    """Detect scanner type based on XML root tags/attributes"""
    if "NessusClientData_v2" in xml_dict:
        return "NESSUS"
    elif "report" in xml_dict and "report_format" in xml_dict["report"]:
        return "GVM"
    elif "niktoscans" in xml_dict:
        return "NIKTO"
    elif "OWASPZAPReport" in xml_dict:
        return "ZAP"
    elif "<issues>" in xml_dict:
        return "BURP"
    elif "<nmaprun" in xml_dict:
        return "NMAP"
    else:
        return "Unknown"

def archive_report(archive_folder, file_path, scanner):
    """Move report into archive/{date}/{scanner}/"""
    today = datetime.date.today().strftime("%Y-%m-%d")
    archive_dir = os.path.join(archive_folder, today, scanner)
    os.makedirs(archive_dir, exist_ok=True)

    dest_file = os.path.join(archive_dir, os.path.basename(file_path))
    shutil.copy(file_path, dest_file)

    return dest_file


def parse_report(file_path, archive_folder, reports, reports_cve):
    """Auto-detect scanner and parse into MongoDB schema"""
    logger.info(f"Reading, archiving, processing file {file_path} ...")
    with open(file_path, "r", encoding="utf-8") as f:
        xml_data = f.read()


    xml_dict = xmltodict.parse(xml_data)
    scanner = detect_scanner_type(xml_dict)
    if scanner == "Unknown":
        return

    # archive original
    archived_file = archive_report(archive_folder, file_path, scanner)
    report_hash = hashlib.sha256(xml_data.encode('utf-8')).hexdigest()
    # if "report-e395e9c6-8f33-41c1-adb0-67c643e1c925" in file_path:
    #     print()

    if scanner == "NESSUS":
        events, scan_info = parse_nessus_report(archived_file, report_hash)
    elif scanner == "GVM":
        events, scan_info = parse_gvm_report(archived_file, report_hash)
    elif scanner == "NIKTO":
        events, scan_info = parse_nikto_report_cg(archived_file, report_hash)
    elif scanner == "ZAP":
        events, scan_info = parse_zap_report_cg(archived_file, report_hash)
    elif scanner == "NMAP":
        events, scan_info = nmap_reports_parse_cg(archived_file, report_hash)
    elif scanner == "BURP":
        events, scan_info = burp_reports_parse_cg(archived_file, report_hash)
    else:
        logger.info(f"Unknown scanner {scanner}")
        return

    return mongo_collection_add_report(archived_file, scan_info, events, reports, reports_cve)


if __name__ == "__main__":
    # Параметры подключения
    MONGO_URI = "mongodb://localhost:27017/"
    DB_NAME = "cs_reports_db"

    FILE_EXT = [".xml", ".nessus"]
    XML_FILE_FOLDER = "../import"
    ARCHIVE_FOLDER = "../archive"

    # Засекаем время до начала поиска
    start_time = time.time()
    logger.info(f"START PARSER in [{XML_FILE_FOLDER}] at {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}")
    # Обработка отчета
    try:
        files = collect_files_in_folder(XML_FILE_FOLDER, FILE_EXT)
        if len(files) == 0:
            print("Nothing to add in db")
            exit(1)
        # Подключение к MongoDB
        client, reports, reports_cve = connect_to_mongodb(MONGO_URI, DB_NAME)
    except Exception as e:
        print(f"Ошибка: {e}")
        exit(1)

    logger.info(f"Collected {len(files)} reports. Processing ...")
    count = 0
    errors = 0
    try:
        for file in files:
            file_name, file_extension = os.path.splitext(file)
            if file_extension.lower() not in FILE_EXT:
                continue

            try:
                count += 1
                document_id = parse_report(file, ARCHIVE_FOLDER, reports, reports_cve)
                logger.info(f"Report processed successfully, ID: [{document_id}] from {file_name}")
            except Exception as e:
                errors += 1
                logger.error(f"Error: {e} in file {file}")
    finally:
        logger.info(f"STATS In: {XML_FILE_FOLDER}\treports processed {count}, with problems {errors}")
        if 'client' in locals():
            client.close()
        # Засекаем время после окончания поиска
        end_time = time.time()
        elapsed_time = end_time - start_time

        logger.info(f"Total time: {elapsed_time:.4f} sec")
