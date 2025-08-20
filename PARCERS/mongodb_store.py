import pymongo
import hashlib

from MAVERICK.lib_etc.logger_helper import logger

def update_mongodb_collections(xml_file_path, reports, reports_cve, converted_results, scan_info):
    """Обновляет MongoDB коллекцию с результатами"""
    try:

        # Вставляем документ
        scan_id = scan_info['scan_id']
        if_report_exists = reports.find_one({ "scan_id" : scan_id})
        if if_report_exists:
            result = reports.update_one({ "scan_id" : scan_id}, {"$set" : scan_info})
            logger.info(f"Updated report: {scan_id} ID {result}")
            reports_cve.delete_many({ "scan_id" : scan_id})
        else:
            result = reports.insert_one(scan_info)
            logger.info(f"Report added: {scan_id} ID {result.inserted_id}")

        # Также можно вставлять каждый результат отдельно для лучшего поиска
        individual_results = []
        for vuln in converted_results:
            vuln_doc = vuln.copy()
            vuln_doc["scan_id"] = scan_id
            individual_results.append(vuln_doc)

        if individual_results:
            individual_result = reports_cve.insert_many(individual_results)
            logger.info(f"Found {len(individual_result.inserted_ids)} events stored in collection")

        return scan_id

    except Exception as e:
        logger.error(f"Error while updating MongoDB collection for {xml_file_path}, error {e}")
        raise

def mongo_collection_add_report(xml_file_path, scan_info, events, reports, reports_cve):
    """Основная функция обработки отчета """

    if not events:
        logger.warning(f"No events in report: {xml_file_path}")
        return None

    logger.info(f"Place report events of: {xml_file_path}")

    # Обновление MongoDB

    document_id = update_mongodb_collections(xml_file_path, reports, reports_cve, events, scan_info)
    if document_id is None:
        logger.error(f"Something wrong with db insertion {scan_info}")

    logger.info(f"Saved in DB with ID [{document_id}]")
    return document_id
