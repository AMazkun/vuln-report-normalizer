# Настройка логирования
from datetime import datetime
import json
import logging
from typing import Dict, Any, Optional


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def remove_empty_json(obj):
    if isinstance(obj, dict):
        return {k: remove_empty_json(v) for k, v in obj.items() if v is not None and v != "" and v != [] and v != {}}
    elif isinstance(obj, list):
        return [remove_empty_json(elem) for elem in obj if elem is not None and elem != "" and elem != [] and elem != {}]
    else:
        return obj

def array_str_to_(data:list, length = 3) -> str:
    if len(data) > length:
        s =  "[" + ", ".join(str(item) for item in data[:length])+ " ..."
        return s
    else:
        s =  "[" + ", ".join(str(item) for item in data)+ "]"
        return f'{data}'

def json_safe(obj):
    """Рекурсивно преобразует объект в JSON-допустимый формат."""
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_safe(v) for v in obj]
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    else:
        # Всё, что не JSON-сериализуемое — в строку
        return str(obj)


def json_save(title:str, data: Dict[str, Any], REPORTS_DIR = "reports/", filename: Optional[str] = None) -> str:
    """Экспорт результатов сканирования в JSON"""
    if not filename:
        filename = f"{REPORTS_DIR}{title}__{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        safe_data = json_safe(data)
        # Конвертируем ObjectId в строки для JSON сериализации
        export_json = json.dumps(safe_data, default=str, indent=2, ensure_ascii=False)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(export_json)

        logger.info(f"Данные экспортированы в файл: {filename}")

    except Exception as e:
        logger.error(f"Ошибка при экспорте в JSON: {e}")

    return filename

def load_json(filename):
    """Загружает список словарей из JSON-файла."""
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def merge_json(obj1, obj2) -> dict | list:
    """Рекурсивное слияние двух JSON-подобных структур"""

    # Если оба — словари, сливаем по ключам
    if isinstance(obj1, dict) and isinstance(obj2, dict):
        merged = dict(obj1)
        for key, value in obj2.items():
            if key in merged:
                merged[key] = merge_json(merged[key], value)
            else:
                merged[key] = value
        return merged

    # Если оба — списки, объединяем уникально
    if isinstance(obj1, list) and isinstance(obj2, list):
        merged_list = obj1[:]
        for item in obj2:
            if item not in merged_list:
                merged_list.append(item)
        return merged_list

    # Если значения разные и не списки — делаем список из уникальных значений
    if obj1 != obj2:
        if isinstance(obj1, list):
            merged_list = obj1[:]
            if obj2 not in merged_list:
                merged_list.append(obj2)
            return merged_list
        if isinstance(obj2, list):
            merged_list = obj2[:]
            if obj1 not in merged_list:
                merged_list.append(obj1)
            return merged_list
        return [obj1, obj2]  # два простых значения

    # Если значения одинаковые
    return obj1

def test_merge():
    # ==== Пример ====
    json1 = {
        "name": "Server1",
        "ip": "192.168.0.1",
        "tags": ["prod", "db"],
        "meta": {
            "location": "Datacenter A",
            "os": "Linux"
        }
    }

    json2 = {
        "ip": "192.168.0.1",  # одинаково — игнорируем
        "tags": ["db", "backup"],  # добавляем "backup"
        "meta": {
            "os": "Linux",  # одинаково — игнорируем
            "role": "database"
        }
    }

    #merged = merge_json(json1, json2)
    merged = merge_json(problems.host_info_041, problems.host_info_065)
    merged = merge_json(merged, problems.host_info_127)
    print(json.dumps(merged, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    test_merge()