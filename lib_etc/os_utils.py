import os
import shutil
from math import trunc


def erase_directory(path: str)->bool:
    # Видаляємо весь вміст каталогу
    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        try:
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
            return True
        except Exception as e:
            print(f"Error deleting {item_path}: {e}")
            return False

def ensure_clean_directory(path)->bool:
    if os.path.exists(path):
        return  erase_directory(path)
    else:
        # Створюємо каталог
        try:
            os.makedirs(path)
            print(f"Folder created: {path}")
            return  True
        except Exception as e:
            print(f"Error creating folder {path}: {e}")
            return False

def collect_files_in_folder(path: str, FILE_EXT: list[str])-> list[str]:
    """
    Checks if a given path is a file or a folder. If it's a folder,
    it returns a list of all file names within that folder.

    Args:
        path (str): The path to check (file or folder).
    """
    if not os.path.exists(path):
        return []
    elif os.path.isfile(path):
        _, file_extension = os.path.splitext(path)
        if file_extension.lower() in FILE_EXT:
            return [path]
        else:
            return []
    elif os.path.islink(path):
        real_path = os.readlink(path)
        files_in_link = collect_files_in_folder(real_path, FILE_EXT)
        return files_in_link
    elif os.path.isdir(path):
        files_in_folder = []
        list_dir = os.listdir(path)
        #print("list_dir=", list_dir)
        for item in list_dir:
            #print("item=", item)
            item_path = os.path.join(path, item)
            if os.path.islink(item_path):
                target = os.readlink(item_path)
                # If the target is relative, resolve it to an absolute path
                files_in_folder += collect_files_in_folder(target, FILE_EXT)
            elif os.path.isfile(item_path):
                _, file_extension = os.path.splitext(item)
                if file_extension.lower() in FILE_EXT:
                    files_in_folder.append(item_path)
            elif os.path.isdir(path):
                files_in_folder += collect_files_in_folder(item_path, FILE_EXT)
        return files_in_folder
    else:
        return []
