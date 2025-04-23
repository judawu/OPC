import json
import os
from typing import Dict, Optional, Tuple, List, Callable
from decimal import Decimal
import datetime
import pywintypes
import ctypes  # 添加 ctypes 用于强制类型转换
import logging
import pickle

def _format_data_(data: Dict[str, any]) -> Dict:
    """将服务器状态格式化为字典，处理特定类型的数据"""
    formatted_data = {}
    for key, value in data.items():
        if isinstance(value, Decimal):
            formatted_data[key] = float(value)
        elif isinstance(value, bytes):
            formatted_data[key] = value.decode('utf-8')
        elif isinstance(value, (datetime.datetime, pywintypes.TimeType)):
            formatted_data[key] = value.isoformat()
        elif isinstance(value, tuple):  # 使用小写 tuple
            new_value = []
            for item in value:  # 使用 item 遍历，避免索引
                if isinstance(item, (datetime.datetime, pywintypes.TimeType)):
                    new_value.append(item.isoformat())
                elif isinstance(item, Decimal):
                    new_value.append(float(item))
                elif isinstance(item, bytes):
                    new_value.append(item.decode('utf-8'))
                else:
                    new_value.append(item)
            formatted_data[key] = tuple(new_value)
        elif isinstance(value, list):  # 使用小写 list
            new_value = []
            for item in value:
                if isinstance(item, (datetime.datetime, pywintypes.TimeType)):
                    new_value.append(item.isoformat())
                elif isinstance(item, Decimal):
                    new_value.append(float(item))
                elif isinstance(item, bytes):
                    new_value.append(item.decode('utf-8'))
                elif isinstance(item, dict):  # 使用小写 dict
                    new_value.append(_format_data_(item))
                else:
                    new_value.append(item)
            formatted_data[key] = new_value
        elif isinstance(value, dict):
            formatted_data[key] = _format_data_(value)
        else:
            formatted_data[key] = value
    return formatted_data

def _format_json_(data: Dict[str, any]) -> str:
    """将服务器状态格式化为 JSON 字符串"""
    formatted_data = _format_data_(data)
    return json.dumps(formatted_data, indent=6, ensure_ascii=False)

def extract_scode(error_obj):
    """
    从 pywintypes.com_error 对象中提取 scode 值。
    
    参数:
        error_obj: pywintypes.com_error - COM 异常对象
    
    返回:
        int: scode 值，如果无法提取则返回 -2147352567
    """
    try:
        # 检查输入是否为 pywintypes.com_error 类型
        if not isinstance(error_obj, pywintypes.com_error):
            return -2147352567
        
        # 提取 excepinfo 元组
        excepinfo = error_obj.excepinfo
        
        # 检查 excepinfo 是否为元组且长度为 6
        if not isinstance(excepinfo, tuple) or len(excepinfo) != 6:
            return error_obj.hresult
        
        # 返回 scode（excepinfo 的第 5 个元素）
        return excepinfo[5]
    except Exception:
        # 如果发生任何异常，返回 -2147352567
        return -2147352567

def transfer_errcode(error_code):
    """将错误代码转换为有效的 32 位整数"""
    if isinstance(error_code, str) and error_code.startswith("0x"):
        error_code = int(error_code, 16)
    if not isinstance(error_code, int):  # 修正：检查是否为 int
        logging.error("transfer_errcode: invalid error code type, should be int")
        return -2147352567
    if error_code > 0x7FFFFFFF:
        error_code = error_code - 0x100000000
    try:
        if not (-2147483648 <= error_code <= 2147483647):
            logging.error(f"_DVUACommon_.transfer_errcode: Error code {error_code} out of valid range")
            return -2147352567
        error_code = ctypes.c_long(error_code).value
        return error_code  # 修正：返回转换后的 error_code
    except Exception as e:
        logging.error(f"_DVUACommon_.transfer_errcode {error_code}: {str(e)}")
        return -2147352567

def flatten_structure(structure: Dict, parent_path: str = "") -> List[str]:
    """Convert nested structure dictionary to a flat list of paths."""
    items = []
    for key, value in structure.items():
        full_path = f"{parent_path}.{key}" if parent_path else key
        items.append(full_path)
        if isinstance(value, dict) and value:  # 如果有子节点，递归展开
            items.extend(flatten_structure(value, full_path))
    return items

def convert_paths(paths: List[str]) -> List[str]:
    """
    Convert full OPC DA paths to short paths by removing the first two segments,
    keeping the last dot and suffix, and replacing intermediate dots with slashes.
    
    Args:
        paths (List[str]): List of full paths, e.g., ['MODULES.AREA_V1.V1-IO.AI1_SCI1.EU0']
    
    Returns:
        List[str]: List of converted short paths, e.g., ['V1-IO/AI1_SCI1.EU0']
    """
    converted_paths = []
    
    for path in paths:
        # Split the path by dots
        parts = path.strip().split('.')
        
        # Check if there are at least 3 parts (to remove first two and keep last)
        if len(parts) < 3:
            converted_paths.append(path)  # Return original if invalid
            continue
        
        # Remove the first two parts (MODULES and AREA_Vx)
        remaining_parts = parts[2:]
        
        # If only one part remains after removal, use it as is
        if len(remaining_parts) == 1:
            converted_paths.append(remaining_parts[0])
            continue
        
        # Take all but the last part, join with slashes, then append the last part with its dot
        prefix_and_middle = remaining_parts[:-1]
        last_part = remaining_parts[-1]
        short_path = '/'.join(prefix_and_middle) + '.' + last_part
        
        converted_paths.append(short_path)
    
    return converted_paths

def merge_structures(main, new, path_parts, replace_empty=False):
    """Merge new structure into main structure at specified path."""
    if not path_parts:  # Reached the target location
        if new is None or (new == {} and replace_empty):
            return None
        elif new == {} and not replace_empty:
            return main
        
        if not isinstance(main, dict):
            main = {}
        
        for key, value in new.items():
            if isinstance(value, dict):
                if key not in main or not isinstance(main.get(key), dict):
                    main[key] = {}
                result = merge_structures(main[key], value, [], replace_empty)
                if result is None:
                    del main[key]
                elif value != {} or (replace_empty and main[key] == {}):
                    main[key] = result
            else:
                if key not in main or (replace_empty and main.get(key) in [None, {}, ""]):
                    main[key] = value
        return main
    
    current_part = path_parts[0]
    remaining_parts = path_parts[1:]

    if current_part not in main or not isinstance(main.get(current_part), dict):
        main[current_part] = {}

    if merge_structures(main[current_part], new, remaining_parts, replace_empty) is None:
        del main[current_part]

    return main

def update_structure(new_structure, target_path="", main_structure_file=None, replace_empty=False):
    """Update main structure with new structure and save to bin file."""
    if main_structure_file is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        main_structure_file = os.path.join(current_dir, 'main_structure.bin')
    
    try:
        if os.path.exists(main_structure_file):
            with open(main_structure_file, 'rb') as f:
                main_structure = pickle.load(f)
        else:
            main_structure = {}
        
        path_parts = target_path.split('.') if target_path else []
        merge_structures(main_structure, new_structure, path_parts, replace_empty)

        with open(main_structure_file, 'wb') as f:
            pickle.dump(main_structure, f)
        #print(f"Updated structure: {main_structure}")

    except Exception as e:
        logging.error(f"_DVUACommon_.update_structure: Failed to update main structure: {str(e)}")
        raise

def load_structure(main_structure_file=None) -> Dict:
    """从bin文件加载结构"""
    try:
        if main_structure_file is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            main_structure_file = os.path.join(current_dir, 'main_structure.bin')
        with open(main_structure_file, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        logging.error(f"_DVUACommon_.load_structure: Failed to load structure: {str(e)}")
        return {}

def bin_to_json(output_json_path: str = None) -> Dict:
    """将bin文件转换为json格式"""
    structure = load_structure()
    if output_json_path:
        try:
            with open(output_json_path, 'w') as f:
                json.dump(structure, f, indent=4)
        except Exception as e:
            logging.error(f"_DVUACommon_.bin_to_json: Failed to convert to JSON: {str(e)}")
    return structure