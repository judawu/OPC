import json
import os
from typing import Dict, Optional, Tuple, List, Callable
from decimal import Decimal
import datetime
import pywintypes
import ctypes  # 添加 ctypes 用于强制类型转换
import logging
import pickle
import struct
from cryptography.fernet import Fernet
import zlib
import uuid 

TYPE_STRING = 0x01
TYPE_BOOL = 0x02
TYPE_INT = 0x03
TYPE_FLOAT = 0x04
TYPE_TUPLE = 0x05
TYPE_LIST = 0x06
TYPE_DICT = 0x07
TYPE_DATETIME = 0x08
TYPE_DECIMAL = 0x09
TYPE_UUID = 0x0A
TYPE_BYTES = 0x0B
TYPE_NONE = 0x0C

def pretify_data(data: Dict[str, any]) -> Dict:
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
                    new_value.append(pretify_data(item))
                else:
                    new_value.append(item)
            formatted_data[key] = new_value
        elif isinstance(value, dict):
            formatted_data[key] = pretify_data(value)
        else:
            formatted_data[key] = value
    return formatted_data

def pretify_json(data: Dict[str, any],ensure_ascii:Optional[bool]=False) -> str:
    """将服务器状态格式化为 JSON 字符串"""
    formatted_data = pretify_data(data)
    return json.dumps(formatted_data, indent=6, ensure_ascii=ensure_ascii)

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

    # 生成或加载加密密钥


# 生成或加载加密密钥
def get_fernet_key(key_file):
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return Fernet(f.read())
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return Fernet(key)

def serialize_data(data):
    """将 data 列表序列化为二进制字节流"""
    result = bytearray()
    # 写入元素数量
    result.extend(struct.pack('<H', len(data)))
    
    for item in data:
        if isinstance(item, str):
            # 字符串：类型 | 长度 | 数据
            encoded = item.encode('utf-8')
            result.extend(struct.pack('<B', TYPE_STRING))
            result.extend(struct.pack('<H', len(encoded)))
            result.extend(encoded)
        elif isinstance(item, bool):
            # 布尔：类型 | 值
            result.extend(struct.pack('<B', TYPE_BOOL))
            result.extend(struct.pack('<B', 1 if item else 0))
        elif isinstance(item, int):
            # 整数：类型 | 数据
            result.extend(struct.pack('<B', TYPE_INT))
            result.extend(struct.pack('<i', item))
        elif isinstance(item, float):
            # 浮点数：类型 | 数据
            result.extend(struct.pack('<B', TYPE_FLOAT))
            result.extend(struct.pack('<d', item))
        elif isinstance(item, tuple):
            # 元组：类型 | 子元素数量 | 子元素数据
            result.extend(struct.pack('<B', TYPE_TUPLE))
            sub_data = serialize_data(item)  # 递归序列化
          
            result.extend(sub_data)  
        elif isinstance(item, list):
            result.extend(struct.pack('<B', TYPE_LIST))
            sub_data = serialize_data(item)  # 和 tuple 一样递归处理
            result.extend(sub_data)

        elif isinstance(item, dict):
            result.extend(struct.pack('<B', TYPE_DICT))
            result.extend(struct.pack('<H', len(item)))
            for key, value in item.items():
                result.extend(serialize_data([key]))   # 不再限制为 str
                result.extend(serialize_data([value]))
        elif isinstance(item, datetime.datetime):
            result.extend(struct.pack('<B', TYPE_DATETIME))
            timestamp = item.timestamp()
            result.extend(struct.pack('<d', timestamp))
        elif isinstance(item, Decimal):
            result.extend(struct.pack('<B', TYPE_DECIMAL))
            encoded = str(item).encode('utf-8')
            result.extend(struct.pack('<H', len(encoded)))
            result.extend(encoded)
        elif isinstance(item, uuid.UUID):
            result.extend(struct.pack('<B', TYPE_UUID))
            encoded = str(item).encode('utf-8')
            result.extend(struct.pack('<H', len(encoded)))
            result.extend(encoded)
        elif isinstance(item, (bytes, bytearray)):
            result.extend(struct.pack('<B', TYPE_BYTES))
            result.extend(struct.pack('<H', len(item)))
            result.extend(item)
        elif item is None:
            result.extend(struct.pack('<B', TYPE_NONE))

        else:
            raise ValueError(f"serialize_data:Unsupported data type: {type(item)}")
    ret=bytes(result)
    logging.debug(f"serialize_data:{data} result: {ret}")
    return ret

def deserialize_data(data_bytes, depth=0, max_depth=10):
    if depth > max_depth:
        raise ValueError(f"deserialize_data:Depth {depth}: Maximum tuple recursion depth exceeded")

    offset = 0
    result = []
    
    # 读取元素数量
    if len(data_bytes) < 2:
        raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: missing element count")
    count = struct.unpack('<H', data_bytes[offset:offset+2])[0]
    logging.debug(f"deserialize_data: Depth {depth}: Element count: {count}")
    offset += 2
    
    # 逐个解析元素
    for i in range(count):
        if offset >= len(data_bytes):
            raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: list data incomplete")
        type_id = data_bytes[offset]
        logging.debug(f"deserialize_data:Depth {depth}: Element {i}: type_id=0x{type_id:02x}, offset={offset}")
        offset += 1
        
        if type_id == TYPE_STRING:  # 字符串
            if offset + 2 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: missing string length")
            str_len = struct.unpack('<H', data_bytes[offset:offset+2])[0]
            offset += 2
            if offset + str_len > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: string data overflow")
            string = data_bytes[offset:offset+str_len].decode('utf-8')
            result.append(string)
            offset += str_len
        elif type_id == TYPE_BOOL:  # 布尔值
            if offset + 1 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: boolean data overflow")
            bool_val = bool(data_bytes[offset])
            result.append(bool_val)
            offset += 1
        elif type_id == TYPE_INT:  # 整数
            if offset + 4 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: integer data overflow")
            integer = struct.unpack('<i', data_bytes[offset:offset+4])[0]
            print(f"deserialize_data:Depth {depth}: Parsed integer: {integer}")
            result.append(integer)
            offset += 4
        
        elif type_id == TYPE_FLOAT:  # 浮点数
            if offset + 8 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: float data overflow")
            float_val = struct.unpack('<d', data_bytes[offset:offset+8])[0]
            result.append(float_val)
            offset += 8
        
        elif type_id == TYPE_TUPLE:  # 元组
         
            sub_result, used_offset = deserialize_data(data_bytes[offset:], depth + 1, max_depth)
            result.append(tuple(sub_result))  # 用完整返回值构建元组
            offset += used_offset
        
        elif type_id == TYPE_LIST:
            sub_result, used_offset = deserialize_data(data_bytes[offset:], depth + 1, max_depth)
            result.append(sub_result)  # 保持为 list
            offset += used_offset

        elif type_id == TYPE_DICT:
            if offset + 2 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: missing dict length")
            dict_len = struct.unpack('<H', data_bytes[offset:offset+2])[0]
            offset += 2
            dictionary = {}
            for _ in range(dict_len):
                # 反序列化 key
                key_result, key_used = deserialize_data(data_bytes[offset:], depth + 1, max_depth)
                key = key_result[0]  # 可以是 str, int, tuple, ...
                offset += key_used

                # 反序列化 value
                val_result, val_used = deserialize_data(data_bytes[offset:], depth + 1, max_depth)
                value = val_result[0]
                offset += val_used

                dictionary[key] = value
            result.append(dictionary)


        elif type_id == TYPE_DATETIME:
            if offset + 8 > len(data_bytes):
                raise ValueError(f"deserialize_data:Depth {depth}: Invalid data format: datetime overflow")
            timestamp = struct.unpack('<d', data_bytes[offset:offset+8])[0]
            dt_val = datetime.datetime.fromtimestamp(timestamp)
            result.append(dt_val)
            offset += 8
        elif type_id == TYPE_DECIMAL:
            str_len = struct.unpack('<H', data_bytes[offset:offset+2])[0]
            offset += 2
            decimal_str = data_bytes[offset:offset+str_len].decode('utf-8')
            result.append(Decimal(decimal_str))
            offset += str_len
        elif type_id == TYPE_UUID:
            str_len = struct.unpack('<H', data_bytes[offset:offset+2])[0]
            offset += 2
            uuid_str = data_bytes[offset:offset+str_len].decode('utf-8')
            result.append(uuid.UUID(uuid_str))
            offset += str_len  
        elif type_id == TYPE_BYTES:
            b_len = struct.unpack('<H', data_bytes[offset:offset+2])[0]
            offset += 2
            result.append(data_bytes[offset:offset+b_len])
            offset += b_len
        elif type_id == TYPE_NONE:
            result.append(None)
        else:
            raise ValueError(f"deserialize_data:Depth {depth}: Unknown type ID: 0x{type_id:02x}")
    logging.debug(f"deserialize_data: deserialize data of {data_bytes}  at depth {depth}  result is {result} with offset {offset}")
    return result, offset

def encrypt_items(items, key_file, output_file):
    fernet = get_fernet_key(key_file)
    
    with open(output_file, 'wb') as f:
        for record in items:
            data = record['data']
            signature = record['signature']
            
            # 构建头部
            logging.debug(f"encrypt data: create header ")
            header = bytearray(16)
            header[0:2] = bytes([254, 254])  # 魔数
            header[6:8] = struct.pack('<H', signature)  # signature
            header[8:14] = bytes([0] * 6)    # 未使用
            
            # 序列化数据
            logging.debug(f"encrypt data:  serialize data ")
            encoded_data = serialize_data(data)
            
            # PKCS#7 填充
            logging.debug(f"encrypt data: data PKCS#7 padding ")
            padding = 16 - (len(encoded_data) % 16)
            if padding == 0:
                padding = 16
            encoded_data += bytes([padding]) * padding
            
            # 计算 CRC32
            logging.debug(f"encrypt data: data CRC ")
            crc = zlib.crc32(encoded_data)
            header[2:6] = struct.pack('<I', crc)
            
            # 加密
            logging.debug(f"encrypt data: data  encrypted ")
            encrypted_data = fernet.encrypt(encoded_data)
            header[14:16] = struct.pack('<H', len(encrypted_data))
            
            # 写入文件
            logging.debug(f"eencrypt data: write file with header {header} and encrypted data {encrypted_data} ")
            f.write(header)
            f.write(encrypted_data)
def decrypt_items(key_file, input_file):
    fernet = get_fernet_key(key_file)
    records = []
    
    with open(input_file, 'rb') as f:
        file_data = f.read()
        if len(file_data) < 16:
            raise ValueError("decrypt_data:File too small to contain valid data")
        offset = 0
        while offset + 16 <= len(file_data):
            # 读取头部（16 字节）
            logging.debug(f"decrypt_data: reade header ")
            header = file_data[offset:offset+16]
            offset += 16
            if len(header) != 16:
                break  # 文件结束或头部不完整
            logging.debug(f"decrypt_data: check header")
            if header[0] != 254 or header[1] != 254:
                raise ValueError("decrypt_data: Record corrupt")
            logging.debug(f"decrypt_data: get CRC,signature,data_length from the hedader ")
            crc_stored = struct.unpack('<I', header[2:6])[0]
            signature = struct.unpack('<H', header[6:8])[0]
            data_length = struct.unpack('<H', header[14:16])[0]
            
            # 读取数据（加密的）
            logging.debug(f"decrypt_data: compare header data length with file data  length")
            if offset + data_length > len(file_data):
                raise ValueError("decrypt_data:FData length overflow")
            encrypted_data = file_data[offset:offset+data_length]
            offset += data_length
            if len(encrypted_data) != data_length:
                raise ValueError("decrypt_data:F Data length mismatch")
            
            # AES 解密
            logging.debug(f"decrypt_data: fernet AES decrypt ")
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception as e:
                raise ValueError(f"decrypt_data:F Decryption failed: {str(e)}")
            
            # 验证 CRC32（对填充后的字节流）
            logging.debug(f"decrypt_data: verify data CRC ")
            crc_computed = zlib.crc32(decrypted_data)
            if crc_computed != crc_stored:
                raise ValueError("decrypt_data:F CRC32 validation failed")
            
            # 去除 PKCS#7 填充
            logging.debug(f"decrypt_data: remove  PKCS#7 padding")
            padding = decrypted_data[-1]  # 最后一个字节表示填充长度
            if not (1 <= padding <= 16):
                raise ValueError("decrypt_data:F Invalid padding value")
            if decrypted_data[-padding:] != bytes([padding]) * padding:
                raise ValueError("decrypt_data:F Padding bytes do not match PKCS#7 format")
            encoded_data = decrypted_data[:-padding]  # 移除填充字节
            
            # 反序列化数据
            logging.debug(f"decrypt_data: deserialize data")
            try:
                data, _ = deserialize_data(encoded_data)
            except Exception as e:
                logging.error(f"decrypt_data:F Deserialization failed for record with signature {signature}: {str(e)}")
                raise
            
            # 存储解密的记录
            logging.debug(f"decrypt_data: deserialize data")
            records.append({
                'signature': signature,
                'data': data
            })
    logging.debug(f"decrypt_data:final record for {file_data} is {records}")
    return records

# 测试代码
if __name__ == "__main__":
    # 示例数据
    logging.basicConfig(
  
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s')
    items = [
    {
        'signature': 1234,
        'data': [
            'V2-BIC-DO/FS_CTRL/CAL2/COMP2/OUT_SCALE.EU200',  # 字符串
            123,  # 整数
            456.0,  # 浮点数
            'abc',  # 字符串
            (123, 124),  # 元组
            True,  # 布尔值
            None,  # None
            Decimal('1234.5678'),  # Decimal 类型
            uuid.uuid4(),  # UUID
            b'\x01\x02\x03\x04',  # bytes
            datetime.datetime(2025, 4, 30, 20, 0),  # datetime
            (11.2,129,datetime.datetime.now(datetime.UTC))
        ]
    },
    {
        'signature': 5678,
        'data': [
            'field3',  # 字符串
            'field4',  # 字符串
            False,  # 布尔值
            Decimal('9876.5432'),  # Decimal 类型
            uuid.uuid4(),  # UUID
            b'\x05\x06\x07\x08',  # bytes
            datetime.datetime.now(),  # datetime
            None,  # None
        ]
    }
]

    # 加密到文件
    base_dir = os.path.dirname(os.path.abspath(__file__))
    key_file = os.path.join(base_dir, "encryption_key.key")
    data_file = os.path.join(base_dir, "encrypted_data.bin")      
    encrypt_items(items, key_file, data_file)

    # 从文件解密
    decrypted_records = decrypt_items(key_file, data_file)
    
    # 打印结果
    print()
    for record in decrypted_records:
        print(record)