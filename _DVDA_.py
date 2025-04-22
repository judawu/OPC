import win32com.client
import pythoncom
import pywintypes  # 添加此导入以解决 'pywintypes' 未定义的问题
import ctypes  # 添加 ctypes 用于强制类型转换
import json
import pickle
import logging
import os
import time

from datetime import datetime
from typing import Dict, Optional, Tuple,List,Callable
import msvcrt  # 用于非阻塞输入（Windows）
class _OPCDA_:
    def __init__(self, node_name:str=None, server_name: str = "OPC.DeltaV.1", client_name: str = "DefaultOPCDAClient"):
        # 获取当前脚本的目录 ,OPC.DeltaV.1
       
        
        self.node_name = node_name
        self.server_name = server_name
        self.opc = None
        self.browser = None
        self.groups = None
        self.last_callback_values = {}
        self.client_name = client_name # 默认客户端名称
        self.connected = False
        self.callback_handler = None  # Explicitly track callback handler

    def connect(self) -> bool:
        """连接到OPC服务器，带超时保护"""
        target = self.node_name if self.node_name else "local"
     
      
        try:
            pythoncom.CoInitialize()  # Initialize COM in this thread
            logging.debug(f"_OPCDA_.connect: Trying to access OPC server {self.server_name} from computer name/ip : {target} ")
            self.opc = win32com.client.Dispatch("OPC.Automation")
            self.opc.Connect(self.server_name, self.node_name)  # Connect with node_name (None for local)               
           
            try:
                self.browser = self.opc.CreateBrowser()
                self.browser.MoveToRoot()
            except:
                logging.error(f"_OPCDA_:connect  Failed to create browser for OPC server {self.server_name} on {target}")
                
                
            self.groups = self.opc.OPCGroups
            
            self.connected = True
            logging.debug(f"_OPCDA_: Successfully connected to OPC server {self.server_name} on {target}")
            return True
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to connect to OPC server {self.server_name} on {target}: {str(e)}")
            return False
        finally:
            if not self.connected:
                pythoncom.CoUninitialize()
                return False

     
         

    def disconnect(self):
        logging.debug(F"Attempting to disconnect from OPC server {self.server_name}")
        if self.opc:
            try:
                if self.groups and self.callback_handler:
                    self.stop_subscribe("SubscribeGroup")  # Ensure subscriptions are stopped
                self.opc.Disconnect()
                self.connected = False
                logging.info(f"_OPCDA_:Successfully disconnected to opc da server {self.server_name}")
            except Exception as e:
                logging.warning(f"_OPCDA_:Disconnect to opc da server {self.server_name} failed: {str(e)}")
            finally:
                # Explicitly release COM objects
                if self.callback_handler:
                    del self.callback_handler
                    self.callback_handler = None
                if self.groups:
                    self.groups = None
                if self.browser:
                    self.browser = None
                if self.opc:
                    import gc
                    self.opc = None
                    gc.collect()  # Force garbage collection
                pythoncom.CoUninitialize()  # Add this
                self.connected = False
    def explore_server_methods(self) -> List[str]:
        """
        探索当前连接的 OPC 服务器对象的可用方法和属性
        Returns:
            List[str]: 可用的属性和方法名称列表
        """
        if not self.opc or not self.groups:
            logging.error("_OPCDA_:Not connected to any OPC server")
            return []

        methods_and_attrs = dir(self.opc)
        logging.debug(f"_OPCDA_:Available methods and attributes for {self.server_name}: {methods_and_attrs}")
        return methods_and_attrs

    def explore_server_details(self):
        if not self.opc or not self.groups:
            logging.error("_OPCDA_: Not connected to any OPC server")
            return

        try:
            server_details = {
                "ServerName": self.opc.ServerName,  # 1=Running, 2=Failed, etc.
                "ServerState": self.opc.ServerState,
                "MajorVersion": self.opc.MajorVersion,
                "MinorVersion": self.opc.MinorVersion,
                "BuildNumber": self.opc.BuildNumber,
                "VendorInfo": self.opc.VendorInfo
            }
            logging.debug(f"_OPCDA_ explore_server_details: opc da Server {self.server_name} status: {server_details}")
            
          
            return server_details
        except Exception as e:
            logging.error(f"_OPCDA_explore_server_details: Error accessing opc da server  {self.server_name} details: {str(e)}")
            return {}

    def query_local_servers(self) -> List[str]:
        """
        查询本机上可用的 OPC DA 服务器，使用 GetOPCServers 方法
        Returns:
            List[str]: 本机 OPC 服务器的 ProgID 列表
        """
        if not self.opc:
            # 如果未连接，先尝试连接默认服务器
            if not self.connect():
                logging.error(f"_OPCDA_: Failed to connect to OPC server {self.server_name} for querying")
                return []

        try:
            # 调用 GetOPCServers 查询本地服务器
            servers = self.opc.GetOPCServers()
            server_list = list(servers) if servers else []
            logging.debug(f"_OPCDA_: Found {len(server_list)} OPC DA servers: {server_list}")
            return server_list
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to query local OPC servers: {str(e)}")
            return []

    def get_server_status(self) -> Dict[str, any]:
        """获取服务器状态和时间信息"""
        if not self.opc:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC server {self.server_name}")
        try:
            status = {
                "ServerState": self.opc.ServerState,  # 1=Running, 2=Failed, etc.
                "CurrentTime": self.opc.CurrentTime,
                "StartTime": self.opc.StartTime,
                "LastUpdateTime": self.opc.LastUpdateTime,
                "ServerNode": self.opc.ServerNode
            }
            logging.debug(f"_OPCDA_: Server {self.server_name} status: {status}")
            return status
        except Exception as e:
            logging.error(f"_OPCDA_:  Failed to get server {self.server_name} status: {str(e)}")
            return {}

    def format_server_status(self,status: Dict[str, any]) -> str:
        """将服务器状态格式化为 JSON 字符串"""
        # 转换 pywintypes.Time 为标准字符串
        formatted_status = {
            key: value.strftime("%Y-%m-%d %H:%M:%S") if isinstance(value, pywintypes.TimeType) else value
            for key, value in status.items()
        }
        return json.dumps(formatted_status, indent=4, ensure_ascii=False)


    def set_client_name(self, name: str):
        """设置客户端名称"""
        if not self.opc:
            raise ConnectionError(F" _OPCDA_:  Not connected to OPC DA server {self.server_name}")
        try:
            self.opc.ClientName = name
            self.client_name = name  # 记录本地值
            logging.debug(f"_OPCDA_:  Client name set to: {name}")
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to set client name: {str(e)}")

    def get_client_name(self) -> str:
        """获取当前设置的客户端名称"""
        return self.client_name

    def get_bandwidth(self) -> int:
        """获取服务器带宽使用情况"""
        if not self.opc:
            raise ConnectionError(F"_OPCDA_:  Not connected to OPC DA server {self.server_name}")
        try:
            bandwidth = self.opc.Bandwidth
            logging.info(f"_OPCDA_: OPC DA SEVER {self.server_name} Current bandwidth: {bandwidth}")
            return bandwidth
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to get OPC DA SEVER {self.server_name}  bandwidth: {str(e)}")
            return -1
    def get_error_description(self, error_code: int) -> str:
        if not self.opc:
            raise ConnectionError(F"_OPCDA_: Not connected to OPC server {self.server_name} ")
        if isinstance(error_code, str) and error_code.startswith("0x"):
            error_code = int(error_code, 16)
        if error_code > 0x7FFFFFFF:
            error_code = error_code - 0x100000000
        try:
            if not (-2147483648 <= error_code <= 2147483647):
                raise ValueError(f"_OPCDA_:Error code {error_code} out of valid range")
            error_code = ctypes.c_long(error_code).value
            desc = self.opc.GetErrorString(error_code)
            logging.debug(f"_OPCDA_: Error {error_code} (0x{error_code & 0xFFFFFFFF:08X}): {desc}")
            return desc
        except Exception as e:
            logging.error(f"_OPCDA_:Failed to get error string for {error_code} (0x{error_code & 0xFFFFFFFF:08X}): {str(e)}")
            return f"_OPCDA_: Unknown error: {error_code} (0x{error_code & 0xFFFFFFFF:08X})"


    
        
    def browse_level(self, browser, level, max_level, path="", structure=None):
        """Browse OPC server hierarchy at a specific level."""
        if structure is None:
            structure = {}  # 初始化为空字典

        if level > max_level:
            return structure  # 返回当前结构

        try:
            browser.ShowBranches()
            branch_count = browser.Count
            branches = []
            for i in range(1, branch_count + 1):
                try:
                    item_name = browser.Item(i)
                  
                    if item_name:
                        branches.append(item_name)
                except pythoncom.com_error as e:
                    logging.error(f"_OPCDA_: Failed to access OPC DA SEVER {self.server_name}  branch {i}: {str(e)}")
                    continue

            browser.ShowLeafs()
            leaf_count = browser.Count
            leaves = []
            for i in range(1, leaf_count + 1):
                try:
                    item_name = browser.Item(i)
                   # item_id = browser.GetItemID(i)
                    if item_name:
                        leaves.append(item_name)
                except pythoncom.com_error as e:
                    logging.error(f"_OPCDA_:Failed to access  OPC DA SEVER {self.server_name} leaf {i}: {str(e)}")
                    continue

            for item_name in branches:
                full_path = f"{path}.{item_name}" if path else item_name
                if item_name not in structure:
                    structure[item_name] = {}
                try:
                    browser.MoveDown(item_name)
                    structure[item_name] = self.browse_level(browser, level + 1, max_level, full_path, structure[item_name])
                    browser.MoveUp()
                except pythoncom.com_error as e:
                    logging.error(f"_OPCDA_: MoveDown opc da server {self.server_name} failed for {item_name}: {str(e)}")

            for item_name in leaves:
                full_path = f"{path}.{item_name}" if path else item_name
                structure[item_name] = full_path

        except pythoncom.com_error as e:
            logging.error(f"_OPCDA_: Browsing opc da server {self.server_name} failed: {str(e)}")

        return structure  # 返回当前结构
    
    def flatten_structure(self, structure: Dict, parent_path: str = "") -> List[str]:
        """Convert nested structure dictionary to a flat list of paths."""
        items = []
        for key, value in structure.items():
            full_path = f"{parent_path}.{key}" if parent_path else key
            items.append(full_path)
            if isinstance(value, dict) and value:  # 如果有子节点，递归展开
                items.extend(self.flatten_structure(value, full_path))
        return items

    
    def move_to_path(self, browser, path=None):
        """Move down to the specified path."""
        browser.MoveToRoot()
        if path is not None:
            
            parts = path.split('.')
        
            for part in parts:
                try:
                    browser.MoveDown(part)
                except pythoncom.com_error as e:
                    logging.error(f"_OPCDA_: Failed to move down opc da server {self.server_name}  to {part}: {str(e)}")
                    return False
        return True
    
  

    def browse_items(self,browser, parent_path: str = "", max_level: int = 5) -> List[str]:
        """Browse OPC server items and return a flat list of paths."""
        if not self.opc:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC da server {self.server_name}")
        try:
            self.move_to_path(browser, parent_path)
            logging.debug(f"_OPCDA_: Browser OPC da server {self.server_name} attributes: {dir(browser)}")
            
            structure = self.browse_level(browser, 1, max_level, parent_path)
            
            items = self.flatten_structure(structure,parent_path)
            if not items:
                logging.warning(f"_OPCDA_: No items found under {parent_path} up to level {max_level} for OPC da server {self.server_name} ")
            else:
                logging.info(f"_OPCDA_: OPC da server {self.server_name} Items under {parent_path} up to level {max_level}: {items}")
            return items
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to browse OPC da server {self.server_name} items: {str(e)}")
            return []

    def convert_paths(self,paths: list[str]) -> list[str]:
        """
        Convert full OPC DA paths to short paths by removing the first two segments,
        keeping the last dot and suffix, and replacing intermediate dots with slashes.
        
        Args:
            paths (list[str]): List of full paths, e.g., ['MODULES.AREA_V1.V1-IO.AI1_SCI1.EU0']
        
        Returns:
            list[str]: List of converted short paths, e.g., ['V1-IO/AI1_SCI1.EU0']
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


  


    

    


    def merge_structures(self, main, new, path_parts, replace_empty=False):
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
                    result = self.merge_structures(main[key], value, [], replace_empty)
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

        if self.merge_structures(main[current_part], new, remaining_parts, replace_empty) is None:
            del main[current_part]

        return main
   
    def update_structure(self, new_structure, target_path="", main_structure_file=None, replace_empty=False):
        if main_structure_file is None:
             current_dir = os.path.dirname(os.path.abspath(__file__))
             main_structure_file =  os.path.join(current_dir, 'main_structure.bin')
         
        try:
            if os.path.exists(main_structure_file):
                with open(main_structure_file, 'rb') as f:
                    main_structure = pickle.load(f)
            else:
                main_structure = {}
            
            path_parts = target_path.split('.') if target_path else []
            self.merge_structures(main_structure, new_structure, path_parts, replace_empty)

            with open(main_structure_file, 'wb') as f:
                pickle.dump(main_structure, f)
            #print(f"Updated structure: {main_structure}")

        except Exception as e:
            logging.error(f"_OPCDA_: Failed to update main structure: {str(e)}")
            raise

    def load_structure(main_structure_file=None) -> Dict:
        """从bin文件加载结构"""
        try:
            if main_structure_file is None:
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    main_structure_file =  os.path.join(current_dir, 'main_structure.bin')
            with open(main_structure_file, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logging.error(f"_OPCDA_: Failed to load  structure: {str(e)}")
            return {}

    def bin_to_json(self, output_json_path: str = None) -> Dict:
        """将bin文件转换为json格式"""
        structure = self.load_structure()
        if output_json_path:
            try:
                with open(output_json_path, 'w') as f:
                    json.dump(structure, f, indent=4)
            except Exception as e:
                logging.error(f"_OPCDA_: Failed to convert to JSON: {str(e)}")
        return structure

    def read(self, item_paths: List[str], group_name: str = "TestGroup", update_rate: int = 1000) -> List[Tuple[any, int, str]]:
        """
        从OPC服务器读取多个指定项的值
        Args:
            item_paths: OPC项路径列表
            group_name: OPC组名称，默认"TestGroup"
            update_rate: 更新速率（毫秒），默认1000
        Returns:
            List of Tuple(value, quality, timestamp): 每个项的值、质量、时间戳
        """
        if not self.opc or not self.groups:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC da server {self.server_name} ")

        try:
            # 创建并配置组
            group = self.groups.Add(group_name)
            group.IsActive = True
            group.IsSubscribed = False
            group.UpdateRate = update_rate

            # 添加多个项
            opc_items = []
            for i, item_path in enumerate(item_paths, 1):  # 从1开始分配client handle
                try:
                    if self.server_name=="DeltaV.DVSYSsvr.1" and ('_' not in item_path.split('.')[-1]):
                        chnanged_item_path=item_path.replace('.', '.F_')
                        opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                        if opc_item is None or (opc_item is not None and opc_item.ServerHandle == 0):
                            chnanged_item_path=item_path.replace('.', '.A_')
                            opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                    else:
                        opc_item = group.OPCItems.AddItem(item_path, i)
                    opc_items.append((item_path, opc_item))
                except Exception as e:
                    logging.error(f"_OPCDA_: Failed to add item {item_path}: {str(e)}")
                    opc_items.append((item_path, None))
               

            # 等待服务器稳定
            time.sleep(1)

            # 读取所有项的值
            results = []
            for item_path, opc_item in opc_items:
                try:
                    if opc_item is not None:
                        value, quality, timestamp = opc_item.Read(2)  # 2 = OPC_DS_DEVICE
                        results.append((value, quality, timestamp))
                        logging.debug(f"_OPCDA_:  read {item_path} from OPC DA server {self.server_name},value is {value}, quality is {quality}, timestamp is {timestamp}")
                    else:
                        logging.error(f"_OPCDA_: Failed to read {item_path} from OPC DA server {self.server_name}")
                        results.append((None, -1, None))  # 用无效值表示读取失败
                except Exception as e:
                    logging.error(f"_OPCDA_: Failed to read {item_path} from OPC DA server {self.server_name} : {str(e)}")
                    results.append((None, -1, None))  # 用无效值表示读取失败

            # 清理组
            self.groups.Remove(group_name)
            
            return results
        except Exception as e:
            logging.error(f"_OPCDA_: Error reading items from OPC da server {self.server_name}: {str(e)}")
            raise
        
    def write(self, item_paths: List[str], values: List, group_name: str = "TestGroup", update_rate: int = 1000) -> List[bool]:
        """
        向OPC服务器批量写入多个指定项的值
        """
        if not self.opc or not self.groups:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC server  {self.server_name}")

        if len(item_paths) != len(values):
            raise ValueError("_OPCDA_:Length of item_paths and values must match")

        try:
            group = self.groups.Add(group_name)
            group.IsActive = True
            group.IsSubscribed = False
            group.UpdateRate = update_rate

            opc_items = []
            for i, item_path in enumerate(item_paths, 1):
                try:
                    if self.server_name=="DeltaV.DVSYSsvr.1" and item_path.split('.')[-1] =='CV':
                        chnanged_item_path=item_path.replace('.', '.F_')
                        opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                        if opc_item is None or (opc_item is not None and opc_item.ServerHandle == 0):
                            chnanged_item_path=item_path.replace('.', '.A_')
                            opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                    else:
                        opc_item = group.OPCItems.AddItem(item_path, i)
                  
                    opc_items.append((item_path, opc_item))
                except Exception as e:
                    logging.error(f"_OPCDA_: Failed to add item {item_path}: {str(e)}")
                    opc_items.append((item_path, None))

            results = []
            for (item_path, opc_item), value in zip(opc_items, values):
                if opc_item is None:
                    results.append(False)
                    continue
                try:
                    opc_item.Write(value)
                    logging.debug(f"_OPCDA_: Successfully wrote {value} to {item_path} to OPC da server  {self.server_name}")
                    results.append(True)
                except Exception as e:
                    logging.error(f"_OPCDA_:Failed to write {value} to {item_path} to OPC da server  {self.server_name}: {str(e)}")
                    results.append(False)

            self.groups.Remove(group_name)
            
            return results
            
        except Exception as e:
            logging.error(f"_OPCDA_: Error writing items: {str(e)}")
            raise
  
    def poll(self, item_paths: List[str], interval: float = 1.0, max_count: Optional[int] = None, max_time: Optional[float] = None, callback: Optional[Callable[[List[str], List[Tuple[any, int, str]]], None]] = None) -> None:
        """
        定期轮询指定 OPC 项的值，直到达到最大计数或最大时间
        Args:
            item_paths: 要轮询的 OPC 项路径列表
            interval: 轮询间隔（秒），默认 1.0
            max_count: 最大轮询次数，默认 None（无限制）
            max_time: 最大运行时间（秒），默认 None（无限制）
            callback: 可选回调函数，接收路径列表和读取结果
        """
        if not self.opc or not self.groups:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC da server {self.server_name}")

        logging.debug(f"Starting poll for {item_paths} every {interval} seconds")
        start_time = time.time()  # 记录开始时间
        count = 0  # 轮询计数器

        while True:
            # 检查停止条件
            if max_count is not None and count >= max_count:
                logging.debug(f"_OPCDA_: Reached max count ({max_count}), stopping poll")
                break
            if max_time is not None and (time.time() - start_time) >= max_time:
                logging.debug(f"_OPCDA_: Reached max time ({max_time} seconds), stopping poll")
                break

            try:
                results = self.read(item_paths)
                if callback:
                    callback(item_paths, results)
                else:
              
                    self.universal_callback(item_paths, results)  # 使用通用回调函数
                count += 1
                time.sleep(interval)
            except Exception as e:
                logging.error(f"_OPCDA_:Polling error: {str(e)}")
                break

        

    def subscribe(self, item_paths: List[str], group_name: str = "SubscribeGroup", update_rate: int = 1000, callback: Optional[Callable[[List[str], List[Tuple[any, int, str]]], None]] = None) -> None:
        if not self.opc or not self.groups:
            raise ConnectionError(f"_OPCDA_: Not connected to OPC da server {self.server_name}")

        try:


            group = self.groups.Add(group_name)
            group.IsActive = True
            group.IsSubscribed = True
            group.UpdateRate = update_rate
            initial_values = self.read(item_paths)
            for path, (value, _, _) in zip(item_paths, initial_values):
                if value is not None:
                    self.last_callback_values[path] = value
            opc_items = []
            for i, item_path in enumerate(item_paths, 1):  # 从1开始分配client handle
                try:
                    if self.server_name=="DeltaV.DVSYSsvr.1" and ('_' not in item_path.split('.')[-1]):
                        chnanged_item_path=item_path.replace('.', '.F_')
                        opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                        if opc_item is None or (opc_item is not None and opc_item.ServerHandle == 0):
                            chnanged_item_path=item_path.replace('.', '.A_')
                            opc_item = group.OPCItems.AddItem(chnanged_item_path, i)
                    else:
                        opc_item = group.OPCItems.AddItem(item_path, i)
                     
                    opc_items.append((item_path, i)) 
                except Exception as e:
                    logging.error(f"_OPCDA_: Failed to add item {item_path}: {str(e)}")
                    opc_items.append((item_path, 0))
  

           
            for path, (value, _, _) in zip(item_paths, initial_values):
                if value is not None:
                    self.last_callback_values[path] = value
              

            active_callback = callback if callback else self.universal_callback

            self.callback_handler = win32com.client.WithEvents(group, OPCDADataCallback)
            self.callback_handler.callback = active_callback
            self.callback_handler.opc_items = opc_items

            logging.debug(f"_OPCDA_:Subscribed to {item_paths} with update rate {update_rate}ms from OPC da server {self.server_name}")
          
        except Exception as e:
            logging.error(f"_OPCDA_: Subscription error from OPC da server {self.server_name}: {str(e)}")
            raise

    def stop_subscribe(self, group_name: str = "SubscribeGroup"):
        if self.groups:
            try:
                for i in range(1, self.groups.Count + 1):
                    if self.groups.Item(i).Name == group_name:
                        self.groups.Remove(group_name)
                        if self.callback_handler:
                            del self.callback_handler  # Release event handler
                            self.callback_handler = None
                        logging.debug(f"_OPCDA_: Subscription {group_name} stopped successfully from OPC da server {self.server_name}")
                      
                        return
                logging.warning(f"_OPCDA_: Group {group_name} not found in OPCGroups from OPC da server {self.server_name}")
               
            except Exception as e:
                logging.error(f"_OPCDA_: Failed to stop subscription {group_name}  from OPC da server {self.server_name} : {str(e)}")
              
        else:
            logging.warning("_OPCDA_: No OPC groups available to stop")
         
        
    def get_last_subscribe(self) -> str:
        """获取当前设置的客户端名称"""
        return self.last_callback_values
  
        


    def universal_callback(self, paths, results):
       
        for path, (value, quality, timestamp) in zip(paths, results):                  
            last_value = self.last_callback_values.get(path)
            if last_value != value and value is not None:
                print(f"_OPCDA_: Poll/Subscribe {path}: Value={value}, Quality={quality}, Timestamp={timestamp}")  
                self.last_callback_values[path] = value
               
               
       

 # 定义回调类
class OPCDADataCallback:
    def __init__(self, callback=None):
        self.callback = callback
        self.opc_items = []  # Store (path, client_handle) list
        self.data: Dict[str, Tuple[any, int, str]] = {}

    def OnDataChange(self, TransactionID, NumItems, ClientHandles, ItemValues, Qualities, TimeStamps):
        """Handle OPC DA data change events from COM."""
        results_dict = {ClientHandles[i]: (ItemValues[i], Qualities[i], TimeStamps[i]) for i in range(NumItems)}
        paths = [item[0] for item in self.opc_items]
        results = [results_dict.get(item[1], (None, 0, None)) for item in self.opc_items]
        
        # Update stored data
        for path, result in zip(paths, results):
            self.data[path] = result
        
        # Call the custom callback with processed data
        if self.callback:
            self.callback(paths, results)

    def get_data(self, item_path: str) -> Optional[Tuple[any, int, str]]:
        """Get the latest data for an item."""
        return self.data.get(item_path)
def main():
    opc_da = _OPCDA_(node_name='10.4.0.6',server_name='DeltaV.DVSYSsvr.1')  #DeltaV.DVSYSsvr.1'  OPC.DELTAV.1
    #opc_da = _OPCDA_() 
    try:
       
        
        if opc_da.connect():
            print(f" Connected to {opc_da.server_name}")
            servers = opc_da.query_local_servers()
            print("Available OPC Servers:", servers)
            print()
            methods = opc_da.explore_server_methods()
            print("Available methods and attributes:", methods)
            print()
            server_details=opc_da.explore_server_details()
            print(" explore_server_details:\n",server_details)
            
            print()

           # 测试服务器状态
            status = opc_da.get_server_status()
            print("Server Status::\n")
            print(opc_da.format_server_status(status))
            print()
            # 设置客户端名称
            opc_da.set_client_name("MyPythonClient")
            print("Client name set to:", opc_da.get_client_name())
           # 再次查看
            print("Current client name:", opc_da.get_client_name())

          
           
            print()


            if opc_da.server_name == "OPC.DeltaV.1":
                print(f"Build Main structure ")
                main_structure = {}
                opc_da.move_to_path(opc_da.browser)
                main_structure = opc_da.browse_level(opc_da.browser, 1, 2,"", main_structure)      
                opc_da.update_structure(main_structure)
                print(f" Main structure updated successfully")
                print()
                print("AccessRights:",opc_da.browser.AccessRights)
                print("CLSID:",opc_da.browser.CLSID)
                start_time = time.time()
                print()
                target_path = "MODULES.AREA_V4.V4-EM.V4-AI-2.FS_CTRL1"
                print(f"Updating target path {target_path} structure,it may take a while...")
                if opc_da.move_to_path(opc_da.browser, target_path):
                    max_level = 1
                    structure = {}
                    structure = opc_da.browse_level(opc_da.browser, 1, max_level, target_path, structure)
                    print(structure)
                    opc_da.update_structure(structure, target_path)
                else:
                    logging.error(f"Failed to move to {target_path}")
                print()
                target_path = "DIAGNOSTICS.Physical Network.Control Network.PROPLUS.Campaign Manager"
                print(f"Updating target path {target_path} structure,it may take a while...")
                if opc_da.move_to_path(opc_da.browser, target_path):
                
                    max_level = 6
                    structure = {}
                    structure = opc_da.browse_level(opc_da.browser, 1, max_level, target_path, structure)
                
                    opc_da.update_structure(structure, target_path)
                else:
                    print("Fail move to path")
                    logging.error(f"Failed to move to {target_path}")
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(f"Target path {target_path} update completed in {elapsed_time:.2f} seconds")
                print()
                # 测试bin转json
                current_dir = os.path.dirname(os.path.abspath(__file__))
                json_output = os.path.join(current_dir, 'main_structure.json')
                structure= opc_da.bin_to_json(json_output)
                print(f"JSON structure saved to {json_output}")
          
                print()
                #print(json.dumps(structure, indent=4))


                # 测试项属性
            
                items = opc_da.browse_items(opc_da.browser,"MODULES.AREA_V1.V1-IO.AI1_SCI1", max_level=1)
                print("Available Items:", items)
                print("Read able path:", opc_da.convert_paths(items))
                print()
                # items = opc_da.browse_items(opc_da.browser,"DIAGNOSTICS.Physical Network.Control Network.PROPLUS", max_level=1)
                # print("Available Items:", items)
            
                print("CurrentPosition:",opc_da.browser.CurrentPosition)
         



            # 测试read
            print(f" testing OPC read")
            item_paths = ["V1-IO/DO1_NA_PV.CV", "V1-IO/PH1_MV_PV.CV",'PROPLUS/FREMEM.CV','V1-AI-1/FS_CTRL1/MOD_DESC.CV']
            # if opc_da.server_name == "OPC.DeltaV.1":
            #     item_paths = ["V1-IO/DO1_NA_PV.CV", "V1-IO/PH1_MV_PV.CV",'PROPLUS/FREMEM.CV']+opc_da.convert_paths(items)
            # else:
            #     item_paths = ["V1-IO/DO1_NA_PV.F_CV", "V1-IO/PH1_MV_PV.F_CV",'PROPLUS/FREMEM.F_CV']
            try:
                read_results = opc_da.read(item_paths)
                for item_path, (value, quality, timestamp) in zip(item_paths, read_results):
                    print(f"Read from {item_path}: Value={value}, Quality={quality}, Timestamp={timestamp}")
            except Exception as e:
                print(f"Failed to read items: {str(e)}")

            print()
           # 测试write
            print(f" testing OPC Write")
            write_paths = ["V1-IO/AI1_SCI1.EU100", "V1-AIC-DO/PID1/MODE.TARGET",'V1-AI-1/FS_CTRL1/MOD_DESC.CV']
            # if opc_da.server_name == "OPC.DeltaV.1":
            #    write_paths = ["V1-IO/AI1_SCI1.EU100", "V1-AIC-DO/PID1/MODE.TARGET",'V1-AI-1/FS_CTRL1/MOD_DESC.CV']
            # else:
            #      write_paths = ["V1-IO/AI1_SCI1.F_EU100", "V1-AIC-DO/PID1/MODE.F_TARGET",'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV']
            write_values = [32767, 8,'AI1 test']
            try:
                write_results = opc_da.write(write_paths, write_values)
                for path, value, success in zip(write_paths, write_values, write_results):
                    if success:
                        print(f"Successfully wrote {value} to {path}")
                    else:
                        print(f"Failed to write {value} to {path}")
            except Exception as e:
                print(f"Write error: {str(e)}")


  
            # 测试read验证写入结果
            item_paths = write_paths
            try:
                read_results = opc_da.read(item_paths)
                for item_path, (value, quality, timestamp) in zip(item_paths, read_results):
                    print(f"Read from {item_path}: Value={value}, Quality={quality}, Timestamp={timestamp}")
            except Exception as e:
                print(f"Failed to read items: {str(e)}")
           
            print()
            print(f" testing OPC poll")
          
         
           
           # 测试 max_time，运行 3 秒后停止
            print("testing poll for 3 seconds then stop")
            opc_da.poll(item_paths, interval=2.0, max_time=3.0, callback=opc_da.universal_callback)
            

            # 测试 max_count，轮询 3 次后停止
            print("testing poll for 5 times then stop")
            #opc_da.poll(item_paths, interval=2.0, max_count=5, callback=opc_da.universal_callback)
            opc_da.poll(item_paths, interval=2.0, max_time=3.0)
            
            print()
            
            # 测试错误描述
           # 测试错误码 0x80004005 (E_FAIL)
            error_desc = opc_da.get_error_description(0x80004005)
            print("Error Description (0x80004005):", error_desc)
            # 测试十进制输入
            error_desc = opc_da.get_error_description(-2147467259)
            print("Error Description (-2147467259):", error_desc)
            # 测试其他错误码
            error_desc = opc_da.get_error_description(0)  # 成功
            print("Error Description (0):", error_desc)
            print()
       
           
            
      
                                
           
           
            
            print()
           
            bandwidth = opc_da.get_bandwidth()
            print("Bandwidth:", bandwidth)
            print()
          
            print("testing subscribe meothod, try to simulate data change to obersve the callback")
           
            print()
            # 保持程序运行以接收回调
            print("Subscribed, waiting for data changes... (Press Ctrl+C to stop)")
           

            #测试 subscribe with max_count in main
           
            group_name_count = "SubscribeCountGroup"
            
            maxcount = ""  # 初始化为空字符串
            while maxcount.isdigit() == False:
              maxcount = input("Enter max count do you want the subscribe to stop: ").strip()
            print(f"\nTesting subscribe with max_count={maxcount} (controlled in main)")
            opc_da.subscribe(
                item_paths=item_paths,
                group_name=group_name_count,
                update_rate=1000,
                callback=opc_da.universal_callback
            )
            print("Subscribe count start...")
            count = 0
            try:
                while count < int(maxcount):  # 5 次回调后停止
                    #pythoncom.PumpMessages()
                    pythoncom.PumpWaitingMessages()
                    time.sleep(1)
                    # 这里假设每次循环可能触发一次回调，实际需要根据数据变化频率调整
                    # 为了简化，我们用时间模拟计数，真实场景可能需要回调计数器
                    count += 1  # 注意：这只是模拟，实际计数应在回调中实现
                print("Reached max count (5 iterations), stopping subscription...")
                opc_da.stop_subscribe(group_name_count)
            except KeyboardInterrupt:
                print("Stopping subscription via Ctrl+C...")
                opc_da.stop_subscribe(group_name_count)



            print()
             # 测试 subscribe with max_time in main
           
            group_name_time = "SubscribeTimeGroup"
            maxtime = ""  # 初始化为空字符串
            while maxtime.isdigit() == False:
              maxtime = input("Enter max seconds do you want the subscribe to stop: ").strip()
            print(f"\nTesting subscribe with max_time={maxtime} seconds (controlled in main)")
            
           
            opc_da.subscribe(
                        item_paths=item_paths,
                        group_name=group_name_time,
                        update_rate=1000,
                        callback=opc_da.universal_callback
                    )
            print("Subscribe timer start...")
            start_time = time.time()
            try:
                while True:
                    elapsed_time = time.time() - start_time
                    if elapsed_time >= float(maxtime):  # 精确检查 10 秒
                        print(f"{elapsed_time:.1f} seconds elapsed, stopping subscription...")
                        opc_da.stop_subscribe(group_name_time)
                        break
                    pythoncom.PumpWaitingMessages()
                   # pythoncom.PumpMessages()
                    time.sleep(0.1)  # 缩短 sleep 时间，提高检查频率
            except KeyboardInterrupt:
                print("Stopping subscription via Ctrl+C...")
                opc_da.stop_subscribe(group_name_time)


            print()

            # 测试 subscribe with manual stop
            # 测试 subscribe with user input to stop
            print("\nTesting subscribe with user input to stop")
            group_name_manual = "ManualStopGroup"
            opc_da.subscribe(
                item_paths=item_paths,
                group_name=group_name_manual,
                update_rate=1000,
                callback=opc_da.universal_callback
            )
            print("Type 'stop' to end subscription (runs until stopped)...")
            command_buffer = ""
            try:
                while True:
                    # 检查是否有键盘输入（非阻塞）
                    if msvcrt.kbhit():
                        char = msvcrt.getch().decode('utf-8')
                        if char == '\r':  # 回车键
                            if command_buffer.strip().lower() == "stop":
                                print("User requested stop, stopping subscription...")
                                opc_da.stop_subscribe(group_name_manual)
                                break
                            command_buffer = ""
                        else:
                            command_buffer += char
                            print(f"Enter command: {command_buffer}", end='\r')
                    pythoncom.PumpWaitingMessages()
                    time.sleep(0.1)  # 短间隔处理事件
            
            except KeyboardInterrupt:
                print("Stopping subscription via Ctrl+C...")
                opc_da.stop_subscribe(group_name_manual)
        
            print(opc_da.get_last_subscribe())


           

    except Exception as e:
        logging.error(f"{str(e)}")
    finally:
        opc_da.disconnect()

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(base_dir,'opcda.log')
    logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    main()