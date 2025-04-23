import logging
import os
import time
import datetime

import pythoncom
import json

from typing import List, Dict, Tuple, Optional
import asyncio
from asyncua import Server, ua

from asyncua.server.users import User, UserRole  # Correct import for v1.1.5
from asyncua.crypto.security_policies import (
    SecurityPolicy,
    SecurityPolicyBasic256Sha256,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyAes128Sha256RsaOaep
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from _DVUserManager_ import CustomUserManager
from _DVDA_ import _OPCDA_, OPCDADataCallback
from _DVAE_ import EventChronicleClient
from _DVHDA_ import _OPCHDA_
from _DVSecurity_ import CustomSecurity
#from asyncua.server.history_sql import HistorySQLite
from collections import deque  # Added import
from asyncua.common import ua_utils

class CustomDAManager:
        def __init__(self,wrapper,nodename="PROPLUS"):
            self.nodename=nodename
            self.group_name :str = "OPCDAGroup"     
            
            self._da_update_rate: int= 1000
            self._ua_update_rate: int= 10
            self._da_subscribe_waittime :int= 1 
            self.callback = OPCDADataCallback(self.custom_callback)
            self.write_lock = asyncio.Lock()
            self.poll_queue = Queue()
            self.write_queue = Queue()
            self._update_count:int = 0
            self._max_updates:int = 999999  
            self._max_level = 1
            self.path_lock = asyncio.Lock()
            self.path =None
            self.structure={}
            
            
            self.items=[f'{self.nodename}/FREOIDS.CV']
                               
            
            self._opcdeltav = _OPCDA_(node_name=self.nodename,server_name = "OPC.DeltaV.1")
            self._opcda = _OPCDA_(node_name=self.nodename,server_name = "DeltaV.DVSYSsvr.1")
            self._wrapper = wrapper
      
            
       
        def custom_callback(self, paths: List[str], results: List[Tuple[any, int, str]]):
            for path, (value, quality, timestamp) in zip(paths, results):
                if quality > 127:
                    self.callback.data[path] = (value, quality, timestamp)
                    print(f"CustomDAManager.custom_callback:Poll/Subscribe: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
                    #logging.debug(f"CustomDAManager.custom_callback: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
        async def append_items(self,items: List[str]):
             for item in items:
                  if item not in self.items:
                       self.items.append(item)
             logging.debug(f"CustomDAManager.init_load_item completed")
        async def remove_items(self,items: List[str]):
             for item in items:
                if item in self.items:
                    if item  in self._wrapper.node.nodes:
                        try:
                            remove_node = self._wrapper.node.nodes[item]

                            if hasattr(remove_node, 'nodeid'):
                                await self._wrapper.server.delete_nodes([remove_node], recursive=True)
                                del self._wrapper.node.nodes[item]
                                del self.callback.data[item]
                                logging.debug(f"CustomDAManager.remove_items:Deleted existing  node {item}")
                        except ua.UaStatusCodeError as e:
                               logging.warning(f"CustomDAManager.remove_items:Failed to delete existing node {item}: {str(e)}")
                    self.items.remove(item)
             logging.debug(f"CustomDAManager.remove_items  completed")
        def broswer_thread(self):
          
            self._wrapper._initialize_com()
            logging.debug(f"CustomDAManager.broswer_thread broswer_thread start")
            try:
                        if not self._opcdeltav.connected:
                            self._opcdeltav.connect()                
                        while not self._wrapper.event.shutdown.is_set():
                            if self._wrapper.event.broswe_opcda_struture.is_set():                                      
                                    self.structure={}
                                    if self.path !="":
                                        move_to_path = self._opcdeltav.move_to_path(self._opcdeltav.browser, self.path)
                                    else:
                                        move_to_path =True
                                    if move_to_path:  
                                        self.structure = self._opcdeltav.browse_level(
                                        self._opcdeltav.browser, 1, self._max_level, self.path, self.structure
                                        )
                                    logging.debug(f"CustomDAManager.broswer_thread: Browser structure completed: {self.structure}")
                                    self._wrapper.event.update_structure.set()
                                    self._wrapper.event.broswe_opcda_struture.clear()                             
                            pythoncom.PumpWaitingMessages()
                            time.sleep(0.01)        
            except Exception as e:
                logging.error(f"CustomDAManager.broswer_thread : broswe_thread error: {str(e)}")
                
            finally:
                try:
                    if self._opcdeltav.connected:
                        self._opcdeltav.disconnect()
                      
                except Exception as e:
                    logging.error(f"CustomDAManager.broswer_thread:Cleanup error in broswe_thread: {str(e)}")
                
                finally:
                   self._wrapper._uninitialize_com()
                 
      
        def opcda_thread(self):
          
            self._wrapper._initialize_com()
            logging.debug(f"CustomDAManager.broswer_thread opcda_thread start")
            try:
            
                        if not self._opcda.connected:
                            self._opcda.connect()
                        items_to_subscribe=self.items.copy()
                        self._opcda.subscribe(items_to_subscribe, group_name=self.group_name, update_rate=self._da_update_rate, callback=self.custom_callback)
                        logging.debug(f"CustomDAManager.opcda_thread:Subscription started for group {self.group_name}")
                        while not self._wrapper.event.shutdown.is_set():
                            
                            
                            if len(items_to_subscribe) != len(self.items):
                                self._opcda.stop_subscribe(self.group_name)
                                time.sleep(self._da_subscribe_waittime)
                                items_to_subscribe=self.items.copy()
                                self._opcda.subscribe(items_to_subscribe, group_name=self.group_name, update_rate=self._da_update_rate, callback=self.custom_callback)
                                logging.debug(f"CustomDAManager.opcda_thread:Dectected items changed, Subscription restarted for group {self.group_name}")
                                time.sleep(self._da_subscribe_waittime)
                              
                            try:
                                poll_data = self.poll_queue.get_nowait()
                             
                                items_to_poll, interval, max_count, max_time = poll_data

                                logging.debug(f"CustomDAManager.opcda_thread:Starting poll for {items_to_poll} every {interval} seconds")
                                start_time = time.time()
                                count = 0
                                while self._wrapper.event.polling.is_set() and not self._wrapper.event.shutdown.is_set() and (max_count is None or count < max_count) and (max_time is None or time.time() - start_time < max_time):
                                    try:
                                        
                                        results = self._opcda.read(items_to_poll)
                                        self.custom_callback(items_to_poll, results)
                                    except Exception as e:
                                        logging.error(f"_OPCDAWrapper_.opc_da_thread:Poll read error: {str(e)}")
                                    count += 1
                                    time.sleep(interval)
                                logging.debug("CustomDAManager.opcda_thread:Polling completed")
                                self._wrapper.event.polling.clear()
                            except Empty:
                                pass

                            try:
                                write_data = self.write_queue.get_nowait()
                              
                                items_to_write, values, write_group_name, write_update_rate, future = write_data
                                logging.debug(f"CustomDAManager.opcda_thread:Starting write operation for {items_to_write}")
                                start_time = time.time()
                                while self._wrapper.event.writing.is_set() and not self._wrapper.event.shutdown.is_set() and (time.time() - start_time < 10):
                                    try:
                                        results = self._opcda.write(items_to_write,values, write_group_name, write_update_rate)
                                        if all(results):
                                            logging.debug(f"CustomDAManager.opcda_thread:Successfully wrote {values} to {items_to_write}")
                                        else:
                                            failed_items = [item for item, success in zip(items_to_write, results) if not success]
                                            logging.warning(f"CustomDAManager.opcda_thread:Partially succeeded: Failed to write to {failed_items}")
                                        logging.debug(f"CustomDAManager.opcda_thread:Write results for {items_to_write}: {results}")
                                        future.set_result(results)
                                        break
                                    except Exception as e:
                                        logging.error(f"CustomDAManager.opcda_thread:Write error in opc_da_thread: {str(e)}")
                                        future.set_exception(e)
                                        break
                                if self._wrapper.event.writing.is_set() and time.time() - start_time >= 10:
                                    logging.error(f"CustomDAManager.opcda_thread:Write to {items_to_write} timed out after 10 seconds")
                                    future.set_exception(asyncio.TimeoutError("Write operation timed out"))
                                self._wrapper.event.writing .clear()
                            except Empty:
                                pass

                            pythoncom.PumpWaitingMessages()
                            time.sleep(0.01)
             
            except Exception as e:
                logging.error(f"CustomDAManager.opcda_thread:OPC DA thread error: {str(e)}")
                
            finally:
                try:
                    if self.group_name and self._opcda.connected:
                        self._opcda.stop_subscribe(self.group_name)
                        logging.debug(f"CustomDAManager.opcda_thread:Subscription {self.group_name} stopped")
                    if self._opcda.connected:
                        self._opcda.disconnect()
                        logging.debug("CustomDAManager.opcda_thread:Disconnected from OPC server")
                except Exception as e:
                    logging.error(f"CustomDAManager.opcda_thread:Cleanup error in thread: {str(e)}")
                
                finally:
                   self._wrapper._uninitialize_com()
                   logging.info("CustomDAManager.opcda_thread:OPC DA thread exiting")
        async def async_poll(self, items: List[str], interval: float = 1.0, max_count: Optional[int] = None, max_time: Optional[float] = None):
            if self._wrapper.event.polling.is_set():
                logging.warning("CustomDAManager.async_poll:Polling already in progress")
                return
            self._wrapper.event.polling.set()
            self.poll_queue.put((items, interval, max_count, max_time))
            try:
                await asyncio.wait_for(self._wait_for_polling(), timeout=max_time or 180)
            except asyncio.TimeoutError:
                logging.debug(f"CustomDAManager.async_poll:Polling for {items} timed out ")
            
                self._wrapper.event.polling.clear()
            logging.debug(f"CustomDAManager.async_poll:Poll task for {items} exited at {time.strftime('%H:%M:%S')}")
        async def _wait_for_polling(self):
            while self._wrapper.event.polling.is_set() and not self._wrapper.event.shutdown.is_set():
                await asyncio.sleep(0.1)
            return True
        async def async_write(self,  values: List[any], items: List[str],group_name: str = "WriteGroup"):
            #logging.info(f"Attempting to write {values} to {items}")
            if not self._wrapper.event.running.is_set():
                logging.error("CustomDAManager.async_write:Cannot write: OPC DA wrapper is not running")
                return [False] * len(items)
            if not self._opcda.connected:
                logging.error("CustomDAManager.async_write:Cannot write: OPC DA server is not connected")
                return None
            if len(items) != len(values):
                logging.error("CustomDAManager.async_write:Cannot write: Number of items and values must match")
                return None
            async with self.write_lock:  # 使用锁确保顺序执行
                if self._wrapper.event.writing.is_set():
                    logging.warning("CustomDAManager.async_write:Write operation already in progress, waiting for lock release")

                    # 这里可以选择等待而不是直接返回 None，因为锁会确保顺序执行

            future = asyncio.Future()
            self._wrapper.event.writing.set()

            self.write_queue.put((items, values, group_name, self._da_update_rate, future))
            try:
                results = await asyncio.wait_for(future, timeout=90)
                #logging.debug(f"Write task for {items} completed at {time.strftime('%H:%M:%S')}")
                return results
            except asyncio.TimeoutError:
                logging.error(f"CustomDAManager.async_write:Write to {items} timed out")
                self._wrapper.event.writing.clear()
                return None
            finally:
                self._wrapper.event.writing.clear()
        async def create_structure(self,parent_node,structure: Dict = None, base_path: str = None):
            """Recursively create folder structure in OPC UA based on OPC DA structure."""
            start_time = time.time()
            logging.debug(f"CustomDAManager.create_structure: Starting structure creation for base_path={base_path}")
            structure = structure if structure is not None else self.structure
            base_path = base_path if base_path is not None else self.path
            logging.debug(f"CustomDAManager.create_structure:Creating folder structure under {parent_node} with base_path={base_path}, structure={structure}")
            node =parent_node
            for key, value in structure.items():
                
                path = f"{base_path}.{key}" if base_path else key                                 
                #folder = await node.add_folder(self.node.idx, key)
                folder = await self.create_folder(path)
           
                
             
               
                if isinstance(value, dict):
                    await self.create_structure(folder,value, path)
                elif value is not None:
                    # value 是 OPC DA item 路径，记录但不立即更新
                    logging.debug(f"CustomDAManager.create_structure: Found item path {value}, awaiting client call to update")
                    # 添加方法到 folder，客户端可调用
                    method_name = f"UpdateItem_{key}"
                    # 检查当前节点下是否已存在同名方法
                    method_exists = False
                    try:
                        # 尝试获取特定子节点
                        await folder.get_child(f"{self._wrapper.node.idx}:{method_name}")
                        method_exists = True
                        logging.debug(f"CustomDAManager.create_structure: Method '{method_name}' already exists under folder {path}, skipping creation")
                    except ua.UaStatusCodeError as e:
                        # 如果子节点不存在，会抛出 BadNodeIdUnknown 异常
                        if e.code == ua.StatusCodes.BadNodeIdUnknown:
                            logging.debug(f"CustomDAManager.create_structure: Method '{method_name}' does not exist, will create it")
                        else:
                            logging.warning(f"CustomDAManager.create_structure: Error checking method '{method_name}' for {path}: {str(e)}")
                    # 如果方法不存在，则创建
                    if not method_exists:
                            async def update_node_wrapper(parent,level:int=3,key=key,value=value):
                                logging.debug(f"CustomDAManager.create_structure: Client called UpdateNode_{key} with preset value={value}")
                                return await self.update_item(parent, ua.Variant(value, ua.VariantType.String),ua.Variant(level, ua.VariantType.Int32))
                            
                            # 添加方法到 folder，客户端调用时无需参数

                            await folder.add_method(
                               self._wrapper.node.idx, 
                                method_name, 
                                update_node_wrapper, 
                                [ua.VariantType.Int32],  
                                [ua.VariantType.String]  # 返回值类型
                            )
            logging.debug(f"CustomDAManager.create_structure: Structure creation completed in {time.time() - start_time:.2f} seconds")              
        async def create_folder(self,base_path: str):
                """Recursively create folder structure in OPC UA based on OPC DA structure."""
                node=self._wrapper.node.da_folder
                
                paths=base_path.split('.')
                
                for i in range(len(paths)):
                    path=".".join(paths[:i+1])
                    if path not in self._wrapper.node.folders:
                        node = await node.add_folder(self._wrapper.node.idx, paths[i])
                        self._wrapper.node.folders[path]=node
                        # 定义一个无需输入参数的包装方法，直接使用 path 作为 base_path
                        async def browse_folder_wrapper(parent,path=path):
                            logging.debug(f"CustomDAManager.create_folder: Client called broswer_{path} with preset base_path={path}")
                            await self.broswe_folder(max_level=1, base_path=path)
                            return [ua.Variant(f"Browsed {path}", ua.VariantType.String)]
                        
                        # 添加方法到 folder，客户端调用时无需参数
                        await node.add_method(
                           self._wrapper.node.idx,
                            f"broswe_{path}",
                            browse_folder_wrapper,
                            [],  # 输入参数为空
                            [ua.VariantType.String]  # 返回值类型
                        )
                        logging.debug(f"CustomDAManager.create_folder:node {path} create for base_path={base_path}, node={node}")    
                    else:
                        node =self._wrapper.node.folders[path]
                        logging.debug(f"CustomDAManager.create_folder:node {path} already existed for base_path={base_path}, node={node}")    
                        
                return  node
        async def broswe_folder(self,max_level:int=1,base_path: str= ""):
                start_time = time.time()
                logging.debug(f"CustomDAManager.broswe_folder: Starting browse for base_path={base_path}")
                async with self.path_lock:  # 使用锁确保顺序执行
                    logging.debug(f"CustomDAManager.broswe_folder:browse sub structure and create sub node for base_path={base_path}") 
                    self.path=base_path
                    self._max_level=max_level
                                
                    self._wrapper.event.broswe_opcda_struture.set()
                    await asyncio.sleep(1)
                    if not self._wrapper.event.update_structure.is_set():
                    # 等待事件被 clear（需要其他协程调用 .clear()）
                        await self._wrapper.event.update_structure.wait()  # 阻塞直到事件被 clear
                
                    logging.debug(f"CustomDAManager.broswe_folder:structure ={self.structure}") 
                    parent_node =self._wrapper.node.da_folder if base_path == "" else self._wrapper.node.folders.get(base_path)
                    if not parent_node and base_path:
                        parent_node = await self.create_folder(base_path)
                    await self.create_structure(parent_node,self.structure,base_path)
                    self._wrapper.event.update_structure.clear()
                    logging.debug(f"CustomDAManager.broswe_folder: Browse completed in {time.time() - start_time:.2f} seconds")
        async def add_items(self, items: List[str],base_path: str = 'MODULES'):
       
            last_values = {}
            logging.debug(f"CustomDAManager.add_items: try to  add items node for {items} at {base_path}...")

            await self.async_poll(items, interval=1, max_time=3.0)
            
            

            for item in items: 
                data = None
                timeout = 3.0
                start_time = time.time()
                while data is None and time.time() - start_time < timeout:
                        data = self.callback.get_data(item)
                        if data is None:
                            await asyncio.sleep(0.1)  # 短暂等待     
                data = self.callback.get_data(item)              
                if data and data[1] != 0:  # 检查数据有效性
                    if item not in self.items:
                        self.items.append(item)
                        logging.debug(f"CustomDAManager.add_items: Added {item} to subcrible items list")
                    value, quality, timestamp = data
                    status = ua.StatusCode(ua.StatusCodes.Good) if quality > 127 else ua.StatusCode(ua.StatusCodes.Bad)                   
                    # 处理时间戳
                    if isinstance(timestamp, str):
                        try:
                            source_timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        except ValueError as e:
                            logging.warning(f"CustomDAManager.add_items Invalid timestamp format for {item}: {timestamp}, using current time. Error: {e}")
                            source_timestamp = datetime.datetime.now(datetime.UTC)
                    elif isinstance(timestamp, datetime.datetime):
                        source_timestamp = timestamp
                    else:
                        logging.warning(f"CustomDAManager.add_items: Unsupported timestamp type for {item}: {type(timestamp)}, using current time")
                        source_timestamp = datetime.datetime.now(datetime.UTC)
                    
                    # 如果值有变化或节点不存在，则更新或创建节点
                    
                    if item not in last_values or last_values[item] != value:
                       
                        if item  not in self._wrapper.node.nodes:
                            #item_path='.'.join([base_path, item.split('/')[0]])                           
                            target_folder=await self.create_folder(base_path)                                                         
                            
                            # 根据值的类型创建 UA 节点
                            if isinstance(value, float):
                                variant_type = ua.VariantType.Double
                                initial_value = float(value)
                            elif isinstance(value, str):
                                variant_type = ua.VariantType.String
                                initial_value = str(value)
                            elif isinstance(value, int):
                                variant_type = ua.VariantType.Int32
                                initial_value = int(value)
                            elif isinstance(value, bool):
                                variant_type = ua.VariantType.Boolean
                                initial_value = bool(value)
                            else:
                                variant_type = ua.VariantType.String
                                initial_value = str(value)
                            
                            # 在目标文件夹下创建节点
                            node_name = item  
                            node = await target_folder.add_variable(self._wrapper.node.idx, node_name, initial_value, varianttype=variant_type)
                            await node.set_writable(True)
                            self._wrapper.node.nodes[item] = node
                            node_id = node.nodeid
                            logging.debug(f"CustomDAManager.add_items: Added UA node for {item} with type {variant_type}, NodeId: {node_id}")
                            # 添加 PollItem 方法
                            async def poll_item_wrapper(parent,item=item):
                                    logging.debug(f"CustomDAManager.poll_item: Client called PollItem for {item}")
                                    return await self.poll_item(parent, item)
                            
                            await node.add_method(
                               self._wrapper.node.idx,
                                f"PollItem_{item.replace('/', '_')}",  # 避免特殊字符影响方法名
                                poll_item_wrapper,
                                [],  
                                [ua.VariantType.Boolean]  # 返回布尔值表示成功与否
                            )

                            
                            # 添加 WriteItem 方法
                            async def write_item_wrapper(parent,value_variant,item=item):
                                logging.debug(f"CustomDAManager.write_item: Client called WriteItem for {item} with value {value_variant.Value}")
                                return await self.write_items(parent,value_variant,item)
                            
                            await node.add_method(
                               self._wrapper.node.idx,
                                f"WriteItem_{item.replace('/', '_')}",
                                write_item_wrapper,
                                [ua.VariantType.Variant],  # 输入值为任意类型
                                [ua.VariantType.Boolean]  # 返回布尔值表示成功与否
                            )

                     # Add EnableHistorizing method
                            async def enable_historizing_wrapper(parent, item=item):
                                logging.debug(f"CustomDAManager.enable_historizing: Client called EnableHistorizing for {item}")
                                return awaitself._wrapper.history_manager.enable_historizing(parent, item)
                            await node.add_method(
                               self._wrapper.node.idx,
                                f"EnableHistorizing_{item.replace('/', '_')}",
                                enable_historizing_wrapper,
                                [],
                                [ua.VariantType.Boolean]
                            )
                            # Add ReadHistory method
                            async def read_history_wrapper(parent, item=item):
                                logging.debug(f"CustomDAManager.read_history: Client called ReadOnehourHistory for {item} with params ")
                                return awaitself._wrapper.history_manager.read_item_history(parent, item)
                            await node.add_method(
                               self._wrapper.node.idx,
                                f"ReadOneHourHistory_{item.replace('/', '_')}",
                                read_history_wrapper,
                                [],
                                [ua.VariantType.String]
                            )
                        # 更新节点值
                        node =self._wrapper.node.nodes[item]
                       
                        node_type = await node.read_data_type()
                      
                        if node_type == ua.NodeId(11, 0):  # Double
                            variant_value = float(value)
                        elif node_type == ua.NodeId(12, 0):  # String
                            variant_value = str(value)
                        elif node_type == ua.NodeId(6, 0):  # Int32
                            variant_value = int(value)
                        elif node_type == ua.NodeId(1, 0):  # Boolean
                            variant_value = bool(value)
                        else:
                            logging.warning(f"CustomDAManager.add_items: Unsupported node type for {item}")
                            continue
                        
                        try:
                            variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                            await node.write_value(ua.DataValue(variant, status, source_timestamp))
                            self._update_count += 1
                            last_values[item] = value
                            if self._max_updates and self._update_count >= self._max_updates:
                                logging.debug(f"CustomDAManager.add_items: Reached max updates ({self._max_updates}), stopping program...")
                                self._wrapper.event.shutdown.set()
                        except ua.UaStatusCodeError as e:
                            logging.error(f"CustomDAManage.add_itemsr:Failed to write {item}: {str(e)}")
                            await self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_items: Failed to write {item}, Error Occured: {str(e)}")
                    else:
                         logging.warning(f"CustomDAManager.add_items: iem {item}: not in last values ot it's value doesn't change")
                else:
                     logging.warning(f"CustomDAManage.add_items: iiem {item}: is not valid in opc data server,check your item path")
        async def update_ua_nodes(self):
                """Update OPC UA nodes with values from OPC DA items"""
                
                while not self._wrapper.event.shutdown.is_set():
                   # logging.debug(f"CustomDAManage.update_ua_nodes: cycle update ua nodes ")    
                    for item in self.items:
                        
                        data = self.callback.get_data(item)              
                        if data and data[1] != 0:  # 检查数据有效性
                            value, quality, timestamp = data
                            status = ua.StatusCode(ua.StatusCodes.Good) if quality > 127 else ua.StatusCode(ua.StatusCodes.Bad)                   
                            # 处理时间戳
                            if isinstance(timestamp, str):
                                try:
                                    source_timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                                except ValueError as e:
                                    logging.warning(f"CustomDAManage.update_ua_nodes: Invalid timestamp format for {item}: {timestamp}, using current time. Error: {e}")
                                    source_timestamp = datetime.datetime.now(datetime.UTC)
                            elif isinstance(timestamp, datetime.datetime):
                                source_timestamp = timestamp
                            else:
                                logging.warning(f"CustomDAManage.update_ua_nodes: Unsupported timestamp type for {item}: {type(timestamp)}, using current time")
                                source_timestamp = datetime.datetime.now(datetime.UTC)
                    
                        # 更新节点值
                        node =self._wrapper.node.nodes[item]
                        node_type = await node.read_data_type()             
                        if node_type == ua.NodeId(11, 0):  # Double
                            variant_value = float(value)
                        elif node_type == ua.NodeId(12, 0):  # String
                            variant_value = str(value)
                        elif node_type == ua.NodeId(6, 0):  # Int32
                            variant_value = int(value)
                        elif node_type == ua.NodeId(1, 0):  # Boolean
                            variant_value = bool(value)
                        else:
                            logging.warning(f"CustomDAManage.update_ua_nodes: Unsupported node type for {item}")
                            continue
                        
                        try:
                            variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                            await node.write_value(ua.DataValue(variant, status, source_timestamp))
                            logging.debug(f"CustomDAManage.update_ua_nodes: update node  for {item} to {value} ")           
                        except ua.UaStatusCodeError as e:
                            logging.error(f"CustomDAManage.update_ua_nodes: Failed to write {item}: {str(e)}")
                            await  self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.update_ua_nodes: Failed to write {item}, Error Occured: {str(e)}") 
                    await asyncio.sleep(self._ua_update_rate)  

        async def update_item(self, parent, path_variant,level_variant):
                    """OPC UA 方法：对指定 item path 执行 add 操作"""
                    userrole = await  self._wrapper.security._get_current_userrole()
            
                    if not self._wrapper.user_manager.check_method_permission(50, userrole):
                        logging.warning(f"CustomDAManage.update_node_call:Unauthorized attempt to call update_node_call ")
                        await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                        await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.update_node_call:Unauthorized attempt to call generate_server_certificate ")
                        raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
                    try:
                        path = path_variant.Value
                        level = level_variant.Value
                        if not isinstance(path, str):
                                await self._wrapper.node.last_error_desc.write_value("CustomDAManage.update_node_call: Invalid input - path must be a string")
                                raise ValueError("Path must be a string")
                        path = path.upper() 
                        path_parts = path.split('.')
                        if level==0 and len(path_parts)==2 and "/" in path_parts[0]:
                             await self.update_node(path,0)
                             logging.debug(f"CustomDAManager.update_node_call: Client requested update for path={path} and level={level}")
                             return [ua.Variant(True, ua.VariantType.Boolean)] 
                            # 检查是否有空字符串
                        special_chars = {'/', '$', '!', '%', '#', '@', '~', '\\', '`', '(', '{', '[','+','=','^','&','*',')','}',']',',','?','|'}
                        if any(part == '' or any(char in part for char in special_chars) for part in path_parts) or len(path_parts) < 2:
                            await self._wrapper.node.last_error_desc.write_value("CustomDAManage.update_node_call: Invalid input - path must not contain empty parts or '/' and must have at least 4 segments")
                            raise ValueError("Invalid path format: must not contain empty parts or '/' and must have at least 4 segments")
                
                        # 检查 level_variant
                       
                        if not isinstance(level, int):
                            await self._wrapper.node.last_error_desc.write_value("CustomDAManage.update_node_call: Invalid input - level must be an integer")
                            raise ValueError("Level must be an integer")
                        if 0 < level < 2:
                            await self._wrapper.node.last_error_desc.write_value("CustomDAManage.update_node_call: Invalid input - level must be >= 2 or =0 ")
                            raise ValueError("Level must be >= 3 or level = 0 ")
                        logging.debug(f"CustomDAManager.update_node_call: Client requested update for path={path} and level={level}")
                       
                        
                       
                        await self.update_node(path,level)
                        return [ua.Variant(True, ua.VariantType.Boolean)] 
                    except ValueError as e:
                        logging.error(f"CustomDAManage.update_node_call: Input validation failed: {str(e)}")
                        await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadInvalidArgument)
                        raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)   
                    except Exception as e:
                            logging.error(f"CustomDAManage.update_node_call:Failed to update_node_call: {str(e)}")
                            if self._wrapper.node.last_error_desc is not None: 
                                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.update_node_call:Failed to call update_node ,Error Occured: {str(e)}")
                            raise           
        async def poll_item(self, parent, item: str) -> list:
            """OPC UA 方法：对指定 item 执行 async_poll 操作"""
            userrole = await self._wrapper.security._get_current_userrole()
            if not self._wrapper.user_manager.check_method_permission(50, userrole):  # 与 update_item 相同的权限级别
                logging.warning(f"CustomDAManage.poll_item: Unauthorized attempt to poll item {item}")
                await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.poll_item: Unauthorized attempt to poll item {item}")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            
            try:
                await self.async_poll([item], interval=1.0, max_time=2.0)  # 默认参数，可根据需要调整
                logging.info(f"CustomDAManage.poll_item: Successfully polled item {item}")
                return [ua.Variant(True, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"CustomDAManage.poll_item: Failed to poll item {item}: {str(e)}")
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.poll_item: Failed to poll item {item}, Error Occurred: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]
        async def update_node(self,path: str,level:int=3):                         
                    parts = path.split('.')
                    if level== 0:
                         item=path
                         await self.add_items([item])
                         logging.debug(f"CustomDAManager.update_node: Client requested update for path={path} and item is {item}")
                         return item
                    elif len(parts) > level:
                        folder = '.'.join(parts[:level])  # 前 level 项是 folder
                        item_parts = parts[level:]        # 剩下的部分是 item
                        item = '/'.join(item_parts[:-1]) + '.' + item_parts[-1] if len(item_parts) > 1 else item_parts[0]
                       
                    else:
                        num=len(parts)
                        if num==3:
                           folder = parts[0]
                           item = '/'.join(parts[1:-1]) + '.' + parts[-1]
                        else:                 
                           folder = '.'.join(parts[:3])
                           item = '/'.join(parts[3:-1]) + '.' + parts[-1]

                    await self.add_items([item], folder)
                    logging.debug(f"CustomDAManage.update_node: Try to create item {item} node under {folder}")
                    return item 

                    
                    
                   
        async def write_items(self,parent, values_variant, items_variant):
                userrole = await self._wrapper.security._get_current_userrole()
                if not self._wrapper.user_manager.check_method_permission(13, userrole):
                    logging.warning(f"CustomDAManage.write_items:Unauthorized attempt to call write_items ")
                    await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.write_items:Unauthorized attempt to call write_items ")
                    return [ua.Variant(False, ua.VariantType.Boolean), ua.Variant("BadUserAccessDenied", ua.VariantType.String)]
                logging.debug(f"CustomDAManage.write_items: called with items_variant: {items_variant}, values_variant: {values_variant}")
                try:
                    if isinstance(items_variant, str):
                        items = [items_variant]
                        values = [values_variant.Value]
                    elif not isinstance(items_variant.Value, list) or not isinstance(values_variant.Value, list):
                        logging.error(f"CustomDAManage.write_items: Invalid input types: items={type(items_variant.Value)}, values={type(values_variant.Value)}")
                        return [ua.Variant(False, ua.VariantType.Boolean)]
                    
                    else:
                        items = items_variant.Value
                        values = [val.Value for val in values_variant.Value]
                    await self.async_poll(items, interval=1.0, max_time=2.0)
                    for i in range(len(items)):
                        
                        current_data = self.callback.get_data(items[i])
                        if current_data and current_data[1] != 0:  # 数据有效
                                current_value, quality, timestamp = current_data
                                expected_type = type(current_value)
                            
                        else:
                            
                                expected_type = None 
                        # 类型转换
                        if expected_type:
                                try:
                                    if expected_type == float and not isinstance(values[i], (int, float)):
                                        values[i] = float(values[i])
                                        logging.debug(f"CustomDAManage.write_item: Converted {values[i]} to float")
                                    elif expected_type == int and not isinstance(values[i], int):
                                        values[i] = int(values[i])
                                        logging.debug(f"CustomDAManage.write_item: Converted {values[i]} to int")
                                    elif expected_type == bool and not isinstance(values[i], bool):
                                        values[i] = bool(values[i])
                                        logging.debug(f"CustomDAManage.write_item: Converted {values[i]} to bool")
                                    elif expected_type == str and not isinstance(values[i], str):
                                        values[i] = str(values[i])
                                        logging.debug(f"CustomDAManage.write_item: Converted {values[i]} to str")
                                except (ValueError, TypeError) as e:
                                
                                    await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.write_item: Type mismatch for {items[i]}, expected {expected_type}, got {type(values[i])}")
                                   
                                    return [ua.Variant(False, ua.VariantType.Boolean), ua.Variant("Type mismatch", ua.VariantType.String)]
                    results = await self.async_write(values,items)
                    logging.debug(f"CustomDAManage.write_item: write results for  {items} is {results}")
                    for item, value, success in zip(items, values, results):
                        if not success:
                            continue
                        #ua_name = item.replace('/', '_')
                        ua_name = item
                        if item not in self._wrapper.node.nodes:
                            if isinstance(value, int):
                                variant_type = ua.VariantType.Int64
                            elif isinstance(value, float):
                                variant_type = ua.VariantType.Double
                            elif isinstance(value, str):
                                variant_type = ua.VariantType.String
                            elif isinstance(value, bool):
                                    variant_type = ua.VariantType.Boolean
                                
                            else:
                                variant_type = ua.VariantType.Variant
                            node = await self._wrapper.node.da_folder.add_variable( self._wrapper.node.idx, ua_name, value, varianttype=variant_type)
                            self._wrapper.node.nodes[item] = node
                        else:
                            node = self._wrapper.node.nodes[item]
                            data_value = await node.read_data_value()
                            current_type = data_value.Value.VariantType
                            try:
                                if current_type == ua.VariantType.Double and isinstance(value, int):
                                    value = float(value)
                                elif current_type == ua.VariantType.Int64 and isinstance(value, float):
                                    value = int(value)
                                await node.write_value(value)
                            except ua.UaStatusCodeError as e:
                                logging.warning(f"CustomDAManage.write_items:Failed to update UA node {item}: {e}")
                    return [ua.Variant(results, ua.VariantType.Boolean)]
                    #return [ua.Variant(all(results), ua.VariantType.Boolean)]
                except Exception as e:
                    logging.error(f"CustomDAManage.write_items:Error in write_items: {str(e)}")
                    await self._wrapper.node.last_error_desc.write_value(f"CustomDAManage.write_items:Error in write_items,Error Occured: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean), ua.Variant(f"{str(e)}", ua.VariantType.String)]
          
                 

        async def _process_json_structure(self, structure: Dict, base_path: str):
            
                try:
                    for key, value in structure.items():
                        # 处理当前路径
                        current_path = f"{base_path}.{key}" if base_path else key
                        
                        # 处理 value
                        if isinstance(value, list):
                            # 如果 value 是列表，添加项
                            if value:  # 仅对非空列表处理                       
                                await self.add_items(value, current_path)
                        
                        elif isinstance(value, dict):
                            # 如果 value 是字典，继续递归
                            if value:  # 仅对非空字典递归
                                await self._process_json_structure(value, current_path)
                except Exception as e:
                        logging.error(f"CustomDAManage._process_json_structure: Failed at {base_path}: {str(e)}")
                        raise  # 或者根据需求决定是否抛出                                           
        async def add_nodes_from_json(self, parent, json_data_variant) -> list:
                    """
                    OPC UA 方法：从客户端上传的 JSON 文件添加节点
                    输入参数：json_data (ByteString) - JSON 文件内容
                    返回值：[Boolean] - True 表示成功，False 表示失败
                    """
                    userrole = await self._wrapper.security._get_current_userrole()
                    if not self._wrapper.user_manager.check_method_permission(50, userrole):
                        logging.warning(f"CustomDAManage.add_nodes_from_json: Unauthorized attempt to add nodes from JSON")
                        await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                        await self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to add nodes from JSON")
                        raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

                    try:
                        # 从 ByteString 获取 JSON 数据
                        json_data = json_data_variant.Value.decode('utf-8')

                        structure = json.loads(json_data)
                        logging.debug(f"CustomDAManage.add_nodes_from_json: Received JSON structure: {json.dumps(structure, indent=2)}")
                    
                        # 从根节点开始处理整个 JSON 结构
                        asyncio.create_task(self._process_json_structure(structure, ""))
                        
                    
                        return [ua.Variant(True, ua.VariantType.Boolean)]
                    except json.JSONDecodeError as e:
                        logging.error(f"CustomDAManage.add_nodes_from_json: Invalid JSON format: {str(e)}")
                        await self._wrapper.node.last_error_desc.write_value(f"Invalid JSON format: {str(e)}")
                        return [ua.Variant(False, ua.VariantType.Boolean)]
                    except Exception as e:
                        logging.error(f"CustomDAManage.add_nodes_from_json: Error processing JSON: {str(e)}")
                        await self._wrapper.node.last_error_desc.write_value(f"Error processing JSON: {str(e)}")
                        return [ua.Variant(False, ua.VariantType.Boolean)] 
        async def export_nodes_to_json(self, parent) -> list:
            """
            OPC UA 方法：导出当前节点结构到 JSON
            返回值：[String] - JSON 格式的节点结构
            """
            userrole = await self._wrapper.security._get_current_userrole()
            if not self._wrapper.user_manager.check_method_permission(50, userrole):
                logging.warning(f"CustomDAManage.export_nodes_to_json: Unauthorized attempt to export nodes")
                await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to export nodes")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

            try:
                # 构建节点结构的 JSON 表示
                node_structure = await self._wrapper.node._build_node_structure( self._wrapper.node.da_folder)
                logging.debug(node_structure)
                json_data = json.dumps(node_structure, indent=2)
                logging.debug(f"CustomDAManage.export_nodes_to_json: Exported structure: {json_data}")
                return [ua.Variant(json_data, ua.VariantType.String)]
            except Exception as e:
                logging.error(f"CustomDAManage.export_nodes_to_json: Error exporting nodes: {str(e)}")
                await self._wrapper.node.last_error_desc.write_value(f"Error exporting nodes: {str(e)}")
                raise

class CustomHistoryManager:
    def __init__(self,wrapper,server_name: str = "DeltaV.OPCHDAsvr"):
        self._events = {}  # node_id -> deque of (timestamp, event_data)
        self._event_update_rate:int=5
        self.period_event_filters = {
                                 "Category": ["PROCESS","USER"],
                                # "Event_Type":["ALARM","EVENT","CHANGE"],
                                # "Attribute": ["LO_ALM","LO_LO_ALM","HI_ALM","HI_HI_ALM","PVBAD_ALM"]
                                 "Area":["AREA_V1","AREA_V2","AREA_A"]
                                                                      
                            }
        self._lock = asyncio.Lock()
        self._retention_period = datetime.timedelta(minutes=5)
        self._retention_count = None  # Initialize retention count
        logging.debug("CustomHistoryManager: Initialized CustomHistoryManager")
        self._opchda = _OPCHDA_(server_name)
        self._wrapper = wrapper
        self.opchda_executor =None
       

    async def init(self):
        """Initialize the history manager."""
        logging.debug("CustomHistoryManager: set _prune_old_events and executor_opchda task")
        asyncio.create_task(self._prune_old_events())
        self.opchda_executor = self._wrapper.executor_opchda

    async def setup_event_type(self):
            """初始化自定义事件类型 DeltaVEventType"""
      
            try:
                # try:
                    
                #    #AckedState_node= self.server.get_node(ua.NodeId(9013))
                #    AckedState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AckedState"])
                #    await AckedState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await AckedState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Unacknowledged", "en"))
                #    await (await AckedState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Acknowledged", "en"))
                #    #await AckedState_node.write_value(False)
                #    await AckedState_node.set_modelling_rule(True)
                #    ConfirmedState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:ConfirmedState"])
                #    await ConfirmedState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await ConfirmedState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Unconfirmed", "en"))
                #    await (await ConfirmedState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Confirmed", "en"))
                #    ##wait ConfirmedState_node.write_value(False)
                #    await ConfirmedState_node.set_modelling_rule(True)
                # #    EnabledState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:EnabledState"])
                # #    await EnabledState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                # #    await (await EnabledState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Disabled", "en"))
                # #    await (await EnabledState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Enabled", "en"))
                # #    await EnabledState_node.write_value(False)
                # #    await EnabledState_node.set_modelling_rule(True)

                #    #ActiveState_node= self.server.get_node(ua.NodeId(9160))
                #    ActiveState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType","0:ActiveState"])
                #    await ActiveState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await ActiveState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("InActive", "en"))
                #    await (await ActiveState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Active", "en"))
                #    #await ActiveState_node.write_value(False)
                #    await ActiveState_node.set_modelling_rule(True)
                #    LatchedState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType","0:LatchedState"])
                #    await LatchedState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await LatchedState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Unlatched", "en"))
                #    await (await LatchedState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Latched", "en"))
                #    #await LatchedState_node.write_value(False)
                #    await LatchedState_node.set_modelling_rule(True)
                #    OutOfServiceState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType","0:OutOfServiceState"])
                #    await OutOfServiceState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await OutOfServiceState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("iNOfService", "en"))
                #    await (await OutOfServiceState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("OutOfService", "en"))
                #    #await OutOfServiceState_node.write_value(False)
                #    await OutOfServiceState_node.set_modelling_rule(True)
                #    SilenceState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType","0:SilenceState"])
                #    await SilenceState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await SilenceState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Not Silenced", "en"))
                #    await (await SilenceState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Silenced", "en"))
                #    #await SilenceState_node.write_value(False)
                #    await SilenceState_node.set_modelling_rule(True)
                #    SuppressedState_node=await self.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType","0:SuppressedState"])
                #    await SuppressedState_node.write_attribute(ua.AttributeIds.DataType, ua.DataValue(ua.NodeId(ua.ObjectIds.TwoStateVariableType)))
                #    await (await SuppressedState_node.get_child("0:FalseState")).write_value(ua.LocalizedText("Unsuppressed", "en"))
                #    await (await SuppressedState_node.get_child("0:TrueState")).write_value(ua.LocalizedText("Suppressed", "en"))
                #    #await SuppressedState_node.write_value(False)
                #    await SuppressedState_node.set_modelling_rule(True)
                # except Exception as e:
                #     logging.error(f"_OPCDAWrapper_.setup_event_type: Failed to set base type  : {str(e)}")
                #     raise 


                # 定义 DeltaVEventType
                self._wrapper.node.event_type = await self._wrapper.server.nodes.base_event_type.add_object_type( self._wrapper.node.idx, "DeltaVEventType")
                event_properties = [
                    ("EventTime", ua.Variant(datetime.datetime.now(), ua.VariantType.DateTime)),
                    ("Event_Type", ua.Variant("", ua.VariantType.String)),
                    ("Category", ua.Variant("", ua.VariantType.String)),
                    ("Area", ua.Variant("", ua.VariantType.String)),
                    ("Node", ua.Variant("", ua.VariantType.String)),
                    ("Module", ua.Variant("", ua.VariantType.String)),
                    ("ModuleDescription", ua.Variant("", ua.VariantType.String)),
                    ("Attribute", ua.Variant("", ua.VariantType.String)),
                    ("State", ua.Variant("", ua.VariantType.String)),
                    ("Level", ua.Variant("", ua.VariantType.String)),
                    ("Parameter", ua.Variant("", ua.VariantType.String)),
                    ("Description", ua.Variant("", ua.VariantType.String)),
                    ("Severity", ua.Variant(0, ua.VariantType.UInt32))
                 
             
                
                ]
                for name, value in event_properties:
                    prop = await self._wrapper.node.event_type.add_property( self._wrapper.node.idx, name, value)
                    await prop.set_modelling_rule(True)
                logging.debug(f"CustomHistoryManager.setup_event_type: Created DeltaVEventType: { self._wrapper.node.event_type}")



                condition_type_node = None
                # 优先尝试直接查找 AlarmConditionType
                try:
                    condition_type_node = await self._wrapper.server.nodes.base_event_type.get_child(["0:ConditionType","0:AcknowledgeableConditionType","0:AlarmConditionType"])
                    logging.debug("CustomHistoryManager.setup_event_type: Accessed AlarmConditionType via get_child")
                except ua.UaStatusCodeError as e:
                    logging.warning(f"CustomHistoryManager.setup_event_type: Failed to get AlarmConditionType via get_child: {str(e)}. Searching recursively...")
                    # 递归查找 AlarmConditionType
                    condition_type_node = await self._wrapper._find_type_node(self.server.nodes.base_event_type, "AlarmConditionType", namespace_index=0)
                    if not condition_type_node:
                        logging.warning("CustomHistoryManager.setup_event_type: Could not find AlarmConditionType. Trying ConditionType as fallback...")
                        # 回退到 ConditionType
                        condition_type_node = await self._wrapper._find_type_node(self.server.nodes.base_event_type, "ConditionType", namespace_index=0)
                        if not condition_type_node:
                            logging.error("CustomHistoryManager.setup_event_type: Could not find ConditionType or AlarmConditionType. Using BaseEventType as fallback.")
                            condition_type_node = self._wrapper.server.nodes.base_event_type

                # 验证节点类型
                node_class = await condition_type_node.read_node_class()
                if node_class != ua.NodeClass.ObjectType:
                    logging.warning(f"CustomHistoryManager.setup_event_type: Node {condition_type_node} is not an ObjectType. Using BaseEventType as fallback.")
                    condition_type_node = self._wrapper.server.nodes.base_event_type

                # Verify node is an ObjectType
                node_class = await condition_type_node.read_node_class()
                if node_class != ua.NodeClass.ObjectType:
                    logging.warning(f"CustomHistoryManager.setup_event_type: Node {condition_type_node} is not an ObjectType. Using BaseEventType as fallback.")
                    condition_type_node = self._wrapper.server.nodes.base_event_type
                self._wrapper.node.alarm_type = await condition_type_node.add_object_type( self._wrapper.node.idx, "DeltaVAlarmType")
                alarm_properties = [
                    ("EventTime", ua.Variant(datetime.datetime.now(), ua.VariantType.DateTime)),
                    ("Event_Type", ua.Variant("", ua.VariantType.String)),
                    ("Category", ua.Variant("", ua.VariantType.String)),
                    ("Area", ua.Variant("", ua.VariantType.String)),
                    ("Node", ua.Variant("", ua.VariantType.String)),
                    ("Module", ua.Variant("", ua.VariantType.String)),
                    ("ModuleDescription", ua.Variant("", ua.VariantType.String)),
                    ("Attribute", ua.Variant("", ua.VariantType.String)),
                    ("State", ua.Variant("", ua.VariantType.String)),
                    ("Level", ua.Variant("", ua.VariantType.String)),
                    ("Parameter", ua.Variant("", ua.VariantType.String)),
                    ("Description", ua.Variant("", ua.VariantType.String)),
                    ("Severity", ua.Variant(0, ua.VariantType.UInt32))
               
                    
                ]
                for name, value in alarm_properties:
                    prop = await self._wrapper.node.alarm_type.add_property( self._wrapper.node.idx, name, value)
                    await prop.set_modelling_rule(True)
                logging.debug(f"CustomHistoryManager.setup_event_type: Created DeltaVAlarmType: { self._wrapper.node.alarm_type}")
                
            except Exception as e:
                logging.error(f"CustomHistoryManager.setup_event_type: Failed to create event/alarm types: {str(e)}")
                raise
  
    
    async def test_alarm(self):
                logging.debug(f"test_alarm:BEGIN test server event & alarm function")
                condition = self._wrapper.server.get_node(ua.NodeId(2830))
                
                con_gen = await self._wrapper.server.get_event_generator(condition, self._wrapper.node.events_node)  
                logging.debug(f"test_alarm:add get_event_generator: {con_gen}")
            

               
                alarm = self._wrapper.server.get_node(ua.NodeId(10637)) #10637
                alarm_gen = await self._wrapper.server.get_event_generator(alarm, self._wrapper.node.events_node)
                logging.debug(f"test_alarm:aadd get_event_generator: {alarm_gen}")
                con_gen.event.ConditionName = 'Example Condition'
                con_gen.event.Message = ua.LocalizedText("test_alarm: Example Condition Some Message")
                con_gen.event.Severity = 500
                con_gen.event.BranchId = ua.NodeId(0)
                con_gen.event.Retain = True
                #await con_gen.trigger()
                logging.debug(f"test_alarm:a Triggered condition event: {con_gen.event}")
                logging.debug(f"test_alarm:aExample Alarm1")
                alarm_gen.event.ConditionName = 'test_alarm: Example Alarm1'
                alarm_gen.event.Message = ua.LocalizedText("SIMLUATE error in module1")
                alarm_gen.event.Severity = 500
                
                alarm_gen.event.BranchId = ua.NodeId(0)
                alarm_gen.event.AckedState = ua.LocalizedText('Unacknowledged', 'en')
                setattr(alarm_gen.event, 'AckedState/Id', False)
                await alarm_gen.trigger()
                logging.debug(f"Triggered alarm event: {alarm_gen.event}")
                await asyncio.sleep(20)
                alarm_gen.event.Retain = True
                alarm_gen.event.ActiveState = ua.LocalizedText('Active', 'en')
                setattr(alarm_gen.event, 'ActiveState/Id', True)
                
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                await asyncio.sleep(5)
                alarm_gen.event.Retain = False
                alarm_gen.event.ActiveState = ua.LocalizedText('Inactive', 'en')
                setattr(alarm_gen.event, 'ActiveState/Id', False)
                await alarm_gen.trigger()
                await asyncio.sleep(5)
                
                con_gen.event.Retain = False
                await con_gen.trigger()
                logging.debug(f"test_alarm:Triggered condition event: {con_gen.event}")
                await asyncio.sleep(5)
                logging.debug(f"test_alarm:Example Alarm2")
                alarm_gen.event.ConditionName = 'Example Alarm2'
                alarm_gen.event.Message = ua.LocalizedText("SIMULATE error in module2")
                alarm_gen.event.Severity = 500
                alarm_gen.event.BranchId = ua.NodeId(0)
                alarm_gen.event.AckedState = ua.LocalizedText('Unacknowledged', 'en')
                setattr(alarm_gen.event, 'AckedState/Id', False)
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                await asyncio.sleep(10)
                
                alarm_gen.event.Retain = True
                alarm_gen.event.ActiveState = ua.LocalizedText('Active', 'en')
                setattr(alarm_gen.event, 'ActiveState/Id', True)
                await asyncio.sleep(10)
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                await asyncio.sleep(5)
                alarm_gen.event.Retain = False
                alarm_gen.event.ActiveState = ua.LocalizedText('Inactive', 'en')
             
                setattr(alarm_gen.event, 'ActiveState/Id', False)
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                con_gen.event.Retain = True
                await con_gen.trigger()
                logging.debug(f"test_alarm:Triggered condition event: {con_gen.event}")
                alarm_gen.event.Retain = True
                alarm_gen.event.ActiveState = ua.LocalizedText('Active', 'en')
                setattr(alarm_gen.event, 'ActiveState/Id', True)
         
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                await asyncio.sleep(10)
                alarm_gen.event.Retain = False
                alarm_gen.event.ActiveState = ua.LocalizedText('Inactive', 'en')
                setattr(alarm_gen.event, 'ActiveState/Id', False)
                await alarm_gen.trigger()
                logging.debug(f"test_alarm:Triggered alarm event: {alarm_gen.event}")
                logging.debug(f"test_alarm:END test server event & alarm function")
               
    def read_opchda(self,item_id, start_time, end_time, num_values, return_bounds=3):
             
                try:
                    if self._opchda.connect():
                        results =  self._opchda.ReadRaw(item_id,start_time, end_time, num_values, return_bounds)
                        return results
                    else:
                        return None
                except Exception as e:
                       logging.error(f"CustomHistoryManager:Failed to connect OPCHDA: {str(e)}")    
                       return None
                finally:
                     self._opchda.disconnect()
                    
                
                   
    def sync_read_opchda(self,item_ids, start_time, end_time, max_values):
                 
                    try:
                        if self._opchda.connect():
                           
                            results =  self._opchda.SyncReadRaw(item_ids, start_time, end_time, max_values)
                            #logging.debug(f"sync_read_opchda: get results from opchda server {results}")
                            return results
                        else:
                             return None
                    except Exception as e:
                       logging.error(f"CustomHistoryManager:Failed to connect OPCHDA: {str(e)}")   
                       return None
                    finally:
                        self._opchda.disconnect()
                       
                      
  
    async def enable_historizing(self, parent, item: str) -> list:
        """OPC UA Method: Enable historizing for the specified item."""
        userrole = await self._wrapper.security._get_current_userrole()
        if not self._wrapper.user_manager.check_method_permission(50, userrole):
            logging.warning(f"CustomHistoryManager.enable_historizing: Unauthorized attempt to enable historizing for {item}")
            await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Unauthorized attempt to enable historizing for {item}")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
        try:
            node = self._wrapper.node.nodes.get(item)
            if not node:
                logging.error(f"CustomHistoryManager.enable_historizing: Node for {item} not found")
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Node for {item} not found")
                return [ua.Variant(False, ua.VariantType.Boolean)]
              # Debug node type and attributes
            logging.debug(f"CustomHistoryManager.enable_historizing: Node for {item} is of type {type(node)}, NodeId: {node.nodeid}")
              # Verify node is a variable node
            node_class = await node.read_node_class()
            if node_class != ua.NodeClass.Variable:
                logging.error(f"CustomHistoryManager.enable_historizing: Node {item} is not a variable node (NodeClass: {node_class})")
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Node {item} is not a variable node")
                return [ua.Variant(False, ua.VariantType.Boolean)]
            # Enable historizing for the node
              # Check if set_historizing is available
            if not hasattr(node, 'set_historizing'):
                logging.error(f"CustomHistoryManager.enable_historizing: Node {item} does not support set_historizing method")
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Node {item} does not support historizing")
                # Alternative: Set Historizing attribute manually
                try:
                    await node.write_attribute(ua.AttributeIds.Historizing, ua.DataValue(True))
                    #access_level = ua.AccessLevel.CurrentRead | ua.AccessLevel.CurrentWrite | ua.AccessLevel.HistoryRead
                    access_level =7 #1+2+4
             
                    await node.write_attribute(
                        ua.AttributeIds.AccessLevel,
                        ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte))
                    )
                    await node.write_attribute(
                        ua.AttributeIds.UserAccessLevel,
                        ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte))
                    )
                    logging.info(f"CustomHistoryManager.enable_historizing: Manually set Historizing attribute for {item}")
                except Exception as e:
                    logging.error(f"CustomHistoryManager.enable_historizing: Failed to set Historizing attribute for {item}: {str(e)}")
                    await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Failed to set Historizing attribute for {item}: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]
            else:
                # Use set_historizing if available
                await node.set_historizing(True)
               
                logging.debug(f"CustomDAManager.enable_historizing: Set historizing for {item} using set_historizing")
            
            # Configure history storage with a retention period (e.g., 1 hour) and optional count
            # await self.historize_data(
            #     node.nodeid,
            #     period=datetime.timedelta(hours=1),
            #     count=None
            # )
            logging.debug(f"CustomHistoryManager.enable_historizing: Successfully enabled historizing for {item}")
            return [ua.Variant(True, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"CustomHistoryManager.enable_historizing: Failed to enable historizing for {item}: {str(e)}")
            await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.enable_historizing: Failed to enable historizing for {item}, Error Occurred: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
    # async def historize_data(self, node_id: ua.NodeId, period: datetime.timedelta, count: Optional[int] = None):
    #     async with self._lock:
           
    #          logging.debug(f"CustomHistoryManager: historize_data :dont't trust me , for DeltaV use DeltaV.OPCHDAsvr to fetch data from historian")
    #         #logging.debug(f"CustomHistoryManager: historize_data Marked node {node_id} for data historization with period={period}, count={count}")
    # def is_historizing_data(self, node_id: ua.NodeId):
        
    #     return True
    async def read_item_history(self, parent, item: str) -> list:
        """OPC UA Method: Read historical data for the specified item."""
        userrole = await self._wrapper.security._get_current_userrole()
        if not self._wrapper.user_manager.check_method_permission(50, userrole):
            logging.warning(f"CustomHistoryManager.read_item_history: Unauthorized attempt to read history for {item}")
            await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.read_item_history: Unauthorized attempt to read history for {item}")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
        try:
            node = self._wrapper.node.nodes.get(item)
            if not node:
                logging.error(f"CustomHistoryManager.read_history: Node for {item} not found")
                await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.read_item_history: Node for {item} not found")
                return [ua.Variant("", ua.VariantType.String)]
            start_time=datetime.datetime.now()-datetime.timedelta(hours=1)
            end_time=datetime.datetime.now()
            results = await asyncio.get_running_loop().run_in_executor(
                    self.opchda_executor,
                    lambda: self.read_opchda(item, start_time, end_time, 3600)
                )
            if results is None:
                      return [ua.Variant("", ua.VariantType.String)]
         
            data_points = []
          
                  
            item_data = results.get(item, {"values": [], "qualities": [], "timestamps": []})
            for value, quality, timestamp in zip(
                item_data["values"], item_data["qualities"], item_data["timestamps"]
            ):
                if isinstance(timestamp, datetime.datetime):
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=datetime.UTC)
                    timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp = datetime.datetime.fromtimestamp(
                            timestamp.timestamp(), tz=datetime.UTC
                        )
                    timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
           
                data_points.append({
                            "value": value,
                            "quality": quality,
                            "timestamp": timestamp_num,
                            "Time": timestamp_str
                        })
             
            json_output = json.dumps(data_points, ensure_ascii=False)
            logging.debug(f"CustomHistoryManager.read_item_history: Retrieved {len(data_points)} data points for {item}")
            return [ua.Variant(json_output, ua.VariantType.String)]
        except json.JSONDecodeError as e:
            logging.error(f"CustomHistoryManager.read_item_history: Invalid JSON parameters for {item}: {str(e)}")
            await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.read_item_history: Invalid JSON parameters for {item}: {str(e)}")
            return [ua.Variant("", ua.VariantType.String)]
        except Exception as e:
            logging.error(f"CustomHistoryManager.read_item_history: Failed to read history for {item}: {str(e)}")
            await self._wrapper.node.last_error_desc.write_value(f"CustomDAManager.read_item_history: Failed to read history for {item}, Error Occurred: {str(e)}")
            return [ua.Variant("", ua.VariantType.String)]
    async def _prune_old_events(self):
            while True:
                try:
                    async with self._lock:
                        now = datetime.datetime.now(datetime.UTC)
                        for source_id in list(self._events.keys()):
                            queue = self._events[source_id]
                            while queue:
                                event = queue[0]
                                event_time = event.get("EventTime")
                                if not isinstance(event_time, ua.Variant) or event_time.VariantType != ua.VariantType.DateTime:
                                    logging.warning(f"CustomHistoryManager._prune_old_events:Invalid EventTime in event for {source_id}: {event_time}")
                                    queue.pop(0)  # Remove invalid event
                                    continue
                                # Ensure event_time.Value is offset-aware
                                if event_time.Value.tzinfo is None:
                                    event_time_value = event_time.Value.replace(tzinfo=datetime.UTC)
                                else:
                                    event_time_value = event_time.Value
                                if  now - event_time_value > self._retention_period:
                                    queue.pop(0)
                                    logging.debug(f"CustomHistoryManager._prune_old_events:Pruned old event for {source_id}")
                                else:
                                    break
                            if not queue:
                                del self._events[source_id]
                                logging.debug(f"CustomHistoryManager._prune_old_events:Removed empty event queue for {source_id}")
                except Exception as e:
                    logging.error(f"CustomHistoryManager._prune_old_events:Error in _prune_old_events: {str(e)}")
                await asyncio.sleep(60)  # Run every minute
    
    async def historize_event(self, source_id: ua.NodeId, period, count=None):
        """Mark a node as historizing events."""
        if source_id not in self._events:
            self._events[source_id] = deque()
        self._retention_period = period
        self._retention_count = count  # Store retention count
        logging.debug(f"CustomHistoryManager.historize_event: Marked node {source_id} for event historization with period={period}, count={count}")

    def is_historizing_events(self, source_id: ua.NodeId):
        """Check if a node is historizing events."""
        return source_id in self._events

    async def save_event(self, source_id: ua.NodeId, event_data: dict):
            async with self._lock:
                try:
                    logging.debug(f"CustomHistoryManager.save_event: Event data for {source_id}: {event_data}")
                    # Convert event_data fields to ua.Variant with appropriate VariantType
                    validated_event_data = {}
                    for key, value in event_data.items():
                        try:
                            # Handle known types directly
                            if isinstance(value, ua.Variant):
                                validated_event_data[key] = value
                            elif isinstance(value, datetime):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.DateTime)
                            elif isinstance(value, str):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.String)
                            elif isinstance(value, bool):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.Boolean)
                            elif isinstance(value, int):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.Int32)
                            elif isinstance(value, float):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.Float)
                            elif isinstance(value, bytes):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.ByteString)
                            elif isinstance(value, ua.NodeId):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.NodeId)
                            elif isinstance(value, ua.LocalizedText):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.LocalizedText)
                            elif isinstance(value, ua.TimeZoneDataType):
                                validated_event_data[key] = ua.Variant(value, ua.VariantType.ExtensionObject)
                            elif value is None:
                                validated_event_data[key] = ua.Variant(None, ua.VariantType.Null)
                            else:
                                # Fallback for unsupported types
                                logging.warning(f"CustomHistoryManager.save_event:Unsupported type for {key}: {type(value)}, value: {value}, converting to string")
                                validated_event_data[key] = ua.Variant(str(value), ua.VariantType.String)
                        except Exception as e:
                            logging.error(f"CustomHistoryManager.save_event:Error processing {key}: {str(e)}, value: {value}")
                            validated_event_data[key] = ua.Variant(str(value), ua.VariantType.String)

                    if source_id not in self._events:
                        self._events[source_id] = []
                    self._events[source_id].append(validated_event_data)
                    logging.debug(f"CustomHistoryManager.save_event: Saved event for {source_id}, total events: {len(self._events[source_id])}")
                except Exception as e:
                    logging.error(f"CustomHistoryManager.save_event: Failed to save event for {source_id}: {str(e)}")
                    raise
   
    async def read_event_history(self, source_id: ua.NodeId, params: ua.HistoryReadParameters):
                # logging.debug(f"CustomHistoryManager.read_event_history.read_event_history: Processing params: {params}")
                # logging.debug(f"CustomHistoryManager.read_event_history : EventFilter SelectClauses: {[str(clause) for clause in params.HistoryReadDetails.Filter.SelectClauses]}")
                # logging.debug(f"CustomHistoryManager.read_event_history :EventFilter WhereClause: {params.HistoryReadDetails.Filter.WhereClause}")
                async with self._lock:
                    if source_id not in self._events:
                        logging.debug(f"CustomHistoryManager.read_event_history : read_event_history: No events for {source_id}")
                        return ua.HistoryData(DataValues=[])

                    select_clauses = params.HistoryReadDetails.Filter.SelectClauses
                    start_time = params.HistoryReadDetails.StartTime
                    end_time = params.HistoryReadDetails.EndTime
                    events = []

                    for event_data in self._events[source_id]:
                        event_time = event_data.get("EventTime")
                        if not isinstance(event_time, ua.Variant) or event_time.VariantType != ua.VariantType.DateTime:
                            logging.error(f"CustomHistoryManager.read_event_history : Invalid EventTime in event data: {event_time}")
                            continue

                        # Ensure event_time.Value is offset-aware
                        event_time_value = event_time.Value
                        if event_time_value.tzinfo is None:
                            event_time_value = event_time_value.replace(tzinfo=datetime.UTC)

                        # Compare with start_time and end_time
                        if start_time <= event_time_value <= end_time:
                            event_fields = []
                            for clause in select_clauses:
                                browse_path = [qname.Name for qname in clause.BrowsePath]
                                field_key = "/".join(browse_path) if browse_path else None
                                
                                # Handle empty BrowsePath
                                if not browse_path:
                                    if clause.TypeDefinitionId == ua.NodeId(Identifier=6, NamespaceIndex=2):
                                        if clause.AttributeId == 1:  # NodeId
                                            value = ua.Variant(source_id, ua.VariantType.NodeId)
                                        elif clause.AttributeId == 13:
                                            value = ua.Variant(ua.NodeId(Identifier=6, NamespaceIndex=2), ua.VariantType.NodeId)
                                        else:
                                            value = ua.Variant(None, ua.VariantType.Null)
                                    elif clause.TypeDefinitionId == ua.NodeId(Identifier=2782, NamespaceIndex=0):  # SimpleEventType
                                        if clause.AttributeId == 1:  # NodeId
                                            value = ua.Variant(source_id, ua.VariantType.NodeId)
                                        else:
                                            value = ua.Variant(None, ua.VariantType.Null)
                                    else:
                                        logging.warning(f"CustomHistoryManager.read_event_history : Unhandled TypeDefinitionId with empty BrowsePath: {clause}")
                                        value = ua.Variant(None, ua.VariantType.Null)
                                elif clause.TypeDefinitionId == ua.NodeId(Identifier=6, NamespaceIndex=2):
                                    if clause.AttributeId == 13:
                                        value = event_data.get(field_key, ua.Variant(None, ua.VariantType.Null))
                                    elif clause.AttributeId == 1:  # NodeId
                                        value = ua.Variant(source_id, ua.VariantType.NodeId)
                                    else:
                                        value = ua.Variant(None, ua.VariantType.Null)
                                elif clause.TypeDefinitionId == ua.NodeId(Identifier=2041, NamespaceIndex=2):  # BaseEventType
                                    if clause.AttributeId == 13:
                                        value = event_data.get(field_key, ua.Variant(None, ua.VariantType.Null))
                                    elif clause.AttributeId == 1:  # NodeId
                                        value = ua.Variant(source_id, ua.VariantType.NodeId)
                                    else:
                                        value = ua.Variant(None, ua.VariantType.Null)
                                elif clause.TypeDefinitionId == ua.NodeId(Identifier=2041, NamespaceIndex=0):  # BaseEventType
                                    if clause.AttributeId == 13:
                                        if browse_path == ["EventType"]:
                                           # value = ua.Variant(ua.NodeId(Identifier=6, NamespaceIndex=2), ua.VariantType.NodeId)
                                            value = ua.Variant(ua.NodeId(Identifier=6, NamespaceIndex=2), ua.VariantType.NodeId)
                                        elif browse_path == ["SourceNode"]:
                                            value = ua.Variant(ua.NodeId(Identifier=5, NamespaceIndex=2), ua.VariantType.NodeId)
                                        elif browse_path == ["SourceName"]:
                                            value = event_data.get("Node", ua.Variant(str(source_id), ua.VariantType.String))
                                        elif browse_path == ["Message"]:
                                            value = ua.Variant(f"✅ Event {event_data['Module']} {event_data['Attribute']}", ua.VariantType.String)
                                        elif browse_path == ["Time"]:
                                            value = event_data.get("EventTime", ua.Variant(datetime.datetime.now(tz=datetime.timezone.utc), ua.VariantType.DateTime))
                                        elif browse_path == ["ReceiveTime"]:
                                            value = ua.Variant(datetime.datetime.now(tz=datetime.timezone.utc), ua.VariantType.DateTime)
                                        elif browse_path == ["LocalTime"]:
                                            value = ua.Variant(ua.TimeZoneDataType(Offset=0, DaylightSavingInOffset=False), ua.VariantType.ExtensionObject)
                                        elif browse_path == ["EnabledState"]:
                                            value = ua.Variant(ua.LocalizedText(Text="Enabled"), ua.VariantType.LocalizedText)
                                        elif browse_path == ["EnabledState","Id"]:
                                            value = ua.Variant(True, ua.VariantType.Boolean)
                                        elif browse_path == ["ConditionClassId"]:
                                            value = ua.Variant(ua.NodeId(Identifier=0, NamespaceIndex=0), ua.VariantType.NodeId)
                                        elif browse_path == ["ConditionClassName"]:
                                            value = ua.Variant(ua.LocalizedText(Text="DefaultCondition"), ua.VariantType.LocalizedText)
                                        elif browse_path == ["ConditionName"]:
                                            value = ua.Variant(ua.LocalizedText(Text="DefaultCondition"), ua.VariantType.LocalizedText)
                                     
                                        elif browse_path == ["AckedState"]:
                                            value = ua.Variant(ua.LocalizedText(Text="Acknowledged"), ua.VariantType.LocalizedText)
                                      
                                        elif browse_path == ["AckedState","Id"]:
                                            value = ua.Variant(True, ua.VariantType.Boolean)
                                        elif browse_path == ["Retain"]:
                                            value = ua.Variant(False, ua.VariantType.Boolean)
                                        elif browse_path == ["ConfirmedState"]:
                                            value = ua.Variant(ua.LocalizedText(Text="Confirmed"), ua.VariantType.LocalizedText)
                                        elif browse_path == ["ConfirmedState","Id"]:
                                            value = ua.Variant(True, ua.VariantType.Boolean)
                                        elif browse_path == ["ActiveState"]:
                                            state = event_data.get("State", "INACT/ACK")
                                            active = "Active" if state in ["ACT/UNACK", "ACT/ACK"] else "Inactive"
                                            value = ua.Variant(ua.LocalizedText(Text=active), ua.VariantType.LocalizedText)
                                        elif browse_path == ["ActiveState","Id"]:
                                            state = event_data.get("State", "INACT/ACK")
                                            value = ua.Variant("ACTIVE" in ["ACT/UNACK", "ACT/ACK"], ua.VariantType.Boolean)
                                        elif browse_path == ["ActiveState","EffectiveDisplayName"]:
                                            state = event_data.get("State", "INACT/ACK")
                                            active = "Active" if state in ["ACT/UNACK", "ACT/ACK"] else "Inactive"
                                            value = ua.Variant(ua.LocalizedText(Text=active), ua.VariantType.LocalizedText)
                                        elif browse_path == ["Severity"]:
                                            value = ua.Variant(event_data.get("Severity", 0), ua.VariantType.UInt32)
                                       
                                        elif field_key in event_data.keys():
                                            value = event_data.get(field_key, ua.Variant(None, ua.VariantType.Null))
                                        else:
                                            value = ua.Variant(None, ua.VariantType.Null)
                                    elif clause.AttributeId == 1:  # NodeId
                                        value = ua.Variant(source_id, ua.VariantType.NodeId)
                                    else:
                                        value = ua.Variant(None, ua.VariantType.Null)
                                elif clause.TypeDefinitionId == ua.NodeId(Identifier=2782, NamespaceIndex=0):  # SimpleEventType
                                    if clause.AttributeId == 13:
                                        value = ua.Variant(None, ua.VariantType.Null)
                                    elif clause.AttributeId == 1:  # NodeId
                                        value = ua.Variant(source_id, ua.VariantType.NodeId)
                                    else:
                                        value = ua.Variant(None, ua.VariantType.Null)
                                else:
                                    value = ua.Variant(None, ua.VariantType.Null)
                                event_fields.append(value)
                            events.append(ua.EventFieldList(EventFields=event_fields))

                    logging.debug(f"CustomHistoryManager.read_event_history: Retrieved {len(events)} events for {source_id}")
                    if not events:
                        return ua.HistoryData(DataValues=[])

                    # 构造 DataValue 列表，设置时间戳
                    data_values = []
                    for event in events:
                        time_field = None
                        receive_time_field = None
                        for i, clause in enumerate(select_clauses):
                            browse_path = [qname.Name for qname in clause.BrowsePath]
                            if browse_path == ["Time"]:
                                time_field = event.EventFields[i]
                            elif browse_path == ["ReceiveTime"]:
                                receive_time_field = event.EventFields[i]
                        
                        source_timestamp = time_field.Value if time_field and time_field.VariantType == ua.VariantType.DateTime else datetime.datetime.now(tz=datetime.UTC)
                        if source_timestamp.tzinfo is None:
                                 source_timestamp = source_timestamp.replace(tzinfo=datetime.UTC)
                        server_timestamp = receive_time_field.Value if receive_time_field and receive_time_field.VariantType == ua.VariantType.DateTime else datetime.datetime.now(tz=datetime.UTC)
                        if server_timestamp.tzinfo is None:
                                 server_timestamp = server_timestamp.replace(tzinfo=datetime.UTC)
                        data_value = ua.DataValue(
                            Value=ua.Variant(event, ua.VariantType.ExtensionObject),
                            SourceTimestamp=source_timestamp,
                            ServerTimestamp=server_timestamp
                        )
                        data_values.append(data_value)

                    history_data = ua.HistoryData(DataValues=data_values)
                    #logging.debug(f"CustomHistoryManager.read_event_history : DataValues: {[f'SourceTimestamp={dv.SourceTimestamp}, ServerTimestamp={dv.ServerTimestamp}' for dv in data_values]}")
                    return history_data

    async def read_data_history(self, node_id: ua.NodeId, params: ua.HistoryReadParameters):
        logging.debug(f"CustomHistoryManager.read_data_history: Reading data for {node_id}")
        details = params.HistoryReadDetails
        start_time = details.StartTime
        end_time = details.EndTime
        num_values = details.NumValuesPerNode
       

        item_id = None
        for item_path, node in self._wrapper.node.nodes.items():
            if node.nodeid == node_id:
                item_id = item_path
                break

        if not item_id:
            logging.error(f"CustomHistoryManager.read_data_history: No OPCHDA ItemID found for NodeId {node_id}")
            return ua.HistoryData(DataValues=[])

        try:
            

           

            results = await asyncio.get_running_loop().run_in_executor(
                    self.opchda_executor,
                    lambda: self.read_opchda(item_id, start_time, end_time, num_values)
                )
            if results is None:
                      return ua.HistoryData(DataValues=[])
            data_values = []
          
                  
            item_data = results.get(item_id, {"values": [], "qualities": [], "timestamps": []})
            for value, quality, timestamp in zip(
                item_data["values"], item_data["qualities"], item_data["timestamps"]
            ):
                if isinstance(timestamp, datetime.datetime):
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=datetime.UTC)
                    timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp = datetime.datetime.fromtimestamp(
                            timestamp.timestamp(), tz=datetime.UTC
                        )
                    timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                 # 根据值的类型创建 UA 节点
                if isinstance(value, float):
                    variant_type = ua.VariantType.Double
                    initial_value = float(value)
                elif isinstance(value, str):
                    variant_type = ua.VariantType.String
                    initial_value = str(value)
                elif isinstance(value, int):
                    variant_type = ua.VariantType.Int32
                    initial_value = int(value)
                elif isinstance(value, bool):
                    variant_type = ua.VariantType.Boolean
                    initial_value = bool(value)
                else:
                    variant_type = ua.VariantType.String
                    initial_value = str(value)
                

                status = ua.StatusCode(ua.StatusCodes.Good) if quality > 127 else ua.StatusCode(ua.StatusCodes.Bad)
                data_value = ua.DataValue(
                    Value=ua.Variant(initial_value,variant_type),
                    StatusCode_=status,
                    SourceTimestamp=timestamp,
                    ServerTimestamp=datetime.datetime.now(datetime.UTC)
                )
                data_values.append(data_value)

            logging.debug(f"CustomHistoryManager.read_data_history: Retrieved {len(data_values)} data points for {node_id} (ItemID: {item_id})")
            return ua.HistoryData(DataValues=data_values)
        except Exception as e:
            logging.error(f"CustomHistoryManager.read_data_history: Failed to read OPCHDA data for {item_id}: {str(e)}")
            return ua.HistoryData(DataValues=[])
    async def read_history(self, params: ua.HistoryReadParameters):
        logging.debug(f"CustomHistoryManager.read_history: Processing params: {params}")
        if not params.NodesToRead:
            logging.warning("CustomHistoryManager.read_history: No nodes to read in HistoryReadParameters")
            return []

        results = []
        for node in params.NodesToRead:
            node_id = node.NodeId
            try:
                if isinstance(params.HistoryReadDetails, ua.ReadEventDetails):
                    history_data = await self.read_event_history(node_id, params)
                else:
                    history_data = await self.read_data_history(node_id, params)
                if not isinstance(history_data, ua.HistoryData):
                    logging.error(f"CustomHistoryManager.read_history: Invalid HistoryData returned for {node_id}: {type(history_data)}")
                    history_data = ua.HistoryData(DataValues=[])
                result = ua.HistoryReadResult(
                    StatusCode_=ua.StatusCode(ua.StatusCodes.Good),
                    ContinuationPoint_=None,
                    HistoryData=history_data
                )
                logging.debug(f"CustomHistoryManager.read_history: Created HistoryReadResult for {node_id}: StatusCode={result.StatusCode_.name}")
            except Exception as e:
                logging.error(f"CustomHistoryManager.read_history: Failed to read history for {node_id}: {str(e)}")
                result = ua.HistoryReadResult(
                    StatusCode_=ua.StatusCode(ua.StatusCodes.BadInternalError),
                    ContinuationPoint_=None,
                    HistoryData=ua.HistoryData(DataValues=[])
                )
            results.append(result)
        logging.debug(f"CustomHistoryManager.read_history: Returning {len(results)} HistoryReadResults")
        return results
   

              
    async def read_raw_history(self,parent, json_variant):
            userrole = await self._wrapper.security._get_current_userrole()
            if not self._wrapper.user_manager.check_method_permission(50, userrole):
                    logging.warning(f"CustomHistoryManager.query_event_history: Unauthorized attempt to query event history")
                    await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to query event history")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
         
            try:
                json_input = json_variant.Value
                logging.debug(f"CustomHistoryManager.sync_read_raw_history: Called with input: {json_input}")
                input_data = json.loads(json_input)
                item_ids = input_data.get("item_ids", [])
                max_values = input_data.get("max_values", 0)
                start_time_str = input_data.get("start_time")
                end_time_str = input_data.get("end_time")

                if not item_ids or not start_time_str or not end_time_str:
                    raise ValueError("CustomHistoryManager.sync_read_raw_history:Missing required fields: item_ids, start_time, or end_time")

                start_time = datetime.datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                #start_time = start_time.replace(tzinfo=datetime.UTC)
                end_time = datetime.datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
                #end_time = end_time.replace(tzinfo=datetime.UTC)

              
                results = await asyncio.get_running_loop().run_in_executor(
                    self.opchda_executor,
                    lambda: self.sync_read_opchda(item_ids, start_time, end_time, max_values)
                )
                if results is None:
                      return [ua.Variant("", ua.VariantType.String)]
                output = {}
                for item_id in item_ids:
                    data_points = []
                    item_data = results.get(item_id, {"values": [], "qualities": [], "timestamps": []})
                    for value, quality, timestamp in zip(
                        item_data["values"], item_data["qualities"], item_data["timestamps"]
                    ):
                        if isinstance(timestamp, datetime.datetime):
                            if timestamp.tzinfo is None:
                                timestamp = timestamp.replace(tzinfo=datetime.UTC)
                            timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            timestamp = datetime.datetime.fromtimestamp(
                                    timestamp.timestamp(), tz=datetime.UTC
                                )
                            timestamp_num = timestamp.timestamp()  # 输出数字时间戳
                            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                        quality_str =quality 
                        data_points.append({
                            "value": value,
                            "quality": quality,
                            "timestamp": timestamp_num,
                            "Time": timestamp_str
                        })
                    output[item_id] = data_points

                json_output= json.dumps(output, ensure_ascii=False)
                return [ua.Variant(json_output, ua.VariantType.String)]
            except Exception as e:
                logging.error(f"CustomHistoryManager.sync_read_raw_history:SyncReadRawHistory failed: {str(e)}")
                return [ua.Variant("", ua.VariantType.String)]
    async def update_events(self, events):
           
                Severity_map = {
                    "4-INFO": 4,
                    "10-UNIT_WARN": 600,
                    "14-UNIT_CRIT": 900,
                    "06-UNIT_ADVIS": 100,
                    "12-PROMPT": 12,
                    "3-LOG": 3,
                    "13-CRITICAL_ACT": 700,
                    "15-CRITICAL": 800,
                    "7-ADVISORY": 90,
                    "11-WARNING": 500,
                    "CRITICAL": 800,
                    "WARNING": 400,
                    "ADVISORY": 80,
                    "INFO": 4,
                    "LOG": 3
                }

                for node_id in list( self._wrapper.node.event_nodes.keys()):
                    try:
                        condition_node = self._wrapper.node.event_nodes[node_id]
                        if hasattr(condition_node, 'nodeid'):
                            await self._wrapper.server.delete_nodes([condition_node], recursive=True)
                            del self._wrapper.node.event_nodes[node_id]
                            logging.debug(f"CustomHistoryManager.update_events:Deleted existing condition node {node_id}")
                    except ua.UaStatusCodeError as e:
                        logging.warning(f"CustomHistoryManager.update_events:Failed to delete condition node {node_id}: {str(e)}")
              
                for event in events:
                
                    event_id = f"{event['Module']}_{event['Ord']}"
                    EventId = ua.Variant(event_id.encode(), ua.VariantType.ByteString)
                    event_time = event["EventTime"] if isinstance(event["EventTime"], datetime.datetime) else datetime.datetime.strptime(event["EventTime"], "%Y-%m-%d %H:%M:%S")
                    event_severity=ua.Variant(int(Severity_map.get(event["Level"], 100)), ua.VariantType.UInt32)
                    event_data = {
                                "EventId": EventId,
                                "EventTime": ua.Variant(event_time, ua.VariantType.DateTime),
                                "Category": ua.Variant(event.get("Category", ""), ua.VariantType.String),
                                "Event_Type" :  ua.Variant(event.get("Event_Type", ""), ua.VariantType.String),
                                "Area": ua.Variant(event.get("Area", ""), ua.VariantType.String),
                                "Node": ua.Variant(event.get("Node", ""), ua.VariantType.String),
                                "Module": ua.Variant(event.get("Module", ""), ua.VariantType.String),
                                "ModuleDescription": ua.Variant(event.get("ModuleDescription", ""), ua.VariantType.String),
                                "Attribute": ua.Variant(event.get("Attribute", ""), ua.VariantType.String),
                                "State": ua.Variant(event.get("State", ""), ua.VariantType.String),
                                "Level": ua.Variant(event.get("Level", ""), ua.VariantType.String),
                                "Parameter": ua.Variant(event.get("Parameter", ""), ua.VariantType.String),
                                "Description": ua.Variant(event.get("Description", ""), ua.VariantType.String),
                                "Severity": event_severity                      
                               
                            }
                    
                    if event_data is not None:
                            await self.save_event( self._wrapper.node.events_node.nodeid,event_data)

                    try:
                        if event['Event_Type'] == "ALARM":
                            
                            is_active = event["State"]  in ["ACT/UNACK", "ACT/ACK"]
                            is_acknowledged=event["State"] in [ "ACT/ACK","INACT/ACK",'DISABLED']
                            is_enabled=(event["State"] != 'DISABLED')
                            is_confirmed= ua.Variant((int(Severity_map.get(event["Level"], 100)) <= 100), ua.VariantType.Boolean)
                            condition_node = await self._wrapper.node.events_node.add_object( self._wrapper.node.idx, f"Condition_{event_id}", objecttype= self._wrapper.node.alarm_type)
                            
                            self._wrapper.node.event_nodes[event_id] = condition_node
                            condition_id = ua.NodeId(f"Condition_{event_id}", self._wrapper.node.idx)
                            
                   
                            for name, value in  event_data.items():
                                prop_node = None
                                for child in await condition_node.get_children():
                                    browse_name = await child.read_browse_name()
                                    if browse_name.Name == name:
                                        prop_node = child
                                        break
                                if prop_node:
                             
                                        await prop_node.write_value(value)
                                else:
                                  
                                        prop_node = await condition_node.add_property( self._wrapper.node.idx, name, value)
                            now = datetime.datetime.now(datetime.UTC)
                            standard_properties = {
                              
                                "ConditionId": condition_id,  
                           
                                "SourceNode": ua.Variant( self._wrapper.node.events_node.nodeid, ua.VariantType.NodeId),
                                
                                "EventType": ua.Variant( self._wrapper.node.alarm_type.nodeid, ua.VariantType.NodeId),
                               
                                "InputNode" : ua.Variant( self._wrapper.node.events_node.nodeid, ua.VariantType.NodeId),
                           
                              
                                "ConditionName":ua.Variant(f"Alarm_{event_id}", ua.VariantType.String),
                                "ConditionClassId":  ua.NodeId(ua.ObjectIds.BaseConditionClassType),      
                                "ConditionClassName":  ua.LocalizedText("DeltaVAlarmClass") ,   
                                "BranchId": ua.NodeId(ua.ObjectIds.Null),
                                "Time": now,
                                "ReceiveTime": now,
                                "LocalTime" :ua.TimeZoneDataType(Offset=0, DaylightSavingInOffset=False),                             
                                "ConditionClass": ua.LocalizedText("Process"),
                                "CurrentState": ua.LocalizedText("Alarm"),
                                "LastTranistion": ua.LocalizedText("Event"),
                                "BranchId": ua.NodeId(),
                                "AudibleEnabled": ua.Variant(False, ua.VariantType.Boolean),
                                "SuppressedOrShelved": ua.Variant(False, ua.VariantType.Boolean),                    
                                "OnDealy": ua.Variant(0.0, ua.VariantType.Float),
                                "OffDealy": ua.Variant(0.0, ua.VariantType.Float),
                                "UnShelveTime": ua.Variant(0.0, ua.VariantType.Float),                              
                                "ReAlarmRepeatCount": ua.Variant(0, ua.VariantType.Int16),
                                "ReAlarmTime": ua.Variant(2.0, ua.VariantType.Float),
                                "Message": ua.LocalizedText(f"🔥 Alarm  {event['Module']} {event['Attribute']}"),
                                "ActiveState":  ua.LocalizedText("Active" if is_active else "InActive"),    
                                "AckedState":  ua.LocalizedText("Acknowledged" if is_acknowledged else "Unacknowledged"),
                                "AckedState/Id":  ua.Variant(is_acknowledged, ua.VariantType.Boolean),
                                "ActiveState/Id":  ua.Variant(is_active, ua.VariantType.Boolean),
                                "EnabledState": ua.LocalizedText("Enabled" if is_enabled else "Dsiabled"),
                                "EnabledState/Id":  ua.Variant(is_enabled, ua.VariantType.Boolean),
                                "OutOfServiceState": ua.LocalizedText("InService"),
                                "SilenceState": ua.LocalizedText("Silence"),
                                "SuppressedState": ua.LocalizedText("UnSuppressed"),
                                "LatchedState": ua.LocalizedText("Unlatched"),
                                #"ConfirmedState": ua.LocalizedText("Confirmed" if is_confirmed else "UnConfirmed"),
                                "ConfirmedState/Id":  ua.Variant(is_confirmed, ua.VariantType.Boolean),
                            
                                "Retain":  ua.Variant(is_active, ua.VariantType.Boolean)                                          
                            }
                      
                            for name, value in standard_properties.items():
                                prop_node = None
                                for child in await condition_node.get_children():
                                    browse_name = await child.read_browse_name()
                                    if browse_name.Name == name:
                                        prop_node = child
                                        break
                                if prop_node:                              
                                        await prop_node.write_value(value)
                        
                            event_generator = await self._wrapper.server.get_event_generator( self._wrapper.node.alarm_type, self._wrapper.node.events_node)
                     
                            event_data.update(standard_properties)

                            for name, value in event_data.items():
                                setattr(event_generator.event, name, value)                          
                            await event_generator.trigger()
                            logging.debug(f"CustomHistoryManager.update_events:Triggered condition alarm for {event_id}")

                        else:

                            standard_properties = {                                                                   
                                "SourceNode" :  ua.Variant( self._wrapper.node.events_node.nodeid, ua.VariantType.NodeId),           
                                "EventType" : ua.Variant( self._wrapper.node.event_type.nodeid, ua.VariantType.NodeId), 
                             
                                "Message" : ua.LocalizedText(f"✅ Event {event['Module']} {event['Attribute']}")                             
                              
                            }
                         
                            event_generator = await self._wrapper.server.get_event_generator( self._wrapper.node.event_type, self._wrapper.node.events_node)
                            event_data.update(standard_properties)
                       
                            for name, value in event_data.items():

                                setattr(event_generator.event, name, value)                    
                            #event_generator.event.Retain = True  # Ensure event is retained for history
                            await event_generator.trigger()
                            logging.debug(f"CustomHistoryManager.update_events:Triggered event {event_id}")
                         # Save to history
                    
                    except Exception as e:
                        logging.error(f"CustomHistoryManager.update_events:Failed to process {event_id}: {str(e)}")
                        raise

              
    async def periodic_event_update(self,server_name="localhost"):
                #sql_client = EventChronicleClient(server="10.4.0.6,55114", instance="DELTAV_CHRONICLE")
                filters=self.period_event_filters
                sql_client = EventChronicleClient(server=server_name, instance="DELTAV_CHRONICLE")
                # 用于存储上一次检查时的事件状态
               
                try:
                  
                    sql_client.connect()
                    while not self._wrapper.event.shutdown.is_set():
                       
                        try:
                            events = sql_client.fetch_events(seconds_back=5,filters=filters)
                            if events:
                                
                                await self.update_events(events)

                               
                            #logging.debug("CustomHistoryManager.periodic_event_update: Periodic event update completed")
                            await asyncio.sleep(self._event_update_rate)  
                        except Exception as e:
                            logging.error(f"CustomHistoryManager.periodic_event_update: Error in periodic event update: {str(e)}")
                            await asyncio.sleep(self._event_update_rate)  
                        
                except Exception as e:
                    logging.error(f"CustomHistoryManager.periodic_event_update: Failed to initialize event update: {str(e)}")
                finally:
                    sql_client.disconnect()
                   
                    #logging.debug("CustomHistoryManager.periodi: Event update SQL client disconnected")
       
    async def _create_events_nodes(self,events):
        
        for node_id in list( self._wrapper.node.event_nodes.keys()):
            try:
                child_node = await self._wrapper.node.events_node.get_child(f"{ self._wrapper.node.idx}:{node_id}")
                await self._wrapper.node.events_node.delete_nodes([child_node], recursive=True)
            except Exception as e:
                logging.warning(f"CustomHistoryManager._create_events_nodes:Failed to delete node {node_id}: {str(e)}")
        self._wrapper.node.event_nodes.clear()

        for event in events:

            event_id = f"{event['Module']}_{event['Ord']}"
            try:
                event_node = await self._wrapper.node.events_node.add_object( self._wrapper.node.idx, event_id)
                self._wrapper.node.event_nodes[event_id] = {
                    "EventTime": await event_node.add_variable( self._wrapper.node.idx, "EventTime", event["EventTime"]),
                    "EventType": await event_node.add_variable( self._wrapper.node.idx, "EventType", event["Event_Type"]),
                    "Category": await event_node.add_variable( self._wrapper.node.idx, "Category", event["Category"]),
                    "Area": await event_node.add_variable( self._wrapper.node.idx, "Area", event["Area"]),
                    "Node": await event_node.add_variable( self._wrapper.node.idx, "Node", event["Node"]),
                    "Module": await event_node.add_variable( self._wrapper.node.idx, "Module", event["Module"]),
                    "ModuleDescription": await event_node.add_variable( self._wrapper.node.idx, "ModuleDescription", event["ModuleDescription"]),
                    "Attribute": await event_node.add_variable( self._wrapper.node.idx, "Attribute", event["Attribute"]),
                    "State": await event_node.add_variable( self._wrapper.node.idx, "State", event["State"]),
                    "Level": await event_node.add_variable( self._wrapper.node.idx, "Level", event["Level"]),
                    "Parameter": await event_node.add_variable( self._wrapper.node.idx, "Parameter", event["Parameter"]),
                    "Description": await event_node.add_variable( self._wrapper.node.idx, "Description", event["Description"])
                }
                for key, node in self._wrapper.node.event_nodes[event_id].items():
                    await node.set_value(event[key])
            except Exception as e:
                logging.error(f"CustomHistoryManager._create_events_nodes:Failed to add event node {event_id}: {str(e)}")

    async def filter_event_history(self, filters: Optional[Dict] = None,server_name:str="localhost"):
                    """Read historical events for a node"""
                    sql_client = EventChronicleClient(server=server_name, instance="DELTAV_CHRONICLE")
                    try:
                        if filters is None:
                            now = datetime.datetime.now(datetime.UTC)
                            filters = {
                                "start_time": now - datetime.timedelta(minutes=10),
                                "end_time": now
                            }
                        logging.debug(f"CustomHistoryManager.filter_event_history: Querying events with filters: {filters}")
                        sql_client.connect()
                        events = sql_client.filter_events(filters=filters)  # Use fetch_events instead of fiters_events
                        logging.debug(f"CustomHistoryManager.filter_event_history: Retrieved {len(events)} events ")
                        return events
                    except Exception as e:
                        logging.error(f"CustomHistoryManager.filter_event_history: Failed to retrieve events: {str(e)}")
                        return []
                    finally:
                        sql_client.disconnect()
                        logging.debug("CustomHistoryManager.filter_event_history: SQL client disconnected")

    async def query_event_history(self, parent, filters_variant) -> list:
                """
                OPC UA Method: Query historical events based on filters.
                Inputs:
                    filters (String): JSON string containing filters, e.g., {"Category": ["PROCESS","USER"], ...}.
                                    If empty, uses default filters (last 10 minutes).
                Returns:
                    [String]: JSON string containing the list of events.
                """
                userrole = await self._wrapper.security._get_current_userrole()
                if not self._wrapper.user_manager.check_method_permission(50, userrole):
                    logging.warning(f"CustomHistoryManager.query_event_history: Unauthorized attempt to query event history")
                    await self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to query event history")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

                try:
                    # Parse filters from JSON string
                    filters_str = filters_variant.Value
                    filters = None
                    if filters_str:
                        try:
                            filters = json.loads(filters_str)
                            # Validate and convert datetime strings to datetime objects if present
                            # if "start_time" in filters and isinstance(filters["start_time"], str):
                            #     filters["start_time"] = datetime.datetime.fromisoformat(filters["start_time"].replace("Z", "+00:00"))
                            # if "end_time" in filters and isinstance(filters["end_time"], str):
                            #     filters["end_time"] = datetime.datetime.fromisoformat(filters["end_time"].replace("Z", "+00:00"))
                        except json.JSONDecodeError as e:
                            logging.error(f"CustomHistoryManager.query_event_history: Invalid JSON filters: {str(e)}")
                            await self._wrapper.node.last_error_desc.write_value(f"Invalid JSON filters: {str(e)}")
                            return [ua.Variant("", ua.VariantType.String)]
                        except ValueError as e:
                            logging.error(f"CustomHistoryManager.query_event_history: Invalid datetime format in filters: {str(e)}")
                            await  self._wrapper.node.last_error_desc.write_value(f"Invalid datetime format in filters: {str(e)}")
                            return [ua.Variant("", ua.VariantType.String)]

                    logging.debug(f"CustomHistoryManager.query_event_history: Querying events with filters: {filters}")
                    events = await self.filter_event_history(filters)
                    # Convert events to JSON for return
                    events_json = json.dumps(events, default=lambda x: x.isoformat() if isinstance(x, datetime.datetime) else str(x))
                    logging.debug(f"CustomHistoryManager.query_event_history: Found {len(events)} events")
                    return [ua.Variant(events_json, ua.VariantType.String)]

                except Exception as e:
                    logging.error(f"CustomHistoryManager.query_event_history: Error querying events: {str(e)}")
                    await self._wrapper.node.last_error_desc.write_value(f"Error querying events: {str(e)}")
                    return [ua.Variant("", ua.VariantType.String)]

    async def stop(self):

        """Clean up resources."""
        async with self._lock:
            self._events.clear()
        logging.debug("CustomHistoryManager: Stopped and cleared events")

class _OPCDAWrapper_:

    class Event:
        def __init__(self):
            self.running = asyncio.Event()
            
            self.polling = asyncio.Event()
            self.writing = asyncio.Event()
            self.shutdown = asyncio.Event()
            self.restart = asyncio.Event()
            self.broswe_opcda_struture = asyncio.Event()
            self.update_structure = asyncio.Event()  

    class Node:
        def __init__(self,name:str= 'OPCUA Server', nodename:str ='localhost',endpoint: str = 'opc.tcp://0.0.0.0:4840',application_uri:str='OPC.DELTAV.1'):
            self.endpoint = endpoint   
            self.name = name
            self.nodename = nodename
            self.application_uri = application_uri
            self.idx = None
            self.da_folder = None
            self.cert_node = None
            self.nodes = {}  # Dict[str, ua.Node]
            self.folders = {}  # 新增: 用于存储文件夹节点
          
            self.events_node = None           
            self.event_nodes = {}
            self.alarm_type = None
            self.event_type = None
            self.historian_node = None
          

            self.last_error_code = None  # 用于存储错误状态的节点
            self.last_error_desc = None  # 用于存储错误状态的节点
        async def __get_server_info__(self):
             server_details = {
                "ServerName":  self.name,
                "NodeName":  self.nodname,
                "application_uri": self.application_uri,
                "idx": self.idx,
                "endpoint": self.endpoint,
                "version": '1.0.16',
                "VendorInfo": 'Juda.monster'
            }
    
        async def _get_node_path(self, node) -> str:
            """Helper to get the full path of a node based on self.node.folders."""
            for path, n in self.folders.items():
                if n.nodeid == node.nodeid:
                    return path
            # If not found in folders, use the browse name at the root level
            browse_name = await node.read_browse_name()
            return browse_name.Name if browse_name.NamespaceIndex == self.idx else ""
        
        def _get_folder_path_for_item(self, item_path: str, current_node_path: str) -> str:
            """Determine the intended folder path for an item based on self.node.folders."""
            # Find the longest matching folder path that this item belongs to
            item_parts = item_path.split('.')
            for folder_path in sorted(self.folders.keys(), key=len, reverse=True):
                if item_path.startswith(folder_path) and folder_path != item_path:
                    return folder_path
            # If no folder matches, it belongs at the current level or root
            return current_node_path
        
        async def _build_node_structure(self, node) -> Dict:
                structure = {}
                items_list = []  # To collect variables at this level
                children = await node.get_children()
                logging.debug(f"_build_node_structure: Node={await node.read_browse_name()}, Children={[await child.read_browse_name() for child in children]}")

                # Get the current node's path for comparison
                current_node_path = await self._get_node_path(node)

                for child in children:
                    child_name = await child.read_browse_name()
                    name = child_name.Name
                    node_class = await child.read_node_class()
                    logging.debug(f"_build_node_structure: Child={name}, NodeClass={node_class}")

                    if node_class == ua.NodeClass.Object:
                        # Recursively build sub-structure for folders
                        sub_structure = await self._build_node_structure(child)
                        if sub_structure:  # Only add non-empty sub-structures
                            structure[name] = sub_structure
                    elif node_class == ua.NodeClass.Variable:
                        # Find the full path from self.node.nodes
                        item_path = next((path for path, n in self.nodes.items() if n.nodeid == child.nodeid), name)
                        # Determine the intended folder path for this item
                        item_folder_path = self._get_folder_path_for_item(item_path, current_node_path)
                        
                        if item_folder_path == current_node_path or not item_folder_path:
                            # This item belongs directly at this level
                            if item_path not in items_list:
                                items_list.append(item_path)
                        else:
                            # Navigate to the correct sub-folder
                            relative_path = item_folder_path[len(current_node_path) + 1:] if current_node_path else item_folder_path
                            path_parts = relative_path.split('.')
                            current = structure
                            for part in path_parts:
                                if part not in current:
                                    current[part] = {}
                                current = current[part]
                            if "ITEMS" not in current:
                                current["ITEMS"] = []
                            if item_path not in current["ITEMS"]:
                                current["ITEMS"].append(item_path)

                if items_list:
                    structure["ITEMS"] = items_list

                logging.debug(f"_build_node_structure: Built structure={structure}")
                return structure
        


    

        


    def __init__(self,  name:str= 'OPC.DELTAV.1',nodename:str="PROPLUS", endpoint: str = 'opc.tcp://0.0.0.0:4840'):
        """init the server"""
        self.event = self.Event()
        self.node = self.Node(name=name,nodename=nodename,endpoint=endpoint,application_uri=name)
        self.security = CustomSecurity(wrapper=self)
        self.da_manager = CustomDAManager(wrapper=self,nodename=nodename) 
        self.user_manager = CustomUserManager()  # 强制初始化，避免 None
        self.server = Server(user_manager=self.user_manager)
        self.history_manager=CustomHistoryManager(wrapper=self)
        self.server.set_server_name(self.node.name)
        self.server.set_endpoint(self.node.endpoint)  # 设置端点
        logging.info(f"_OPCDAWrapper_.init: Server type: {type(self.server)}, iserver type: {type(self.server.iserver)},user_manager set to Custom user manager ")
        self.executor_browser = ThreadPoolExecutor(max_workers=2)
        self.executor_opcda = ThreadPoolExecutor(max_workers=2)
        self.executor_opchda = ThreadPoolExecutor(max_workers=2)
        self._max_time: float = 9999999
      
        self._manual_stop: bool = False
    @property
    def max_time(self):
        return self._max_time
   
    @property
    def manual_stop(self):
        return self._manual_stop
             
    async def _find_type_node(self,start_node, target_name, namespace_index=0, max_depth=5, current_depth=0):
                    """递归查找目标类型的节点"""
                    if current_depth > max_depth:
                        return None
                    try:
                        # 尝试直接获取目标类型
                        target_node = await start_node.get_child(f"{namespace_index}:{target_name}")
                        browse_name = await target_node.read_browse_name()
                        if browse_name.Name == target_name and browse_name.NamespaceIndex == namespace_index:
                            logging.debug(f"_OPCDAWrapper_._find_type_node: Found {target_name} via get_child at depth {current_depth}")
                            return target_node
                    except ua.UaStatusCodeError:
                        pass  # 子节点不存在，继续浏览

                    # 浏览子类型
                    references = await start_node.get_references(ua.ObjectIds.HasSubtype)
                    for ref in references:
                        subtype_node = self.server.get_node(ref.NodeId)
                        browse_name = await subtype_node.read_browse_name()
                        if browse_name.Name == target_name and browse_name.NamespaceIndex == namespace_index:
                            logging.debug(f"_OPCDAWrapper_._find_type_node: Found {target_name} via subtype browsing at depth {current_depth}")
                            return subtype_node
                        # 递归查找
                        result = await self._find_type_node(subtype_node, target_name, namespace_index, max_depth, current_depth + 1)
                        if result:
                            return result
                    return None
    async def setup_opc_ua_server(self):
     
        await self.server.init()
        uri = self.node.application_uri
        self.node.idx = await self.server.register_namespace(uri)
        await self.server.set_application_uri(uri)
        logging.debug(f"_OPCDAWrapper_.setup_opc_ua_server:Registered namespace index: {self.node.idx}")
        objects = self.server.nodes.objects
        self.node.da_folder = await objects.add_folder(self.node.idx, self.node.name)  
        
        


        logging.debug(f"_OPCDAWrapper_.setup_opc_ua_server:add foulder to self.node.da_folder: {self.node.idx}: {self.node.name}")


      
        self.server.iserver.history_manager = self.history_manager
        
        await self.server.iserver.history_manager.init()
        logging.debug("_OPCDAWrapper_.setup_opc_ua_server: Initialized CustomHistoryManager with OPCHDA")

       
       
        if not os.path.exists(self.security._initial_cert_path) or not os.path.exists(self.security._initial_key_path):
            logging.info("_OPCDAWrapper_.setup_opc_ua_server:init Certificate or key not found, generating new ones...")
            await self.security.generate_self_signed_cert(self.security._initial_cert_path, self.security._initial_key_path)
        
        
        
        self.server.set_security_IDs(["Anonymous", "Username"])  # 调整顺序，确保 Anonymous 在前
      

        self.node.cert_node = await self.node.da_folder.add_variable(
            self.node.idx, "ServerCertificate", b"", ua.VariantType.ByteString
        )

      
        cert_path = self.security._cert_path if os.path.exists(self.security._cert_path) else self.security._initial_cert_path
        key_path = self.security._key_path if os.path.exists(self.security._key_path) else self.security._initial_key_path

        # 加载证书和私钥
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            await self.server.load_certificate(cert_path)
        with open(key_path, "rb") as f:
            key_data = f.read()
            await self.server.load_private_key(key_path)
        await self.node.cert_node.write_value(cert_data)
        logging.info("_OPCDAWrapper_.setup_opc_ua_server: Server certificate loaded and available at ServerCertificate node")

       
       
        self.security.security_policies = [SecurityPolicy(), SecurityPolicyBasic256Sha256,SecurityPolicyAes256Sha256RsaPss,SecurityPolicyAes128Sha256RsaOaep]
        for policy in self.security.security_policies:
                    if policy != SecurityPolicy():
                        policy.ClientCertificateDir = self.security._trustedcert_dir


      
        self.node.last_error_code = await self.node.da_folder.add_variable(
            self.node.idx, "LastErrorStatus", 0, ua.VariantType.Int64
        )
        await self.node.last_error_code.set_writable()

        self.node.last_error_desc = await self.node.da_folder.add_variable(
            self.node.idx, "LastErrorDesc", "", ua.VariantType.String
        )
        await self.node.last_error_desc.set_writable()

       
        self.node.events_node = await self.node.da_folder.add_object(self.node.idx, "Alarms and Events")                                  
        await self.node.events_node.write_attribute(
                ua.AttributeIds.EventNotifier,
                ua.DataValue(ua.Variant(5, ua.VariantType.Byte))
            )
        # Enable history for the server
        #self.server.historize_node_event(self.node.events_node, period=None)  # None means store indefinitely
        # Store events for 1 hour
        await self.server.historize_node_event(self.node.events_node, period=datetime.timedelta(minutes=2))
        logging.info("_OPCDAWrapper_.setup_opc_ua_server: Enabled historical event storage for Alarms and Events node")
        await  self.history_manager.setup_event_type()
        self.node.historian_node = await self.node.da_folder.add_folder(self.node.idx, "Countinuous Historain")  
        logging.info("_OPCDAWrapper_.setup_opc_ua_server: Created Historian folder")

    
     

       

        # 添加方法并设置权限
        method_nodes = {
            "write_items": await self.node.da_folder.add_method(
                self.node.idx, "write_items",  self.da_manager.write_items,
                [ua.VariantType.Variant,ua.VariantType.String], [ua.VariantType.Boolean]
            ),
            "add_client_cert": await self.node.da_folder.add_method(
                self.node.idx, "add_client_cert", self.security.add_client_certificate,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "generate_server_certificate": await self.node.da_folder.add_method(
                self.node.idx, "generate_server_certificate", self.security.generate_server_certificate,
                [], [ua.VariantType.Boolean]
            ),
            "set_server_policy": await self.node.da_folder.add_method(
                self.node.idx, "set_server_policy", self.security.set_server_policy,
                [ua.VariantType.String, ua.VariantType.Boolean], [ua.VariantType.Boolean]
            ),
            "restore_initial_certificate": await self.node.da_folder.add_method(
                self.node.idx, "restore_initial_certificate", self.security.restore_initial_certificate,
                [], [ua.VariantType.Boolean]
            ),
             "get_connected_clients":await self.node.da_folder.add_method(
                                        self.node.idx, "get_connected_clients", self.security.get_connected_clients,
                                        [], [ua.VariantType.String]
             ),
             "disconnect_client": await self.node.da_folder.add_method(  
                self.node.idx, "disconnect_client", self.security.disconnect_client,
                [ua.VariantType.String], [ua.VariantType.Boolean]
            ),

            "restart_server": await self.node.da_folder.add_method(  
                self.node.idx, "restart_server", self.restart,
                [], [ua.VariantType.Boolean]
            ),
            
            "add_nodes_from_json": await self.node.da_folder.add_method(
                self.node.idx, "add_nodes_from_json", self.da_manager.add_nodes_from_json,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "export_nodes_to_json": await self.node.da_folder.add_method(
                self.node.idx, "export_nodes_to_json", self.da_manager.export_nodes_to_json,
                [], [ua.VariantType.String]
            ),


            "add_item": await self.node.da_folder.add_method(  
                self.node.idx, "add_item", self.da_manager.update_item,
                [ua.VariantType.String,ua.VariantType.Int32],  [ua.VariantType.Boolean]  # 返回值类型
            ),

            "QueryEventHistory": await self.node.events_node.add_method(
                    self.node.idx,
                    "QueryEventHistory",
                    self.history_manager.query_event_history,
                    [ua.VariantType.String],  # Input: JSON string for filters
                    [ua.VariantType.String]   # Output: JSON string of events
                ),

             "ReadRawHistory": await self.node.historian_node.add_method(
                    self.node.idx,
                    "ReadRawHistory",
                    self.history_manager.read_raw_history,
                    [ua.VariantType.String],  # Input: JSON string for filters
                    [ua.VariantType.String]   # Output: JSON string of events
                ),

            "update_parameters_from_json": await self.node.da_folder.add_method(
                    self.node.idx,
                    "update_parameters_from_json",
                    self.update_parameters_from_json,
                    [ua.VariantType.ByteString],
                    [ua.VariantType.Boolean]
                )


        }
        logging.info("_OPCDAWrapper_.setup_opc_ua_server: setup_opc_ua_server completed")
        
        # 为每个方法设置角色权限
    async def restart(self,parent=None):
            userrole = await self.security._get_current_userrole()
            if not self.user_manager.check_method_permission(12, userrole):
                logging.warning(f"_OPCDAWrapper_restart:Unauthorized attempt to call opc ua restart")
                if self.node.last_error_code is not None and self.node.last_error_desc is not None:
                    await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.restart:Unauthorized attempt to restart opc ua server ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            self.event.restart.set()
            return [ua.Variant(True, ua.VariantType.Boolean)]     
    async def stop(self,restore_init_cert:bool= False):
        self.event.running.clear()
        self.event.polling.clear()
        self.event.writing.clear()
        self.event.shutdown.set()
        self.event.restart.clear()
        self.event.broswe_opcda_struture.clear()
           

       # 清理匿名会话
        if self.user_manager and self.user_manager.anonymous_sessions:
            for client_addr in list(self.user_manager.anonymous_sessions.keys()):
                await self.user_manager._close_session(self.server.iserver,client_addr)
            self.user_manager.anonymous_sessions.clear()
            self.user_manager.recently_closed.clear()
            
            logging.debug("_OPCDAWrapper_.stop:Cleared all anonymous sessions during shutdown")
  
        if  self.user_manager.connected_clients["count"] != 0:
             for session_id in list(self.user_manager.connected_clients["sessions"].keys()):
                 self.security.disconnect_client(session_id)
                 
        # self.user_manager.connected_clients["count"] = 0
        # self.user_manager.connected_clients["sessions"].clear()

        for node_id in list(self.node.event_nodes.keys()):
                try:
                    child_node = await self.node.events_node.get_child(f"{self.node.idx}:{node_id}")
                    await self.server.delete_nodes([child_node], recursive=True)
                    logging.debug(f"Deleted existing event node {node_id}")
                except Exception as e:
                    logging.warning(f"Failed to delete event node {node_id}: {str(e)}")
        self.node.event_nodes.clear()
        try:
            self.executor_browser.shutdown(wait=True, timeout=5)
            self.executor_opcda.shutdown(wait=True, timeout=5)
            self.executor_opchda.shutdown(wait=True, timeout=5)
        except TimeoutError:
            logging.error("Executor shutdown timed out")
            self.executor_browser.shutdown(wait=False)
            self.executor_opcda.shutdown(wait=False)
            self.executor_opchda.shutdown(wait=False)
        await asyncio.sleep(1)
        if self.user_manager.connected_clients["count"] == 0 and restore_init_cert:
           
               await self.security.restore_initial_certificate(None)
            


   

  
        #仅在服务器仍运行时调用 stop()
        if self.server and hasattr(self.server, 'bserver') and self.server.bserver is not None:
            await self.server.stop()
          
        logging.info(f"_OPCDAWrapper_.stop:Shutdown complete at {time.strftime('%H:%M:%S')}")
    

    def _initialize_com(self):
        try:
            pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        except pythoncom.com_error:
            logging.debug("initialize_com Already initialized.")
            pass  # Already initialized

    def _uninitialize_com(self):
        try:
            pythoncom.CoUninitialize()
        except pythoncom.com_error:
            logging.debug("uninitialize_com Already uninitialize")
            pass
    def _update_from_json(self, config: Dict):
        for group, values in config.items():
            if hasattr(self, group):
                target = getattr(self, group)
                for key, value in values.items():
                    if hasattr(target, key):
                        if key == '_retention_period' and isinstance(value, dict):
                            value = datetime.timedelta(**value)
                        setattr(target, key, value)
    async def update_parameters_from_json(self, parent, json_data_variant) -> list:
        """
        OPC UA Method: Update server parameters from a JSON string.
        Inputs:
            json_data (ByteString): JSON string containing parameter table, e.g., 
                                   {"da_manager": {"_da_update_rate": 500, "_ua_update_rate": 5}, ...}.
        Returns:
            [Boolean]: True if successful, False otherwise.
        """
        userrole = await self.security._get_current_userrole()
        if not self.user_manager.check_method_permission(50, userrole):
            logging.warning(f"_OPCDAWrapper_.update_parameters_from_json: Unauthorized attempt to update parameters")
            await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.node.last_error_desc.write_value("Unauthorized attempt to update parameters")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

        try:
            # Decode JSON data from ByteString
            json_data = json_data_variant.Value.decode('utf-8')
            config = json.loads(json_data)
            logging.debug(f"_OPCDAWrapper_.update_parameters_from_json: Received config: {json.dumps(config, indent=2)}")

            # Validate config structure
            if not isinstance(config, dict):
                logging.error("_OPCDAWrapper_.update_parameters_from_json: Invalid config format, expected a dictionary")
                await self.node.last_error_desc.write_value("Invalid config format, expected a dictionary")
                return [ua.Variant(False, ua.VariantType.Boolean)]

            # Update parameters using existing _update_from_json method
            self._update_from_json(config)
            logging.info("_OPCDAWrapper_.update_parameters_from_json: Successfully updated parameters from JSON")
            return [ua.Variant(True, ua.VariantType.Boolean)]

        except json.JSONDecodeError as e:
            logging.error(f"_OPCDAWrapper_.update_parameters_from_json: Invalid JSON format: {str(e)}")
            await self.node.last_error_desc.write_value(f"Invalid JSON format: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.update_parameters_from_json: Error processing JSON: {str(e)}")
            await self.node.last_error_desc.write_value(f"Error processing JSON: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
    async def start(self):
            self.event.running.set()  
            self.event.shutdown.clear()
            await self.setup_opc_ua_server()            
            loop = asyncio.get_running_loop()
            logging.debug(f"Executor browser active: {not self.executor_browser._shutdown}")
            logging.debug(f"Executor opcda active: {not self.executor_opcda._shutdown}")

            def log_task_result(future):
                    try:
                        result = future.result()
                        logging.debug(f"Task completed with result: {result}")
                    except Exception as e:
                        logging.error(f"Task failed: {str(e)}", exc_info=True)
            deltavbrowser_task = loop.run_in_executor(self.executor_browser, self.da_manager.broswer_thread)
            deltavbrowser_task.add_done_callback(log_task_result)
            deltavdata_task = loop.run_in_executor( self.executor_opcda, self.da_manager.opcda_thread)
            deltavdata_task.add_done_callback(log_task_result)
            logging.debug(f"Scheduled tasks: browser={deltavbrowser_task}, data={deltavdata_task}")
            await asyncio.sleep(1)  # Allow threads to start
          
          
        
            async with self.server:
                try:
                    self.server.set_security_policy(self.security.security_policies)
                    logging.debug(f"_OPCDAWrapper_.start: Security policies set: {[policy.URI for policy in self.security.security_policies]}")
                    
                    logging.debug("Performing initial OPC DA browse the top 2 level strture...")
                    await self.da_manager.broswe_folder(max_level=2)
                                   
                    
                    # 持续运行的监控任务
                    monitor_task = asyncio.create_task(self.user_manager.monitor_anonymous_sessions(self.server.iserver))
                    logging.debug("_OPCDAWrapper_.start: Monitor anonymous sessions task started")

                    logging.debug("Wait 10 seconds for update_ua_nodes task...")
                    await asyncio.sleep(10)
                    # 启动周期性更新任务
                    update_task = asyncio.create_task(self.da_manager.update_ua_nodes())
                    logging.debug("_OPCDAWrapper_.start: Periodic update task started")
                
                    event_update_task = asyncio.create_task( self.history_manager.periodic_event_update())
                    logging.debug("_OPCDAWrapper_.start: Periodic event update task started")

                    # 主循环，监听事件并支持动态调用
                    while not self.event.shutdown.is_set():
                        if self.event.restart.is_set():
                            logging.debug("_OPCDAWrapper_.start: Restart event detected, shutting down...")
                            self.event.shutdown.set()
                            monitor_task.cancel()
                            update_task.cancel()
                            event_update_task.cancel()
                            break
                        await asyncio.sleep(0.5)  # 短暂休眠，避免 CPU 占用过高

                    # 等待任务完成
                    await asyncio.gather(deltavbrowser_task, deltavdata_task,monitor_task, update_task, event_update_task, return_exceptions=True)
                
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_.start: Error occurred: {str(e)}")
                finally:
                    self.event.running.clear()
                    self.event.shutdown.set()
                    monitor_task.cancel()
                    update_task.cancel()
                    event_update_task.cancel()
                    await asyncio.gather(deltavbrowser_task,deltavdata_task, monitor_task, update_task, event_update_task, return_exceptions=True)
                    logging.debug(f"_OPCDAWrapper_.start: Start task completed at {time.strftime('%H:%M:%S')}")
                    await asyncio.sleep(3)
   
async def main():
    items1 = [
        "V1-IO/AI1_SCI1.EU100",
        "V1-IO/DO1_NA_PV.CV",
        "V1-AI-1/FS_CTRL1/MOD_DESC.CV",
        "V1-TIC-VSL/PID1/MODE.TARGET",
        "V1-AIC-DO/HI_ALM.CUALM",
        "V1-TIC-JKT/HEAT_OUT_D.CV"
     
    ]

    items2 = [
           "PROPLUS/FREDISK.CV",
           "PROPLUS/FREMEM.CV",
           "PROPLUS/OINTEG.CV",
           "PROPLUS/ISACTIVE.CV",
           "PROPLUS/SWREV.CV",
           "PROPLUS/FAILED_ALM.CV"
     
     
    ]
    items=items1+items2

   
    try:
        wrapper = _OPCDAWrapper_()
       
      
        # 启动服务
        await wrapper.da_manager.append_items(items)
       
       
        start_task = asyncio.create_task(wrapper.start())
        
        # 初始添加节点
        await asyncio.sleep(10)
        
        print(f"_OPCDAWrapper_.main: add  {items} ")
        await wrapper.da_manager.add_items(items1, "MODULES.AREA_V1")
        await asyncio.sleep(10)
        await wrapper.da_manager.add_items(items2, "DIAGNOSTICS")
        await asyncio.sleep(5)
        # 示例：动态调用 update_node
        new_item = await wrapper.da_manager.update_node("MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE.EU100")
        print(f"_OPCDAWrapper_.main: Added new item: {new_item}")
        await asyncio.sleep(10)
        
        # 示例：动态调用 broswe_folder
        await wrapper.da_manager.broswe_folder(base_path="MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
        print("_OPCDAWrapper_.main: Browsed and updated structure under MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
        await asyncio.sleep(30)
        await wrapper.da_manager.remove_items(items2)
        print("_OPCDAWrapper_.main: Remove items from subcrible")
         # Example: Call update_parameters_from_json
        await asyncio.sleep(30)
        sample_config = {
            "da_manager": {
                "_da_update_rate": 2000,
                "_ua_update_rate": 20,
                "_da_subscribe_waittime": 2,
           
            },
            "history_manager": {
                "_event_update_rate": 10,
                "_retention_period": {"days": 1}  # Will be converted to timedelta
            },
               "user_manager": {
                "_anonymous_timeout" : 120 ,         
                "_cooldown_time" : 240,       
                "_monitor_period" : 5
                  }

        }
        json_data = json.dumps(sample_config).encode('utf-8')
        result = await wrapper.update_parameters_from_json(None, ua.Variant(json_data, ua.VariantType.ByteString))
        print(f"_OPCDAWrapper_.main: Updated parameters from JSON, result: {result[0].Value}")
   
        #等待手动停止或超时
        if wrapper.manual_stop:
            await asyncio.sleep(10)
            print("_OPCDAWrapper_.main: manual_stop enabled, waithing for manual stop from client ")
            if not wrapper.event.shutdown.is_set():
                await wrapper.stop()
        elif wrapper.max_time:
            await asyncio.wait([start_task], timeout=wrapper.max_time)
        else:
            await start_task
    
    except Exception as e:
        logging.error(f"_OPCDAWrapper_.main: Error: {str(e)}")
    finally:
        await wrapper.stop(restore_init_cert=True)
        if not start_task.done():
            start_task.cancel()
            await start_task
        print("_OPCDAWrapper_.main: Shutdown complete")

if __name__ == "__main__":
    logging.basicConfig(
        filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'opcuuaserver.log'),
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger('asyncua').setLevel(logging.WARNING)
    asyncio.run(main())