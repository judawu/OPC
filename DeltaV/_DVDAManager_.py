import asyncio
import logging
import pythoncom
import datetime
import time
import json
from queue import Queue, Empty
from asyncua import ua
from typing import List, Dict, Tuple, Optional
from _DVDA_ import _OPCDA_, OPCDADataCallback
class _OPCDAManager_:
        def __init__(self,wrapper,nodename="PROPLUS"):
            self.nodename=nodename
            self.group_name :str = "OPCDAGroup"     
            self._max_items:int = 50000
            self._manual_stop_subcrible:bool = False   
            self._da_update_rate: int= 1000
            self._ua_update_rate: int= 10
            self._da_subscribe_waittime :int= 1 
            self.callback = OPCDADataCallback(self.custom_callback)
            self.write_lock = asyncio.Lock()
            self.poll_queue = Queue()
            self.write_queue = Queue()
            
           
            self._max_level = 1
            self.path_lock = asyncio.Lock()
            self.path =None
            self.structure={}
            
            
            self.items=[f'{self.nodename}/OINTEG.CV']
                               
            
            self._opcdeltav = _OPCDA_(node_name=self.nodename,server_name = "OPC.DeltaV.1")
            self._opcda = _OPCDA_(node_name=self.nodename,server_name = "DeltaV.DVSYSsvr.1")
            self._wrapper = wrapper
      
            
       
        def custom_callback(self, paths: List[str], results: List[Tuple[any, int, str]]):
            for path, (value, quality, timestamp) in zip(paths, results):
                if quality > 127:
                    self.callback.data[path] = (value, quality, timestamp)
                    print(f"CustomDAManager.custom_callback:Poll/Subscribe: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
                    #logging.debug(f"CustomDAManager.custom_callback: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
   
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
                                if not self._manual_stop_subcrible:
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
                   
                    method_name = f"UpdateItem_{value}"
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
            items_number =len(self.items)
            if self._max_items and items_number >= self._max_items:
                  logging.info(f"CustomDAManager.update_ua_nodes: Reached max DST  ({self._max_items}), license Assgined, stop add items...")
            else:                 
                last_values = {}
                logging.debug(f"CustomDAManager.add_items: try to  add items node for {items} at {base_path}...")
              
                await self.async_poll(items, interval=1, max_time=float(items_number))
                

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
                                    return await self._wrapper.history_manager.enable_historizing(parent, item)
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
                                    return await self._wrapper.history_manager.read_item_history(parent, item)
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
                            
                                last_values[item] = value
                            
                            except ua.UaStatusCodeError as e:
                                logging.error(f"CustomDAManage.add_itemsr:Failed to write {item}: {str(e)}")
                                await self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_items: Failed to write {item}, Error Occured: {str(e)}")
                        else:
                            logging.warning(f"CustomDAManager.add_items: item {item}: not in last values ot it's value doesn't change")
                    else:
                        logging.warning(f"CustomDAManage.add_items: item {item}: is not valid in opc data server,check your item path")
        async def update_ua_nodes(self):
                """Update OPC UA nodes with values from OPC DA items"""
                
                while not self._wrapper.event.shutdown.is_set():
                   
                    try:
                        try:
                            await self._wrapper.node.parameters_nodes['PARA1'].write_value(ua.Variant(int(self._wrapper.max_time), ua.VariantType.Int64))   
                            await self._wrapper.node.parameters_nodes['PARA2'].write_value(ua.Variant(bool(self._wrapper.manual_stop), ua.VariantType.Boolean))
                            await self._wrapper.node.parameters_nodes['PARA3'].write_value(ua.Variant(int(self._da_update_rate), ua.VariantType.Int64))
                            await self._wrapper.node.parameters_nodes['PARA4'].write_value(ua.Variant(int(self._ua_update_rate), ua.VariantType.Int64))
                            await self._wrapper.node.parameters_nodes['PARA5'].write_value(ua.Variant(int(self._wrapper.history_manager._event_update_rate), ua.VariantType.Int64))
                            await self._wrapper.node.parameters_nodes['PARA6'].write_value(ua.Variant(int(self._wrapper.user_manager._anonymous_timeout), ua.VariantType.Int64))
                            await self._wrapper.node.parameters_nodes['PARA7'].write_value(ua.Variant(int(self._wrapper.user_manager._cooldown_time), ua.VariantType.Int64))
                            await self._wrapper.node.parameters_nodes['PARA8'].write_value(ua.Variant(int(self._wrapper.user_manager._monitor_period), ua.VariantType.Int64))
                            items_number =len(self.items)
                           
                            await self._wrapper.node.parameters_nodes['PARA10'].write_value(ua.Variant(int(items_number), ua.VariantType.Int64))
                            
                            await self._wrapper.node.parameters_nodes['PARA11'].write_value(ua.Variant(int(self._wrapper._status), ua.VariantType.Int64))
                            logging.debug(f"CustomDAManage.update_ua_nodes: cycle update ua nodes ,the  cycle time is {self._ua_update_rate} s") 
                        except Exception as e:
                            logging.error(f"CustomDAManage.update_ua_nodes: Failed to write to paramters : {str(e)}")
                            continue
                        for item in self.items:
                            if item in self._wrapper.node.nodes:
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
                    except Exception as e:
                         logging.error(f"CustomDAManage.update_ua_nodes: Failed with errof : {str(e)}")
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
                                await self._process_json_structure(structure=value, base_path=current_path)
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
        
        def extract_items_from_json(self, json_structure: Dict) -> List[str]:
            """
            Recursively extracts all item paths from a JSON structure.

            Args:
                json_structure (Dict): JSON structure containing keys with item lists or nested dictionaries.

            Returns:
                List[str]: List of item paths extracted from the JSON.
            """
            items = []
            try:
                for key, value in json_structure.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                items.append(item)
                            else:
                                logging.warning(f"CustomDAManager.extract_items_from_json: Invalid item in JSON list for key {key}: {item}")
                    elif isinstance(value, dict):
                        items.extend(self.extract_items_from_json(value))
            except Exception as e:
                logging.error(f"CustomDAManager.extract_items_from_json: Error extracting items from JSON: {str(e)}")
            return items

        async def batch_control_nodes(self, batch_start: str, json_data):
            """
            Monitors an OPC DA item and dynamically manages nodes based on its value.
            Calls add_nodes_from_json when value is 1, remove_items when value is 0.
            Items to remove are extracted from the provided JSON data.

            Args:
                batch_start (str): OPC DA item path to monitor.
                json_data (str): JSON string for add_nodes_from_json and to extract items for removal.
            """
            logging.debug(f"CustomDAManager.batch_control_nodes: Starting monitoring for item {batch_start}")

            # Validate batch_start item path
            if not isinstance(batch_start, str) or not batch_start.strip():
                logging.error(f"CustomDAManager.batch_control_nodes: Invalid batch_start item path: {batch_start}")
                return

            # Parse JSON to extract items for removal
          

            # Ensure item is subscribed
            if batch_start not in self.items:
                self.items.append(batch_start)
                logging.debug(f"CustomDAManager.batch_control_nodes: Added {batch_start} to subscription list")
                # Trigger subscription update and wait for initial data
                await self.async_poll([batch_start], interval=1.0, max_time=3.0)
                # Wait briefly to ensure subscription is active
                start_time = time.time()
                while time.time() - start_time < 5.0:
                    if self.callback.get_data(batch_start):
                        break
                    await asyncio.sleep(0.5)
                else:
                    logging.warning(f"CustomDAManager.batch_control_nodes: No initial data for {batch_start} after subscription")

            last_value = None
            while not self._wrapper.event.shutdown.is_set():
                try:
                    data = self.callback.get_data(batch_start)
                    if data and data[1] > 127:  # Check for good quality
                        value, quality, _ = data
                        # Convert value to int for comparison
                        try:
                            current_value = int(value) 
                        except (ValueError, TypeError):
                            logging.warning(f"CustomDAManager.batch_control_nodes: Invalid value type for {batch_start}: {value}")
                            await asyncio.sleep(1.0)
                            continue

                        if current_value != last_value:
                            if current_value == 1:
                             
                                try:
                                    asyncio.create_task(self._process_json_structure(json_data, ""))
                                  
                                except Exception as e:
                                    logging.error(f"CustomDAManager.batch_control_nodes: Error adding nodes for {batch_start}: {str(e)}")
                            elif current_value == 0:
                               

                               
                                try:
            
                                    items_to_remove = self.extract_items_from_json(json_data)
                                    logging.debug(f"CustomDAManager.batch_control_nodes: Extracted items to remove: {items_to_remove}")
                                    if items_to_remove:
                                        await self.remove_items(items_to_remove)
                                        logging.debug(f"CustomDAManager.batch_control_nodes: Successfully removed items {items_to_remove}")
                                        
                                    else:
                                        logging.debug(f"CustomDAManager.batch_control_nodes: No items to remove for {batch_start}")
                                except json.JSONDecodeError as e:
                                    logging.error(f"CustomDAManager.batch_control_nodes: Invalid JSON format: {str(e)}")
                                    return
                                except Exception as e:
                                    logging.error(f"CustomDAManager.batch_control_nodes: Error removing items for {batch_start}: {str(e)}")
                                    return
                                 
                                
                                    
                            last_value = current_value
                    else:
                        logging.warning(f"CustomDAManager.batch_control_nodes: No valid data for {batch_start}")
                    
                    await asyncio.sleep(2.0)  # Check every second
                except Exception as e:
                    logging.error(f"CustomDAManager.batch_control_nodes: Error monitoring {batch_start}: {str(e)}")
                    await asyncio.sleep(2.0)
            
            logging.debug(f"CustomDAManager.batch_control_nodes: Stopped monitoring {batch_start}")
                
