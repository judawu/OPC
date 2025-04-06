import win32com.client
import pythoncom
import pywintypes
from win32com.client import Dispatch
import logging
from datetime import datetime, timedelta


class _OPCHDA_:
    def __init__(self, server_name: str = "DeltaV.OPCHDAsvr", client_name: str = "PythonOPCHDAClient"):
        self.server_name = server_name
        self.version = '1.0.1'
        self.status = None
        self.opc_hda = None
        self.hda_server = None
        self.connected = False
        self.client_name = client_name
        self.shutdown_handler = None
    def extract_scode(self,error_obj):
        """
        从 pywintypes.com_error 对象中提取 scode 值。
        
        参数:
            error_obj: pywintypes.com_error - COM 异常对象
        
        返回:
            int: scode 值，如果无法提取则返回 None
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
            # 如果发生任何异常，返回 None
            return -2147352567
    def connect(self) -> int:
        logging.debug(f"_OPCHDA_: Attempting to connect to {self.server_name}")
        try:
            pythoncom.CoInitialize()
            self.opc_hda = win32com.client.Dispatch("OpcHda.Automation")
            logging.debug(f"_OPCHDA_: Successfully created OpcHda.Automation instance")

            if hasattr(self.opc_hda, "Parent"):
                self.hda_server = self.opc_hda.Parent
                logging.debug(f"_OPCHDA_: Successfully accessed Parent")
          
                self.hda_server.Connect(self.server_name)
                logging.debug(f"_OPCHDA_.connect: Successfully Connected ({self.server_name})")
                self.status = self.GetHistorianStatus()
              
                # logging.debug(f"_OPCHDA_: hda_server dir hda_server: {dir(self.hda_server)}")
                #logging.debug(f"_OPCHDA_: hda_server dir OPCHDAItems: {dir(self.hda_server.OPCHDAItems)}")
         
                if  self.status:
                    self.connected = True
                    logging.debug(f"_OPCHDA_: Successfully connected to {self.server_name}")
                    return True
                else:
                    logging.warning(f"_OPCHDA_: Connected but failed to get meaningful status")
            else:
                logging.warning("_OPCHDA_: Parent attribute not available")

            raise Exception("Failed to connect")
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to connect to {self.server_name}: {str(e)}")
            return False
        finally:
            if self.connected:
                self.shutdown_handler = win32com.client.WithEvents(self.hda_server, OPCHDAShutdownHandler)
                self.shutdown_handler.callback = self.on_shutdown
    def disconnect(self):
        if self.connected:
            try:
                self.hda_server.Disconnect()
                self.connected = False
                logging.debug(f"_OPCHDA_: Successfully disconnected from {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCHDA_: Failed to disconnect from {self.server_name}: {str(e)}")
            finally:
                if self.shutdown_handler:
                    del self.shutdown_handler
                self.hda_server = None
                self.opc_hda = None
                self.status = None
                pythoncom.CoUninitialize()
    def on_shutdown(self, reason: str):
        logging.info(f"_OPCHDA_: Shutdown request received from {self.server_name}: {reason}")
        self.disconnect()
    
    def GetErrorString(self,errrcode:int=0) -> str:
        if not self.hda_server:
            logging.error("_OPCHDA_.GetErrorString: No server interface available")
            return 'No server interface available'
        try:           
             return self.hda_server.GetErrorString(errrcode)
        except Exception as e:
            logging.error(f"_OPCHDA_.GetErrorString: Failed to get GetErrorString: {str(e)}")
            return str(e)
    def GetHistorianStatus(self) -> dict:
        if not self.hda_server:
            logging.error("_OPCHDA_.GetHistorianStatus: No server interface available")
            return None
        try:
            self.hda_server.ClientName= self.client_name
            return {
                "Status": self.hda_server.HistorianStatus,
                "StatusString": self.hda_server.StatusString,
                "CurrentTime": str(self.hda_server.CurrentTime),
                "ServerName": str(self.hda_server.ServerName),
                  "ServerNode": self.hda_server.ServerNode,
                "MaxReturnValues": str(self.hda_server.MaxReturnValues),
                "StartTime": str(self.hda_server.StartTime),
                "BuildNumber": self.hda_server.BuildNumber,
                "CLSID": str(self.hda_server.CLSID),
                "LocaleID": self.hda_server.LocaleID,
                "MajorVersion": self.hda_server.MajorVersion,
                "MinorVersion": self.hda_server.MinorVersion,
                "MaxReturnValues": self.hda_server.MaxReturnValues, 
                "VendorInfo": self.hda_server.VendorInfo,
                "CanAsyncDeleteAtTime": self.hda_server.CanAsyncDeleteAtTime,
                "CanAsyncDeleteRaw": self.hda_server.CanAsyncDeleteRaw,
                "CanAsyncInsert": self.hda_server.CanAsyncInsert,
                "CanAsyncInsertAnnotations": self.hda_server.CanAsyncInsertAnnotations,
                "CanAsyncInsertReplace": self.hda_server.CanAsyncInsertReplace,
                "CanAsyncReadAnnotations": self.hda_server.CanAsyncReadAnnotations,
                "CanAsyncReplace": self.hda_server.CanAsyncReplace,
                 "ClientName": self.hda_server.ClientName
              
              

              
            }
        except Exception as e:
            logging.error(f"_OPCHDA_GetHistorianStatus: Failed to get historian status: {str(e)}")
            return None
    def GetItemAttributes(self) -> list:
        """获取支持的项属性列表"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_.GetItemAttributes: Not connected to server")
            return None

        try:
            attributes = self.hda_server.GetItemAttributes()
           
            if isinstance(attributes, tuple):
                attr_count, attr_ids, attr_names, attr_descs, attr_types = attributes
                attr_list = [
                    {"id": attr_ids[i], 
                    "name": attr_names[i],
                    "description": attr_descs[i],
                     "type": attr_types[i]}
                    for i in range(attr_count)
                ]
            else:
                attr_list = list(attributes)
         
            return attr_list
        except Exception as e:
            logging.error(f"_OPCHDA_.GetItemAttributes: Failed to get item attributes: {str(e)}")
            return None
    def GetAggregates (self) -> list:
     
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_.GetAggregates : Not connected to server")
            return None

        try:
            Aggregates = self.hda_server.GetAggregates()
         
            if isinstance(Aggregates, tuple):
                
                Aggregates_list ={
                       "count": Aggregates[0], 
                       "type":[
                        {"id": Aggregates[1][i], 
                          "name": Aggregates[2][i],
                          "description": Aggregates[3][i]
                         }   for i in range(Aggregates[0]) ] 
                } 
                           
         
                return Aggregates_list
            else:
                return None

        except Exception as e:
            logging.error(f"_OPCHDA_.GetAggregates: Failed to get item GetAggregates: {str(e)}")
            return None
    def CreateBrowse(self) -> list[str]:
        """浏览所有 OPC HDA Item IDs"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_.CreateBrowse: Not connected to server")
            return None

        try:
            
            browser_tuple = self.hda_server.CreateBrowser()
            #logging.debug(f"_OPCHDA_.CreateBrowse: CreateBrowser returned: {browser_tuple}")
            browser = browser_tuple[0]  # 提取浏览器对象
           
            # 打印浏览器对象的可用方法
       
            #logging.debug(f"_OPCHDA_.CreateBrowse: Browser methods: {dir(browser)}")
            browser.MoveToRoot() # 移动到根节点
            # 注意：更完整的浏览可能需要递归地遍历分支 (OPCHDABranches)
            # 并使用 MoveDown 等方法。这取决于 DeltaV OPC HDA 服务器的实现。(good news is DeltaV OPC HDA SERVER is flat for itmes browse, don't need to move down)
            #logging.debug(f"_OPCHDA_.CreateBrowse: Browser CurrentPosition: {browser.CurrentPosition}")
            #logging.debug(f"_OPCHDA_.CreateBrowse: Browser CurrentPosition: {dir(browser.GetItemID)}") #This method provides a way to obtain the current OPC HDA Item ID. 
            #logging.debug(f"_OPCHDA_.CreateBrowse: Browser OPCHDAItems: {browser.OPCHDAItems}")
           # logging.debug(f"_OPCHDA_.CreateBrowse: Browser OPCHDABranches: {browser.OPCHDABranches}")
            #logging.debug(f"_OPCHDA_.CreateBrowse: Browser OPCHDALeaves: {browser.OPCHDALeaves}")
           

            items = []
            try:
                # 尝试获取当前位置的项
                hda_items = browser.OPCHDAItems
                for item in hda_items:
                    items.append(item)
                logging.debug(f"_OPCHDA_.CreateBrowse: Successfully browsed {len(items)} items at current level")
            except Exception as e:
                logging.warning(f"_OPCHDA_.CreateBrowse: Failed to get items at current level: {e}")

         

            return items
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to browse items: {str(e)}", exc_info=True)
            return None

    def AddItem(self, item_id: str):
            if not self.connected or not self.hda_server:
                    logging.error("_OPCHDA_: Not connected to server")
                    return None
            try:                    
                  client_handle = 0  # Arbitrary client handle
                  OPCHDAItem= self.hda_server.OPCHDAItems.AddItem(item_id, client_handle)
           
                  return OPCHDAItem
            except Exception as e:             
                    logging.error(f"_OPCHDA_AddItem: Failed to AddItem {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    def ReadRaw(self, item_id: str, start_time: datetime, end_time: datetime,NumValues:int,Bounds:int=3) -> dict:       
            try:       
                
               
                item_point=self.AddItem(item_id)
                results = item_point.ReadRaw(start_time,end_time,NumValues,Bounds)   # 这里的 items 是一个元组，包含了服务器句柄和其他信息
              
                self.hda_server.OPCHDAItems.Remove(1,[item_point.ServerHandle,0])  # 这里的 items 是一个元组，包含了服务器句柄和其他信息
                data = {}
                if isinstance(results, tuple) :
                    history_object = results[0]                 
                    values = []
                    qualities_list = []
                    timestamps = []        
                    try:           
                        if hasattr(history_object, 'Count'):            
                            count = history_object.Count                      
                            for j in range(count):
                                try:
                                    record = history_object.Item(j+1)                           
                                    values.append(record.DataValue)
                                    qualities_list.append(record.Quality)
                                    timestamps.append(record.TimeStamp)                             
                                except Exception as e:
                                    raise                
                        else:
                            logging.warning(f"_OPCHDA_ReadRaw: History object for {item_id} does not have a 'Count' attribute.")

                    except Exception as e:
                        raise

                    data[item_id] = {
                       
                        "values": values,
                        "qualities": qualities_list,
                        "timestamps": timestamps
                    }                                          
       
                return data
               
            except Exception as e:
                    logging.error(f"_OPCHDA_ReadRaw: Failed to ReadRaw: {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    def ReadProcessed(self, item_id: str, start_time: datetime, end_time: datetime,Interval: int,Aggregate:int=1) -> dict:       
            try:       
                
               
                item_point=self.AddItem(item_id)
             
                basetime=pywintypes.Time(86400)
                #print(basetime)
          
                #ResampleInterval=timedelta(seconds=Interval)
                #ResampleInterval=pywintypes.Time(Interval)
                #ResampleInterval = int(timedelta(seconds=Interval).total_seconds() * 1000)
                
                #ResampleInterval=pywintypes.Time(86400+Interval)
                ResampleInterval = basetime+ timedelta(seconds=Interval) 
            
                starttime=start_time
                endtime=end_time
                results = item_point.ReadProcessed(starttime, endtime,ResampleInterval,Aggregate)  
           
                self.hda_server.OPCHDAItems.Remove(1,[item_point.ServerHandle,0])  
                data = {}
                if isinstance(results, tuple) :

                    history_object = results[0] 
               
                    values = []
                    qualities_list = []
                    timestamps = []        
                    try:           
                        if hasattr(history_object, 'Count'):            
                            count = history_object.Count 
                            logging.debug(f"_OPCHDA_ReadProcessed:ReadProcessed count is {count}")                     
                            for j in range(count):
                                try:
                                    record = history_object.Item(j+1) 
                                        
                                    values.append(record.DataValue)
                                    qualities_list.append(record.Quality)
                                    timestamps.append(record.TimeStamp)                             
                                except Exception as e:
                                    raise                
                        else:
                            logging.warning(f"_OPCHDA_ReadProcessed: History object for {item_id} does not have a 'Count' attribute.")

                    except Exception as e:
                        raise

                    data[item_id] = {
                       
                        "values": values,
                        "qualities": qualities_list,
                        "timestamps": timestamps
                    }                                          
       
                return data
               
            except Exception as e:
                    logging.error(f"_OPCHDA_ReadProcessed: Failed to ReadProcessed: {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    

    def SyncReadAttribute(self, item_id: str, start_time: datetime, end_time: datetime, NumAttributes: int , AttributesIDs: list[int]) -> dict:       
            try:       
                
               
                ServerHandle= self.AddItem(item_id).ServerHandle
             
                if ServerHandle is None:
                    logging.error("_OPCHDA_.SyncReadAttribute: Failed to add item")
                    return None
                results = self.hda_server.OPCHDAItems.SyncReadAttribute(start_time,end_time,ServerHandle,NumAttributes, AttributesIDs )   
                self.hda_server.OPCHDAItems.Remove(1,[ServerHandle,0])  # 这里的 items 是一个元组，包含了服务器句柄和其他信息
               # self.hda_server.OPCHDAItems.RemoveAll()
         
                data = {}
                if isinstance(results, tuple) and len(results) >= 3:
                    history_data_objects = results[2]
                    values = []
                    qualities_list = []
                    timestamps = []
                    for i in range(len(history_data_objects)):  
                        
                        history_object = history_data_objects[i]
       
                        try:
                            if history_object is None:
                                logging.debug(f"_OPCHDA_SyncReadAttribute: AttributesIDs {AttributesIDs[i]} for {item_id} is None.")
                                values.append(None)
                                qualities_list.append(None)
                                timestamps.append(None)
                                continue
                            if hasattr(history_object, 'Count'):            
                                count = history_object.Count
                           
                                for j in range(count):
                                    try:
                                        record = history_object.Item(j+1)                                  
                                        values.append(record.DataValue)
                                        qualities_list.append(record.Quality)
                                        timestamps.append(record.TimeStamp)
                                        
                                    except Exception as e:
                                        logging.warning(f"_OPCHDA_SyncReadAttribute: Error accessing record {j} for {item_id}: {e}")
                        

                            else:
                                logging.warning(f"_OPCHDA_SyncReadAttribute: History object for {item_id} does not have a 'Count' attribute.")

                        except Exception as e:
                            logging.error(f"_OPCH_OPCHDA_SyncReadAttributeA_: Error accessing history data for {item_id}: {e}")

                    data[item_id] = {
                        "AttributesIDs": AttributesIDs,
                        "values": values,
                        "qualities": qualities_list,
                        "timestamps": timestamps
                    }                                          
       
                return data
               
            except Exception as e:
                    logging.error(f"_OPCHDA_SyncReadAttribute: Failed to SyncReadAttribute: {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    def ValidateItemIDs(self, item_ids: list) -> dict:
        """验证指定的 Item IDs 是否有效 (使用 Validate 方法 - 临时方案)"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_: Not connected to server")
            return None

        validation = {}
        try:
        
            num_items = len(item_ids)
            item_ids.append(item_ids[-1])
            results = self.hda_server.OPCHDAItems.Validate(num_items,item_ids)
            for i in range(num_items):
                item_id = item_ids[i]
                validation[item_ids[i]] = (results[i]==0)
                           
            return validation
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to validate item IDs: {str(e)}", exc_info=True)
            return None
    def AddItems(self, item_ids: list[str]) -> list[int]:
            if not self.connected or not self.hda_server:
                    logging.error("_OPCHDA_: Not connected to server")
                    return None
            try:   
                num_items = len(item_ids)
                item_ids.append(item_ids[-1])  # 需要添加 item_ids[-1]   以避免错误,otherise num_items=num_items-1
                client_handles = list(range(num_items+1))
                            
                items = self.hda_server.OPCHDAItems.AddItems(num_items, item_ids, client_handles)   # 这里的 items 是一个元组，包含了服务器句柄和其他信息              
                server_handles = [handle for handle in items[0]] # items[0] is server_handles
                server_handles.append(server_handles[-1])  # 需要添加 item_ids[-1]   以避免错误,otherise num_items=num_items-1  
                return server_handles
            except Exception as e:
                    logging.error(f"_OPCHDA_: Failed to AddItems {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    def SyncReadRaw(self, item_ids: list[str], start_time: datetime, end_time: datetime, max_values: int = 0) -> dict:       
            try:       
                num_items = len(item_ids)     
                server_handles= self.AddItems(item_ids)
                if server_handles is None:
                    logging.error("_OPCHDA_: Failed to add items")
                    return None
                results = self.hda_server.OPCHDAItems.SyncReadRaw(start_time,end_time, max_values, 2, num_items, server_handles)   # why not working for last server_handles   
                self.hda_server.OPCHDAItems.Remove(num_items,server_handles)
             

                data = {}
                if isinstance(results, tuple) and len(results) >= 3:
                    history_data_objects = results[2]
                   
                    for i in range(len(history_data_objects)):  
                        item_id = item_ids[i]
                        history_object = history_data_objects[i]

                        values = []
                        qualities_list = []
                        timestamps = []

                        try:
                            if history_object is None:
                                logging.warning(f"_OPCHDA_: History object for {item_id} is None.")
                                continue
                            if hasattr(history_object, 'Count'):            
                                count = history_object.Count
                                #logging.debug(f"_OPCHDA_: Number of historical values for {item_id}: {count}")
                                for j in range(count):
                                    try:
                                        record = history_object.Item(j+1)                                  
                                        #logging.debug(f"_OPCHDA_: get Record {j+1} at  ({record.DataValue},{record.Quality},{record.TimeStamp})")
                                        values.append(record.DataValue)
                                        qualities_list.append(record.Quality)
                                        timestamps.append(record.TimeStamp)
                                        
                                    except Exception as e:
                                        logging.warning(f"_OPCHDA_: Error accessing record {j} for {item_id}: {e}")
                        

                            else:
                                logging.warning(f"_OPCHDA_: History object for {item_id} does not have a 'Count' attribute.")

                        except Exception as e:
                            logging.error(f"_OPCHDA_: Error accessing history data for {item_id}: {e}")

                        data[item_id] = {
                            "values": values,
                           
                            "qualities": qualities_list,
                            "timestamps": timestamps
                        }                                          

                else:
                        logging.warning("_OPCHDA_: Unexpected format of SyncReadRaw results.")
                        for item_id in item_ids:
                            data[item_id] = {"values": [], "qualities": [], "timestamps": []}   
                        
                return data
            except Exception as e:
                    logging.error(f"_OPCHDA_: Failed to read raw data: {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None
    def SyncReadProcessed(self, item_ids: list[str], start_time: datetime, end_time: datetime, Interval: int,Aggregates:list[int]) -> dict:       
            try:       
                num_items = len(item_ids)     
                server_handles= self.AddItems(item_ids)
                if server_handles is None:
                    logging.error("_OPCHDA_: Failed to add items")
                    return None
                basetime=pywintypes.Time(86400)
           
            
                #ResampleInterval=pywintypes.Time(86400+Interval)
                ResampleInterval = basetime + timedelta(seconds=Interval) 
              
                results=self.hda_server.OPCHDAItems.SyncReadProcessed(start_time,end_time,ResampleInterval,num_items,server_handles,Aggregates)  
               
              
           
                data = {}
                if isinstance(results, tuple) and len(results) >= 3:
                    history_data_objects = results[2]
                   
                    for i in range(len(history_data_objects)):  
                        item_id = item_ids[i]
                        history_object = history_data_objects[i]
                        values = []
                        qualities_list = []
                        timestamps = []
                        try:
                            if history_object is None:
                                logging.debug(f"_OPCHDA_: History object for {item_id} is None.")
                                continue
                            if hasattr(history_object, 'Count'):            
                                count = history_object.Count
                                logging.debug(f"_OPCHDA_: Number of historical values for {item_id}: {count}")
                                for j in range(count):
                                    try:
                                        record = history_object.Item(j+1)                                  
                                        logging.debug(f"_OPCHDA_: get Record {j+1} at  ({record.DataValue},{record.Quality},{record.TimeStamp})")
                                        values.append(record.DataValue)
                                        qualities_list.append(record.Quality)
                                        timestamps.append(record.TimeStamp)
                                        
                                    except Exception as e:
                                        logging.warning(f"_OPCHDA_: Error accessing record {j} for {item_id}: {e}")
                        

                            else:
                                logging.warning(f"_OPCHDA_: History object for {item_id} does not have a 'Count' attribute.")

                        except Exception as e:
                            logging.error(f"_OPCHDA_: Error accessing history data for {item_id}: {e}")

                        data[item_id] = {
                            "values": values,
                           
                            "qualities": qualities_list,
                            "timestamps": timestamps
                        }                                          

                else:
                        logging.warning("_OPCHDA_: Unexpected format of SyncReadRaw results.")
                        for item_id in item_ids:
                            data[item_id] = {"values": [], "qualities": [], "timestamps": []}   
                        
                return data
            except Exception as e:
                    logging.error(f"_OPCHDA_: Failed to read raw data: {str(e)}, inner error is: {self.GetErrorString(self.extract_scode(e))}", exc_info=True)
                    return None

    
class OPCHDAShutdownHandler:
    def __init__(self, callback=None):
        self.callback = callback

    def ShutdownRequest(self, Reason):
        if self.callback:
            self.callback(Reason)
    
def main():
   
    opc_hda = _OPCHDA_()
    try:
        if opc_hda.connect():
            print(f"Connected to OPCHDA {opc_hda.server_name}")
            print()
            print("Get OPCHDA  Historian Status:", opc_hda.status)
            print()
            items = opc_hda.CreateBrowse()
            print(f"OPCHDA {opc_hda.server_name} Browsed {len(items)} Items:,first 2 is {items[:2]}" )
            print()
            item_ids = items[:40] if items else ["V1-IO/DO1_NA_PV.CV","V1-IO/PH1_MV_PV.CV"]
            print()
            attributes = opc_hda.GetItemAttributes()
            print("Get OPCHDA Item Attributes:", attributes)
            print()
            Aggregates  = opc_hda.GetAggregates()
            print("OPCHDA support Aggregates :", Aggregates)
            print()
            end_time = datetime.now()  +  timedelta(hours=8)
            start_time = end_time - timedelta(hours=1)
            item_attribute_data = opc_hda.SyncReadAttribute(item_ids[20], start_time, end_time, 11, [1,4,13,14,15,16,-2147483646, -2147483645,-2147483630,-2147483613,-2147483598,0])
          
            print(f"Test SyncReadAttribute for {item_ids[20]} item_attribute_data is: {item_attribute_data}" )
            print()

            item_data = opc_hda.ReadRaw(item_ids[1], start_time, end_time, 100)
          
            print(f"Test ReadRaw for {item_ids[1]}  is: {item_data}" )
            print()
            
        
            print()
            def test_aggregates(opc_hda, item_id, start_time, end_time, interval):
                #aggregates = [1, 3, 4, 10, 11, 12]
                aggregates = [1, 3, 5]
                for agg in aggregates:
                    item_data = opc_hda.ReadProcessed(item_id, start_time, end_time, Interval=interval, Aggregate=agg)
                    print(f"Aggregate {agg} Result for {item_id}: {item_data}")
                    if item_data and item_id in item_data:
                        count = len(item_data[item_id]["values"])
                        logging.warning(f"Aggregate {agg} returned {count} values")

            item_data = test_aggregates(opc_hda,item_ids[1], start_time, end_time, interval=10)
          
            print()

           
           
            validation_results = opc_hda.ValidateItemIDs(item_ids[:3])
            print(f"OPCHDA Validation Results: for {item_ids[:3]}  {validation_results}")
            print()
   
       
            raw_data = opc_hda.SyncReadRaw(item_ids[:3], start_time, end_time, 100)
        
            print(f"OPCHDA SyncReadRaw Test for {item_ids[:3]} is : {raw_data}")
            print()


          
            test_process_ids=item_ids[:3]
            Aggregates=[1]*(len(test_process_ids)+1)
            raw_data = opc_hda.SyncReadProcessed(test_process_ids, start_time, end_time, Interval=60,Aggregates=Aggregates)
        
            print(f"OPCHDA SyncReadProcessed for {item_ids[:3]} is : {raw_data}")
            print()


        
            
           
        else:
            print("Connection failed. Check logs for details.")
    except Exception as e:
        logging.error(f"Error in main: {str(e)}")
    finally:
        opc_hda.disconnect()
        print("disconnected from OPCHDA server")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main()