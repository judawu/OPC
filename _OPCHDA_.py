import win32com.client
import pythoncom
import pywintypes
from win32com.client import Dispatch, VARIANT

import logging
from datetime import datetime, timedelta, timezone

# OPC HDA 服务器状态枚举
OPCHDA_SERVER_STATUS = {
    1: "OPCHDA_RUNNING",
    2: "OPCHDA_FAILED",
    3: "OPCHDA_NOCONFIG",
    4: "OPCHDA_SUSPENDED",
    5: "OPCHDA_TEST",
    6: "OPCHDA_COMM_FAULT"
}

class _OPCHDA_:
    def __init__(self, server_name: str = "DeltaV.OPCHDAsvr", client_name: str = "PythonOPCHDAClient"):
        self.server_name = server_name
        self.opc_hda = None
        self.hda_server = None
        self.connected = False
        self.client_name = client_name
        self.shutdown_handler = None

    def connect(self) -> bool:
        logging.debug(f"_OPCHDA_: Attempting to connect to {self.server_name}")
        try:
            pythoncom.CoInitialize()
            self.opc_hda = win32com.client.Dispatch("OpcHda.Automation")
            logging.debug(f"_OPCHDA_: Successfully created OpcHda.Automation instance")

            if hasattr(self.opc_hda, "Parent"):
                self.hda_server = self.opc_hda.Parent
                logging.debug(f"_OPCHDA_: Successfully accessed Parent")
               # logging.debug(f"_OPCHDA_: Available methods on Parent: {dir(self.hda_server)}")

                self.hda_server.Connect(self.server_name)
                logging.debug(f"_OPCHDA_: Successfully called Connect({self.server_name})")
                # logging.debug(f"_OPCHDA_: hda_server  BuildNumber: {self.hda_server.BuildNumber}")
                # logging.debug(f"_OPCHDA_: hda_server  CLSID: {self.hda_server.CLSID}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncDeleteAtTime: {self.hda_server.CanAsyncDeleteAtTime}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncDeleteRaw: {self.hda_server.CanAsyncDeleteRaw}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncInsert: {self.hda_server.CanAsyncInsert}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncInsertAnnotations: {self.hda_server.CanAsyncInsertAnnotations}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncInsertReplace: {self.hda_server.CanAsyncInsertReplace}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncReadAnnotations: {self.hda_server.CanAsyncReadAnnotations}")
                # logging.debug(f"_OPCHDA_: hda_server  CanAsyncReplace: {self.hda_server.CanAsyncReplace}")


              
                # logging.debug(f"_OPCHDA_: hda_server dir  ClientName: {dir(self.hda_server.ClientName)}")
                # logging.debug(f"_OPCHDA_: hda_server  dir CreateBrowser: {dir(self.hda_server.CreateBrowser)}")
                # logging.debug(f"_OPCHDA_: hda_server dr=ir GetAggregates: {dir(self.hda_server.GetAggregates)}")
                # logging.debug(f"_OPCHDA_: hda_server dir GetErrorString: {dir(self.hda_server.GetErrorString)}")
                # logging.debug(f"_OPCHDA_: hda_server dir GetItemAttributes: {dir(self.hda_server.GetItemAttributes)}")
                # logging.debug(f"_OPCHDA_: hda_server dir  GetOPCHDAServers: {dir(self.hda_server.GetOPCHDAServers)}")
                # logging.debug(f"_OPCHDA_: hda_server dir  HistorianStatus: {self.hda_server.HistorianStatus}")
                # logging.debug(f"_OPCHDA_: hda_server  LocaleID: {self.hda_server.LocaleID}")
                # logging.debug(f"_OPCHDA_: hda_server  MajorVersion: {self.hda_server.MajorVersion}")
                # logging.debug(f"_OPCHDA_: hda_server  MaxReturnValues: {self.hda_server.MaxReturnValues}")
                # logging.debug(f"_OPCHDA_: hda_server  MinorVersion: {self.hda_server.MinorVersion}")
                # logging.debug(f"_OPCHDA_: hda_server  MaxReturnValues: {self.hda_server.MaxReturnValues}")
                # logging.debug(f"_OPCHDA_: hda_server dir OPCHDAItems: {dir(self.hda_server.OPCHDAItems)}")

                # logging.debug(f"_OPCHDA_: hda_server  ServerName: {self.hda_server.ServerName}")
                # logging.debug(f"_OPCHDA_: hda_server  ServerNode: {self.hda_server.ServerNode}")
                # logging.debug(f"_OPCHDA_: hda_server  StartTime: {self.hda_server.StartTime}")
                # logging.debug(f"_OPCHDA_: hda_server  VendorInfo: {self.hda_server.VendorInfo}")
                # logging.debug(f"_OPCHDA_: hda_server dir  __static_attributes__: {dir(self.hda_server.__static_attributes__)}")
                # logging.debug(f"_OPCHDA_: hda_server dir  __init__: {dir(self.hda_server.__init__)}")
                # logging.debug(f"_OPCHDA_: hda_server dir  __init_subclass__: {dir(self.hda_server.__init_subclass__)}")
                # logging.debug(f"_OPCHDA_: hda_server dir  __doc__: {dir(self.hda_server.__doc__)}")
                # logging.debug(f"_OPCHDA_: hda_server  dir __module__: {dir(self.hda_server.__module__)}")

                # logging.debug(f"_OPCHDA_: hda_server  dir __weakref___: {dir(self.hda_server.__weakref__)}")
                # logging.debug(f"_OPCHDA_: hda_server  dir _get_good_object_: {dir(self.hda_server._get_good_object_)}")
                # logging.debug(f"_OPCHDA_: hda_server  _get_good_single_object_: {dir(self.hda_server._get_good_single_object_)}")
                # logging.debug(f"_OPCHDA_: hda_server  _oleobj_: {dir(self.hda_server._oleobj_)}")
                # logging.debug(f"_OPCHDA_: hda_server  _prop_map_get_: {dir(self.hda_server._prop_map_get_)}")
                # logging.debug(f"_OPCHDA_: hda_server  _prop_map_put_: {dir(self.hda_server._prop_map_put_)}")
                # logging.debug(f"_OPCHDA_: hda_server  coclass_clsid: {dir(self.hda_server.coclass_clsid)}")
                status = self.get_historian_status()
                if status:
                    self.connected = True
                    logging.info(f"_OPCHDA_: Successfully connected to {self.server_name}")
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
                self.shutdown_handler = win32com.client.WithEvents(self.hda_server, OPCShutdownHandler)
                self.shutdown_handler.callback = self.on_shutdown

    def disconnect(self):
        if self.connected:
            try:
                self.hda_server.Disconnect()
                self.connected = False
                logging.info(f"_OPCHDA_: Successfully disconnected from {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCHDA_: Failed to disconnect from {self.server_name}: {str(e)}")
            finally:
                if self.shutdown_handler:
                    del self.shutdown_handler
                self.hda_server = None
                self.opc_hda = None
                pythoncom.CoUninitialize()

    def on_shutdown(self, reason: str):
        logging.info(f"_OPCHDA_: Shutdown request received from {self.server_name}: {reason}")
        self.disconnect()

    def get_historian_status(self) -> dict:
        if not self.hda_server:
            logging.error("_OPCHDA_: No server interface available")
            return {}
        try:
            status_code = self.hda_server.HistorianStatus
            status_str = OPCHDA_SERVER_STATUS.get(status_code, f"Unknown status: {status_code}")
            return {
                "Status": status_str,
                "CurrentTime": str(self.hda_server.CurrentTime),
                "ServerName": str(self.hda_server.ServerName),
                "MaxReturnValues": str(self.hda_server.MaxReturnValues)
            }
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to get historian status: {str(e)}")
            return {}
    def get_item_attributes(self) -> list:
        """获取支持的项属性列表"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_: Not connected to server")
            return []

        try:
            attributes = self.hda_server.GetItemAttributes()
            if isinstance(attributes, tuple):
                attr_count, attr_ids, attr_names, attr_descs, attr_types = attributes
                attr_list = [
                    {"id": attr_ids[i], "name": attr_names[i], "description": attr_descs[i], "type": attr_types[i]}
                    for i in range(attr_count)
                ]
            else:
                attr_list = list(attributes)
            logging.info("_OPCHDA_: Successfully retrieved item attributes")
            return attr_list
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to get item attributes: {str(e)}")
            return []
    def browse_items(self) -> list:
        """浏览所有 OPC HDA Item IDs"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_: Not connected to server")
            return []

        try:
            browser_tuple = self.hda_server.CreateBrowser()
           # logging.debug(f"_OPCHDA_: CreateBrowser returned: {browser_tuple}")
            browser = browser_tuple[0]  # 提取浏览器对象

            # 打印浏览器对象的可用方法
            # browser_methods = dir(browser)
            # logging.debug(f"_OPCHDA_: Browser methods: {browser_methods}")

            items = []
            try:
                # 尝试获取当前位置的项
                hda_items = browser.OPCHDAItems
                for item in hda_items:
                    items.append(item)
                logging.info(f"_OPCHDA_: Successfully browsed {len(items)} items at current level")
            except Exception as e:
                logging.warning(f"_OPCHDA_: Failed to get items at current level: {e}")

            # 注意：更完整的浏览可能需要递归地遍历分支 (OPCHDABranches)
            # 并使用 MoveDown 等方法。这取决于 DeltaV OPC HDA 服务器的实现。

            return items
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to browse items: {str(e)}", exc_info=True)
            return []
        
    
    def validate_item_ids(self, item_ids: list) -> dict:
        """验证指定的 Item IDs 是否有效 (使用 Validate 方法 - 临时方案)"""
        if not self.connected or not self.hda_server:
            logging.error("_OPCHDA_: Not connected to server")
            return {}

        validation = {}
        if not item_ids:
            return validation

        try:
            sync_read = self.hda_server.OPCHDAItems
            if hasattr(sync_read, 'Validate'):
                num_items = len(item_ids)
                validate_count = num_items-1  if num_items > 0 else 0
                logging.debug(f"_OPCHDA_: Calling Validate with num_items: {validate_count}, item_ids (first {validate_count}): {item_ids[:validate_count]}")
                try:
                    results = sync_read.Validate(validate_count, item_ids)
                    logging.debug(f"_OPCHDA_: Validate results: {results}")
                    if isinstance(results, tuple):
                        for i in range(min(validate_count, len(results))):
                            validation[item_ids[i]] = (results[i] == 0)
                        if len(results) < validate_count:
                            logging.warning(f"_OPCHDA_: Validate returned {len(results)} results for {validate_count} items.")
                    else:
                        logging.warning("_OPCHDA_: Validate method returned unexpected result format.")
                        # Fallback to single item validation if needed
                    for item_id in item_ids:
                            
                            validation[item_id] = self._validate_single_item_add(item_id)

                    logging.info(f"_OPCHDA_: Successfully validated item IDs using Validate (temporary): {validation}")

                except pywintypes.com_error as e:
                    logging.error(f"_OPCHDA_: COM error during Validate: {e.excepinfo}")
                    validation = {item_id: self._validate_single_item_add(item_id) for item_id in item_ids}
                except Exception as e:
                    logging.error(f"_OPCHDA_: Unexpected error during Validate: {e}", exc_info=True)
                    validation = {item_id: self._validate_single_item_add(item_id) for item_id in item_ids}
            else:
                logging.warning("_OPCHDA_: Validate method not found, using individual AddItem for validation.")
                for item_id in item_ids:
                    validation[item_id] = self._validate_single_item_add(item_id)
            return validation
        except Exception as e:
            logging.error(f"_OPCHDA_: Failed to validate item IDs: {str(e)}", exc_info=True)
            return {}

    def _validate_single_item_add(self, item_id: str) -> bool:
        """使用 AddItem 方法验证单个 Item ID"""
        sync_read = self.hda_server.OPCHDAItems
        try:
            item = sync_read.AddItem(item_id,0)  #AddItem 方法的第二个参数 0 代表的是 客户端句柄 (Client Handle)
          
            if item.ServerHandle is not None:
                sync_read.Remove(item.ServerHandle)
                return True
            else:
                logging.debug(f"_OPCHDA_: Item {item_id} added but returned no valid ServerHandle")
                return False
        except pywintypes.com_error as e:
            logging.debug(f"_OPCHDA_: Failed to add item {item_id}: {e.excepinfo}")
            return False
        except Exception as e:
            logging.debug(f"_OPCHDA_: Unexpected error for item {item_id}: {str(e)}")
            return False
    def read_raw(self, item_ids: list, start_time: datetime, end_time: datetime, max_values: int = 0) -> dict:
            if not self.connected or not self.hda_server:
                logging.error("_OPCHDA_: Not connected to server")
                return {}

            try:
                sync_read = self.hda_server.OPCHDAItems
                num_items = len(item_ids)
                client_handles = list(range(num_items))
               # logging.debug(f"Calling AddItems with: {num_items}, {item_ids}, {client_handles}")

                server_handles = []
                items = sync_read.AddItems(num_items-1, item_ids, client_handles)   # I don't know why only support num_items-1 items
                last_item = sync_read.AddItem(item_ids[-1],client_handles[-1])
        
               
                server_handles = [handle for handle in items[0]] # items[0] is server_handles
                server_handles.append(last_item.ServerHandle)
                server_handles.append(last_item.ServerHandle)   #  I need to add the last ServerHandle again to get alll the items_id working
                #logging.debug(f"AddItems : {item_ids}, server handles is {server_handles}, nums: {len(server_handles)} ")
             
              
                results = sync_read.SyncReadRaw(start_time, end_time, max_values, 2, len(server_handles)-1, server_handles)   # why not working for last server_handles
               
        
                
                #SyncReadRaw', 的参数有,StartTime , EndTime, NumValues, Bounds, NumItems, ServerHandles
                 #据 OPC HDA 的规范，Bounds 参数可以有以下几种常见的值：
                # 0 或 OPCHDA_BOUND_NONE: 不包含起始时间和结束时间边界上的值。只返回严格在指定时间范围内的历史数据。
                # 1 或 OPCHDA_BOUND_START: 包含起始时间边界上的值（如果存在）。
                # 2 或 OPCHDA_BOUND_END: 包含结束时间边界上的值（如果存在）。
                # 3 或 OPCHDA_BOUND_BOTH: 包含起始时间和结束时间边界上的值（如果存在
               # logging.debug(f"_OPCHDA_: Calling SyncReadRaw results: {results}")

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
                            if hasattr(history_object, 'Count'):
                                
                                count = history_object.Count
                                logging.debug(f"_OPCHDA_: Number of historical values for {item_id}: {count}")
                                for j in range(count):
                                    try:
                                        record = history_object.Item(j+1)
                                        # logging.debug(f"_OPCHDA_: Record {j+1} for {item_id}: {record}, type: {type(record)}")
                                        logging.debug(f"_OPCHDA_: get Record {j+1} at  ({record.DataValue},{record.Quality},{record.TimeStamp})")
                                        values.append(record.DataValue)
                                        qualities_list.append(record.Quality)
                                        timestamps.append(record.TimeStamp)
                                        
                                    except Exception as e:
                                        logging.warning(f"_OPCHDA_: Error accessing record {j} for {item_id}: {e}")
                        

                            else:
                                logging.warning(f"_OPCHDA_: History object for {item_id} does not have a 'Count' attribute.")

                        except Exception as e:
                            logging.warning(f"_OPCHDA_: Error accessing history data for {item_id}: {e}")

                        data[item_id] = {
                            "values": values,
                            "values type": [type(v) for v in values],
                            "qualities": qualities_list,
                            "timestamps": timestamps
                        }
                    
                           

                else:
                        logging.warning("_OPCHDA_: Unexpected format of SyncReadRaw results.")
                        for item_id in item_ids:
                            data[item_id] = {"values": [], "qualities": [], "timestamps": []}

                #logging.info(f"_OPCHDA_: Successfully read raw data for {item_ids} : {data}")
             
             
                return data
            except Exception as e:
                    logging.error(f"_OPCHDA_: Failed to read raw data: {str(e)}", exc_info=True)
                    return {}
class OPCShutdownHandler:
    def __init__(self, callback=None):
        self.callback = callback

    def ShutdownRequest(self, Reason):
        if self.callback:
            self.callback(Reason)
    
def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    opc_hda = _OPCHDA_()
    try:
        if opc_hda.connect():
            print(f"Connected to {opc_hda.server_name}")
            status = opc_hda.get_historian_status()
            print("Historian Status:", status)
               # 测试获取项属性
            # attributes = opc_hda.get_item_attributes()
            # print("Item Attributes:", attributes)

            # Browse items and pick a valid one
            items = opc_hda.browse_items()
            print("Browsed Items:", items[:10])
            item_ids = items[:2] if items else ["V1-IO/DO1_NA_PV.CV","V1-IO/PH1_MV_PV.CV"]

            # # 使用新的 validate_item_ids 方法，传递 item_ids 和 browsed_items
            # validation_results = opc_hda.validate_item_ids(item_ids)
            # print("Validation Results (using Validate method ", validation_results)


            end_time = datetime.now() + timedelta(hours=24)
            start_time = end_time - timedelta(hours=24)
            raw_data = opc_hda.read_raw(item_ids, start_time, end_time, 1000)
            print("Raw Data:", raw_data)
            

            
           
        else:
            print("Connection failed. Check logs for details.")
    except Exception as e:
        logging.error(f"Error in main: {str(e)}")
    finally:
        opc_hda.disconnect()

if __name__ == "__main__":
    main()