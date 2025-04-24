import logging
import os
import time
import datetime

import pythoncom
import json

from typing import Dict
import asyncio
from asyncua import Server, ua


from asyncua.crypto.security_policies import (
    SecurityPolicy,
    SecurityPolicyBasic256Sha256,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyAes128Sha256RsaOaep
)

from concurrent.futures import ThreadPoolExecutor

from _DVUserManager_ import _OPCUAUserManager_

from _DVSecurity_ import _OPCUASecurity_
from _DVUANode_ import _OPCUANode_
from _DVDAManager_ import _OPCDAManager_
from _DVHistoryManager_ import _OPChistoryManager_



class _OPCWrapper_:

    class Event:
        def __init__(self):
            self.running = asyncio.Event()
            
            self.polling = asyncio.Event()
            self.writing = asyncio.Event()
            self.shutdown = asyncio.Event()
            self.restart = asyncio.Event()
            self.broswe_opcda_struture = asyncio.Event()
            self.update_structure = asyncio.Event()  

   
        


        


    def __init__(self,  name:str= 'OPC.DELTAV.1',nodename:str="PROPLUS", endpoint: str = 'opc.tcp://0.0.0.0:4840'):
        """init the server"""
        self.event = self.Event()
        self.node = _OPCUANode_(name=name,nodename=nodename,endpoint=endpoint,application_uri=name)
        self.security = _OPCUASecurity_(wrapper=self)
        self.da_manager = _OPCDAManager_(wrapper=self,nodename=nodename) 
      
        self.user_manager = _OPCUAUserManager_()  # 强制初始化，避免 None
        self.server = Server(user_manager=self.user_manager)
        self.history_manager=_OPChistoryManager_(wrapper=self)
        self.server.set_server_name(self.node.name)
        logging.info(f"_OPCDAWrapper_.init: welcome  ot _DVWrapper_ OPC SERVER {name}, nodename is {nodename},server endpoint is {endpoint}  ")
        self.server.set_endpoint(self.node.endpoint)  # 设置端点
        logging.info(f"_OPCDAWrapper_.init: Server type: {type(self.server)}, iserver type: {type(self.server.iserver)},user manager set to custom user manager")
        self.executor_browser = ThreadPoolExecutor(max_workers=2)
        self.executor_opcda = ThreadPoolExecutor(max_workers=2)
        self.executor_opchda = ThreadPoolExecutor(max_workers=2)
        self._max_time: float = 9999999.0
      
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
    

    async def GetServerStatus(self) -> dict:
             
            server_details = {
                 
              
               
                "ServerName":  self.node.name,
                "NodeName":  self.node.nodename,
                "application_uri": self.node.application_uri,
                "idx": self.node.idx,
                "endpoint": self.node.endpoint,
              #  "Status": self.server.status,
                "version": '1.0.18',
                "VendorInfo": 'Juda.monster',
                "author": "juda.wu"
            }
             
            return server_details
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

        self.node.parameters_folder = await self.node.da_folder.add_folder(self.node.idx, "Parameters and Methods")  
        self.node.parameters_nodes['PARA1']=await self.node.parameters_folder.add_variable(
            self.node.idx, "uaserver_max_running_time", self.max_time, ua.VariantType.Double
        )
        await self.node.parameters_nodes['PARA1'].set_writable()
        self.node.parameters_nodes['PARA2']=await self.node.parameters_folder.add_variable(
            self.node.idx, "uaserver_manual_stop_flag", self.manual_stop, ua.VariantType.Boolean
        )
        await self.node.parameters_nodes['PARA2'].set_writable()
        self.node.parameters_nodes['PARA3']=await self.node.parameters_folder.add_variable(
            self.node.idx, "da_update_rate_ms", self.da_manager._da_update_rate, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA3'].set_writable()
        self.node.parameters_nodes['PARA4']=await self.node.parameters_folder.add_variable(
            self.node.idx, "ua_update_rate_s", self.da_manager._ua_update_rate, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA4'].set_writable()
        self.node.parameters_nodes['PARA5']=await self.node.parameters_folder.add_variable(
            self.node.idx, "history_event_update_rate_s", self.history_manager._event_update_rate, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA5'].set_writable()
        self.node.parameters_nodes['PARA6']=await self.node.parameters_folder.add_variable(
            self.node.idx, "anonymous_user_allowtime_s", self.user_manager._anonymous_timeout, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA6'].set_writable()
        self.node.parameters_nodes['PARA7']=await self.node.parameters_folder.add_variable(
            self.node.idx, "session_cooldown_time_s", self.user_manager._cooldown_time, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA7'].set_writable()
        self.node.parameters_nodes['PARA8']=await self.node.parameters_folder.add_variable(
            self.node.idx, "session__monitor_period_s", self.user_manager._monitor_period, ua.VariantType.Int64
        )
        await self.node.parameters_nodes['PARA8'].set_writable()

        self.node.events_node = await self.node.da_folder.add_object(self.node.idx, "Alarms and Events")                                  
        await self.node.events_node.write_attribute(
                ua.AttributeIds.EventNotifier,
                ua.DataValue(ua.Variant(5, ua.VariantType.Byte))
            )
        # Enable history for the server
        #self.server.historize_node_event(self.node.events_node, period=None)  # None means store indefinitely
        # Store events for 1 hour
        await self.server.historize_node_event(self.node.events_node, period=datetime.timedelta(minutes=2))
        logging.debug("_OPCDAWrapper_.setup_opc_ua_server: Enabled historical event storage for Alarms and Events node")
        await  self.history_manager.setup_event_type()
        self.node.historian_node = await self.node.da_folder.add_folder(self.node.idx, "Countinuous Historain")  
        logging.debug("_OPCDAWrapper_.setup_opc_ua_server: Created Historian folder")


        # 添加方法并设置权限
        self.node.methods_nodes = {
            "write_items": await self.node.parameters_folder.add_method(
                self.node.idx, "write_items",  self.da_manager.write_items,
                [ua.VariantType.Variant,ua.VariantType.String], [ua.VariantType.Boolean]
            ),
            "add_client_cert": await self.node.parameters_folder.add_method(
                self.node.idx, "add_client_cert", self.security.add_client_certificate,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "generate_server_certificate": await self.node.parameters_folder.add_method(
                self.node.idx, "generate_server_certificate", self.security.generate_server_certificate,
                [], [ua.VariantType.Boolean]
            ),
            "set_server_policy": await self.node.parameters_folder.add_method(
                self.node.idx, "set_server_policy", self.security.set_server_policy,
                [ua.VariantType.String, ua.VariantType.Boolean], [ua.VariantType.Boolean]
            ),
            "restore_initial_certificate": await self.node.parameters_folder.add_method(
                self.node.idx, "restore_initial_certificate", self.security.restore_initial_certificate,
                [], [ua.VariantType.Boolean]
            ),
             "get_connected_clients":await self.node.parameters_folder.add_method(
                                        self.node.idx, "get_connected_clients", self.security.get_connected_clients,
                                        [], [ua.VariantType.String]
             ),
             "disconnect_client": await self.node.parameters_folder.add_method(  
                self.node.idx, "disconnect_client", self.security.disconnect_client,
                [ua.VariantType.String], [ua.VariantType.Boolean]
            ),

            "restart_server": await self.node.parameters_folder.add_method(  
                self.node.idx, "restart_server", self.restart,
                [], [ua.VariantType.Boolean]
            ),
            
            "add_nodes_from_json": await self.node.parameters_folder.add_method(
                self.node.idx, "add_nodes_from_json", self.da_manager.add_nodes_from_json,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "export_nodes_to_json": await self.node.parameters_folder.add_method(
                self.node.idx, "export_nodes_to_json", self.da_manager.export_nodes_to_json,
                [], [ua.VariantType.String]
            ),


            "add_item": await self.node.parameters_folder.add_method(  
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

            "update_parameters_from_json": await self.node.parameters_folder.add_method(
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
                    logging.debug(f"_OPCDAWrapper_.stop:Deleted existing event node {node_id}")
                except Exception as e:
                    logging.warning(f"_OPCDAWrapper_.stop:Failed to delete event node {node_id}: {str(e)}")
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
        """
        Update object attributes from a JSON config dictionary.
        Handles both top-level attributes (e.g., _max_time) and sub-object attributes (e.g., da_manager).
        """
        for group, value in config.items():
            if hasattr(self, group):
                target = getattr(self, group)
                if isinstance(value, dict):
                    # Handle sub-objects (e.g., da_manager, history_manager)
                    for key, sub_value in value.items():
                        if hasattr(target, key):
                            old_value = getattr(target, key)
                            
                            if key == '_retention_period' and isinstance(sub_value, dict):
                                sub_value = datetime.timedelta(**sub_value)
                            setattr(target, key, sub_value)
                            new_value = getattr(target, key)
                            logging.info(f"System paramters changed: Updated {group}.{key}: old value ={old_value},new valuee={new_value}")

                else:
                  
                    old_value = getattr(self, group)
                    setattr(self, group, value)
                    new_value = getattr(self, group)
                    logging.info(f"System paramters changed: Updated {group}: old value ={old_value},new valuee={new_value}")


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
 