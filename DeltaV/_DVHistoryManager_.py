import datetime
import json
import asyncio
import logging
from typing import Dict, Optional
from asyncua import ua
from collections import deque  # Added import
from _DVHDA_ import _OPCHDA_
from _DVAE_ import EventChronicleClient
class _OPChistoryManager_:
    def __init__(self,wrapper,server_name: str = "DeltaV.OPCHDAsvr"):
        self._events = {}  # node_id -> deque of (timestamp, event_data)
        self._event_update_rate:int=5
        self._period_event_filters = {
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
                filters=self._period_event_filters
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
