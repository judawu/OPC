import asyncio
import logging
from asyncua import Server, ua
from typing import List, Dict, Tuple, Optional
import pythoncom
from concurrent.futures import ThreadPoolExecutor
import time
from queue import Queue, Empty
from _OPCDA_ import _OPCDA_, OPCDADataCallback

class _OPCDAWrapper_:
    def __init__(self, opc_da: '_OPCDA_', endpoint: str = "opc.tcp://0.0.0.0:4840"):
        self.opc_da = opc_da
        self.callback = OPCDADataCallback(self.custom_callback)
        self.endpoint = endpoint
        self.server = Server()
        self.nodes: Dict[str, ua.Node] = {}
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.running = False
        self.group_name = None
        self.polling = False
        self.writing = False
        self.poll_queue = Queue()
        self.write_queue = Queue()
        self.shutdown_event = asyncio.Event()
        self.da_folder = None
        self.idx = None
        self.update_count = 0
        self.max_updates = None

    async def setup_opc_ua_server(self):
        await self.server.init()
        self.server.set_endpoint(self.endpoint)
        self.server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
     
        endpoints = await self.server.iserver.isession.get_endpoints()
        logging.info(f"Endpoints after setup: {endpoints}")
        self.server.set_server_name("OPC DA to UA Bridge")
        uri = "urn:opcda:wrapper"
        self.idx = await self.server.register_namespace(uri)
        logging.info(f"Registered namespace index: {self.idx}")
        objects = self.server.nodes.objects
        self.da_folder = await objects.add_folder(self.idx, "OPC_DA_Items")

        async def write_to_opc_da(parent, items_variant, values_variant):
            logging.info(f"write_to_opc_da called with items_variant: {items_variant}, values_variant: {values_variant}")
            try:
                items = items_variant.Value
                values = [val.Value for val in values_variant.Value]
                logging.info(f"Parsed items: {items}, values: {values}")
                results = await self.async_write(items, values)
                logging.info(f"async_write returned: {results}")

                # 更新 UA 节点
                for item, value, success in zip(items, values, results):
                    if not success:
                        continue
                    ua_name = item.replace('/', '_')
                    if item not in self.nodes:
                        # 根据值类型选择 VariantType
                        if isinstance(value, int):
                            variant_type = ua.VariantType.Int64
                        elif isinstance(value, float):
                            variant_type = ua.VariantType.Double
                        elif isinstance(value, str):
                            variant_type = ua.VariantType.String
                        else:
                            variant_type = ua.VariantType.Variant
                        node = await self.da_folder.add_variable(self.idx, ua_name, value, varianttype=variant_type)
                        self.nodes[item] = node
                        logging.info(f"Created UA node for {item} with value {value} and type {variant_type}")
                    else:
                        # 检查现有节点类型并转换值
                        node = self.nodes[item]
                        data_value = await node.read_data_value()
                        current_type = data_value.Value.VariantType
                        try:
                            if current_type == ua.VariantType.Double and isinstance(value, int):
                                value = float(value)  # 将 Int64 转换为 Double
                            elif current_type == ua.VariantType.Int64 and isinstance(value, float):
                                value = int(value)  # 将 Double 转换为 Int64
                            await node.write_value(value)
                            logging.debug(f"Updated UA node {item} with value {value}")
                        except ua.UaStatusCodeError as e:
                            logging.warning(f"Failed to update UA node {item} with value {value}: {e}")

                return [ua.Variant(results, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"Error in write_to_opc_da: {str(e)}")
                raise

        method_node = await self.da_folder.add_method(
            self.idx, "write_to_opc_da", write_to_opc_da,
            [ua.VariantType.String, ua.VariantType.Variant], [ua.VariantType.Boolean]
        )
        logging.info(f"Added OPC UA method 'write_to_opc_da' with NodeId: {method_node.nodeid}")
        logging.info("OPC UA server initialized with NoSecurity policy")

    async def update_ua_nodes(self, items: List[str]):
        last_values = {}
        while not self.shutdown_event.is_set():
            for item in items:
                data = self.callback.get_data(item)
                if data and data[1] != 0:
                    value, quality, timestamp = data
                    status = ua.StatusCode(ua.StatusCodes.Good) if quality == 192 else ua.StatusCode(ua.StatusCodes.Bad)
                    if item not in last_values or last_values[item] != value:
                        if item not in self.nodes:
                            if isinstance(value, float):
                                variant_type = ua.VariantType.Double
                                initial_value = float(value)
                            elif isinstance(value, str):
                                variant_type = ua.VariantType.String
                                initial_value = str(value)
                            elif isinstance(value, int):
                                variant_type = ua.VariantType.Int32
                                initial_value = int(value)
                            else:
                                variant_type = ua.VariantType.String
                                initial_value = str(value)
                            node = await self.da_folder.add_variable(self.idx, item.replace('/', '_'), initial_value, varianttype=variant_type)
                            await node.set_writable(True)
                            self.nodes[item] = node
                            node_id = node.nodeid
                            logging.info(f"Added UA node for {item} with type {variant_type}, NodeId: {node_id}")

                        node = self.nodes[item]
                        node_type = await node.read_data_type()
                        if node_type == ua.NodeId(11, 0):
                            variant_value = float(value)
                        elif node_type == ua.NodeId(12, 0):
                            variant_value = str(value)
                        elif node_type == ua.NodeId(6, 0):
                            variant_value = int(value)
                        else:
                            logging.warning(f"Unsupported node type for {item}")
                            continue

                        try:
                            variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                            await node.write_value(ua.DataValue(variant, status))
                            self.update_count += 1
                            last_values[item] = value
                            if self.max_updates and self.update_count >= self.max_updates:
                                logging.info(f"Reached max updates ({self.max_updates}), stopping subscription...")
                                self.shutdown_event.set()
                        except ua.UaStatusCodeError as e:
                            logging.error(f"Failed to write {item}: {str(e)}")
            await asyncio.sleep(1)
        logging.debug("update_ua_nodes stopped")

    def opc_da_thread(self, items: List[str], group_name: str, update_rate: int):
        pythoncom.CoInitialize()
        try:
            if not self.opc_da.connected:
                self.opc_da.connect()
            self.group_name = group_name
            self.opc_da.subscribe(items, group_name=group_name, update_rate=update_rate, callback=self.custom_callback)
            logging.info(f"Subscription started for group {group_name}")

            while not self.shutdown_event.is_set():
                try:
                    poll_data = self.poll_queue.get_nowait()
                    items_to_poll, interval, max_count, max_time = poll_data
                    logging.info(f"Starting poll for {items_to_poll} every {interval} seconds")
                    start_time = time.time()
                    count = 0
                    while self.polling and not self.shutdown_event.is_set() and (max_count is None or count < max_count) and (max_time is None or time.time() - start_time < max_time):
                        try:
                            results = self.opc_da.read(items_to_poll)
                            self.custom_callback(items_to_poll, results)
                        except Exception as e:
                            logging.error(f"Poll read error: {str(e)}")
                        count += 1
                        time.sleep(interval)
                    logging.info("Polling completed")
                    self.polling = False
                except Empty:
                    pass

                try:
                    write_data = self.write_queue.get_nowait()
                    items_to_write, values, write_group_name, write_update_rate, future = write_data
                    logging.debug(f"Starting write operation for {items_to_write}")
                    start_time = time.time()
                    while self.writing and not self.shutdown_event.is_set() and (time.time() - start_time < 10):
                        try:
                            results = self.opc_da.write(items_to_write, values, write_group_name, write_update_rate)
                            if all(results):
                                logging.info(f"Successfully wrote {values} to {items_to_write}")
                            else:
                                failed_items = [item for item, success in zip(items_to_write, results) if not success]
                                logging.warning(f"Partially succeeded: Failed to write to {failed_items}")
                            logging.debug(f"Write results for {items_to_write}: {results}")
                            future.set_result(results)
                            break
                        except Exception as e:
                            logging.error(f"Write error in opc_da_thread: {str(e)}")
                            future.set_exception(e)
                            break
                    if self.writing and time.time() - start_time >= 10:
                        logging.error(f"Write to {items_to_write} timed out after 10 seconds")
                        future.set_exception(asyncio.TimeoutError("Write operation timed out"))
                    self.writing = False
                except Empty:
                    pass

                pythoncom.PumpWaitingMessages()
                time.sleep(0.01)
        except Exception as e:
            logging.error(f"OPC DA thread error: {str(e)}")
        finally:
            try:
                if self.group_name and self.opc_da.connected:
                    self.opc_da.stop_subscribe(self.group_name)
                    logging.info(f"Subscription {self.group_name} stopped")
                if self.opc_da.connected:
                    self.opc_da.disconnect()
                    logging.info("Disconnected from OPC server")
            except Exception as e:
                logging.error(f"Cleanup error in thread: {str(e)}")
            finally:
                pythoncom.CoUninitialize()
                logging.debug("OPC DA thread exiting")

    async def async_poll(self, items: List[str], interval: float = 1.0, max_count: Optional[int] = None, max_time: Optional[float] = None):
        if self.polling:
            logging.warning("Polling already in progress")
            return
        self.polling = True
        self.poll_queue.put((items, interval, max_count, max_time))
        try:
            await asyncio.wait_for(self._wait_for_polling(), timeout=max_time or 60)
        except asyncio.TimeoutError:
            logging.warning(f"Polling for {items} timed out")
            self.polling = False
        logging.debug(f"Poll task for {items} exited at {time.strftime('%H:%M:%S')}")

    async def _wait_for_polling(self):
        while self.polling and not self.shutdown_event.is_set():
            await asyncio.sleep(0.1)
        return True

    async def async_write(self, items: List[str], values: List[any], group_name: str = "WriteGroup", update_rate: int = 1000):
        logging.info(f"Attempting to write {values} to {items}")
        if not self.running:
            logging.error("Cannot write: OPC DA wrapper is not running")
            return None
        if not self.opc_da.connected:
            logging.error("Cannot write: OPC DA server is not connected")
            return None
        if len(items) != len(values):
            logging.error("Cannot write: Number of items and values must match")
            return None
        if self.writing:
            logging.warning("Write operation already in progress")
            return None

        future = asyncio.Future()
        self.writing = True
        self.write_queue.put((items, values, group_name, update_rate, future))
        try:
            results = await asyncio.wait_for(future, timeout=10)
            logging.debug(f"Write task for {items} completed at {time.strftime('%H:%M:%S')}")
            return results
        except asyncio.TimeoutError:
            logging.error(f"Write to {items} timed out")
            return None
        finally:
            self.writing = False

    def custom_callback(self, paths: List[str], results: List[Tuple[any, int, str]]):
        for path, (value, quality, timestamp) in zip(paths, results):
            if quality == 192:
                self.callback.data[path] = (value, quality, timestamp)
                print(f"Poll/Subscribe: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
                logging.debug(f"UA Callback: {path} = {value}, Quality={quality}, Timestamp={timestamp}")

    async def start(self, items: List[str], group_name: str = "UA_SubscribeGroup", update_rate: int = 1000, max_updates: Optional[int] = None):
        
        
        self.running = True
        self.max_updates = max_updates
        self.shutdown_event.clear()
        loop = asyncio.get_running_loop()
        opc_da_task = loop.run_in_executor(self.executor, self.opc_da_thread, items, group_name, update_rate)
        
        await self.setup_opc_ua_server()
       
        async with self.server:
            await asyncio.sleep(0.1)
            endpoints = await self.server.iserver.isession.get_endpoints()
            logging.info(f"Endpoints after setup: {endpoints}")
            update_task = asyncio.create_task(self.update_ua_nodes(items))
            try:
                await asyncio.gather(opc_da_task, update_task)
            except asyncio.CancelledError:
                logging.info("Tasks cancelled, shutting down...")
            except Exception as e:
                logging.error(f"Start failed: {str(e)}")
                raise
            finally:
                self.running = False
                self.shutdown_event.set()
                update_task.cancel()
                try:
                    await opc_da_task
                except Exception as e:
                    logging.error(f"opc_da_task failed to complete: {str(e)}")
                logging.debug(f"Start task completed at {time.strftime('%H:%M:%S')}")
                await asyncio.sleep(3)

    async def stop(self):
        self.running = False
        self.polling = False
        self.writing = False
        self.shutdown_event.set()
        try:
            self.executor.shutdown(wait=True)
            logging.info("Executor shutdown completed")
        except Exception as e:
            logging.error(f"Executor shutdown error: {str(e)}")
            self.executor.shutdown(wait=False)
        await asyncio.sleep(1)
        await self.server.stop()
        logging.info(f"Shutdown complete at {time.strftime('%H:%M:%S')}")

async def main(max_time: Optional[float] = None, max_count: Optional[int] = None, manual_stop: bool = False):
    opc_da = _OPCDA_()
    wrapper = _OPCDAWrapper_(opc_da)
    items = [
        "V1-IO/AI1_SCI1.EU100",
        "V1-IO/DO1_NA_PV.CV",
        "V1-AI-1/FS_CTRL1/MOD_DESC.CV",
        "V1-TIC-VSL/PID1/MODE.TARGET",
        "V1-AIC-DO/HI_ALM.CUALM",
        "V1-TIC-JKT/HEAT_OUT_D.CV"
    ]
    
    try:
        subscription_task = asyncio.create_task(wrapper.start(items, max_updates=max_count))
        other_tasks = []

        poll_task = asyncio.create_task(wrapper.async_poll(items, interval=2.0, max_time=10.0))
        other_tasks.append(poll_task)

        if manual_stop:
            async def check_manual_stop():
                await asyncio.sleep(30)
                if not wrapper.shutdown_event.is_set():
                    logging.info("Manual stop triggered")
                    await wrapper.stop()
            manual_task = asyncio.create_task(check_manual_stop())
            other_tasks.append(manual_task)

        logging.info(f"Starting: subscription_task with max_time={max_time}, {len(other_tasks)} other tasks")

        if max_time:
            done, pending = await asyncio.wait([subscription_task], timeout=max_time)
            if subscription_task in done:
                logging.info("Subscription task completed within max_time")
            else:
                logging.info(f"Subscription task reached max_time of {max_time} seconds, stopping...")
                subscription_task.cancel()
                try:
                    await subscription_task
                except asyncio.CancelledError:
                    logging.debug("Subscription task cancelled due to timeout")
        else:
            await subscription_task

        if other_tasks:
            logging.info(f"Waiting for {len(other_tasks)} other tasks to complete")
            await asyncio.wait(other_tasks, return_when=asyncio.ALL_COMPLETED)

    except KeyboardInterrupt:
        logging.info("Received Ctrl+C, stopping...")
    except Exception as e:
        logging.error(f"Main error: {str(e)}")
    finally:
        logging.info("Initiating final shutdown")
        await wrapper.stop()
        all_tasks = [subscription_task] + other_tasks
        for task in all_tasks:
            if not task.done():
                logging.warning(f"Task {task} still running, forcing cancellation")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    logging.debug(f"Task {task} cancelled in finally block")
        # 关闭事件循环
        loop = asyncio.get_running_loop()
        loop.stop()
        logging.info("Event loop stopped")
      

if __name__ == "__main__":
   
    logging.getLogger('asyncua').setLevel(logging.WARNING)

    #asyncio.run(main(max_time=60, max_count=10, manual_stop=False))
    asyncio.run(main(manual_stop=False))
