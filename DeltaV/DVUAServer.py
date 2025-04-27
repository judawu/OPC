
import logging
import os
import json
import random


from typing import  Optional
import asyncio
from asyncua import  ua
from _DVWrapper_ import _OPCWrapper_
from _DVLicManager_ import _DVLicManager_
import _DVUALogger_ as opcua_loggeer
async def DVOPCUAsever(max_time: Optional[float] = None, max_items: Optional[int] = 100000):   
    try:
       
    
        wrapper = _OPCWrapper_()  

        simulate_items = [
        "V1-IO/AI1_SCI1.EU100",
        "V1-IO/DO1_NA_PV.CV",
        "V1-AI-1/FS_CTRL1/MOD_DESC.CV",
        "V1-TIC-VSL/PID1/MODE.TARGET",
        "V1-AIC-DO/HI_ALM.CUALM",
        "V1-TIC-JKT/HEAT_OUT_D.CV"
     
        ]

        diagnostics_items= [
            f"{wrapper._nodename}/FREDISK.CV",
            f"{wrapper._nodename}/FREMEM.CV",
            f"{wrapper._nodename}/OINTEG.CV",
            f"{wrapper._nodename}/ISACTIVE.CV",
            f"{wrapper._nodename}/SWREV.CV",
            f"{wrapper._nodename}/FAILED_ALM.CV"              
        ]
        # 启动服务
        print(diagnostics_items)
        items=simulate_items+diagnostics_items
        while True:
            wrapper.da_manager._max_items=max_items
          
            await wrapper.da_manager.append_items(items)      
            start_task = asyncio.create_task(wrapper.start())   
            # 初始添加节点

            await asyncio.sleep(10)
            server_status= await wrapper.GetServerStatus()
            logging.info(f"OPC UA SERVER status :{json.dumps(server_status, indent=6,ensure_ascii=False)}")
            
            print(f"_OPCDAWrapper_.main: add simulate items {items} ")
            await wrapper.da_manager.add_items(simulate_items, "MODULES.AREA_V1")
            await asyncio.sleep(5)
            await wrapper.da_manager.add_items(diagnostics_items, "DIAGNOSTICS")
            await asyncio.sleep(5)
            # 示例：动态调用 update_node
            new_item = await wrapper.da_manager.update_node("MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE.EU100")
            print(f"_OPCDAWrapper_.main: Added new item: {new_item}")
            await asyncio.sleep(10)
            
            # 示例：动态调用 broswe_folder
            await wrapper.da_manager.broswe_folder(base_path="MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
            print("_OPCDAWrapper_.main: Browsed and updated structure under MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
            await asyncio.sleep(30)
            await wrapper.da_manager.remove_items(simulate_items)
            print("_OPCDAWrapper_.main: Remove items from subcrible")
            # Example: Call update_parameters_from_json
            await asyncio.sleep(30)
            sample_config = {

           
                "_manual_stop": False,
                "da_manager": {
                    "_da_update_rate": 2000,
                    "_ua_update_rate": 2,
                    "_da_subscribe_waittime": 2
                   
            
                },
                "history_manager": {
                    "_event_update_rate": 3,
                    "_retention_period": {"days": 1} , # Will be converted to timedelta
                    "_period_event_filters" : {
                                    "Category": ["PROCESS"],
                                #  "Event_Type":["ALARM","EVENT","CHANGE"],
                                #  "Attribute": ["LO_ALM","LO_LO_ALM","HI_ALM","HI_HI_ALM","PVBAD_ALM"],
                                    "Area":["AREA_V1","AREA_V2","AREA_A"]
                                                                        
                                }
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
        
            
          
            if max_time :  
                       
                await asyncio.wait([start_task], timeout=max_time)                  
            else:
                await start_task
          
                
            if wrapper.event.restart.is_set():
                  continue
            else:
                 break
              
           
             
           
      
             
                
            
    except Exception as e:
        logging.error(f"_OPCDAWrapper_.main: Error: {str(e)}")
    finally:
        if wrapper is not None:
            await wrapper.stop(restore_init_cert=True)
        if start_task is not None and not start_task.done():
            start_task.cancel()
            try:
                await start_task
            except asyncio.CancelledError:
                logging.debug("_OPCDAWrapper_.main: Handled CancelledError in start_task")
        print("_OPCDAWrapper_.main: Shutdown complete")

async def main():
        
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'opcuuaserver.log')
 
    
   
   
    
    # Setup logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
  
    
    # Example: Set logging level (can be changed as needed)
    opcua_loggeer.set_logging_level(0)
    
    # Start daily log rotation task
    rotate_task  = asyncio.create_task(opcua_loggeer.rotate_daily_logs(log_file))
    
    # Start log cleanup task (example: monthly cleanup)
    cleanup_task =asyncio.create_task(opcua_loggeer.cleanup_old_logs('month', log_dir))
    logging.getLogger('asyncua').setLevel(logging.WARNING)
    try:
        license_manager=_DVLicManager_()
        license_manager.run()
        license_type=license_manager._license_type    
        if license_type== 100:
            print(f"you are very lunck to run the servcie for ever")
            await DVOPCUAsever()
        elif license_type== 99:
            print(f"you are run in a 100000 DST license")
            await DVOPCUAsever(max_items=100000)
        elif license_type== 98:
            print(f"you are run in a 50000 DST license")
            await DVOPCUAsever(max_items=50000)
        elif license_type== 97:
            await DVOPCUAsever(max_items=20000)
        elif license_type== 96:
            await DVOPCUAsever(max_items=10000)
        elif license_type== 95:
            await DVOPCUAsever(max_items=5000)
            await DVOPCUAsever(max_items=2000)
        elif license_type== 93:
            await DVOPCUAsever(max_items=1000)
        elif license_type== 2:
            await DVOPCUAsever(max_time=14400.0)
        elif license_type== 1:
            print(f"valid license not found, Running in simulate mode with license")
            await DVOPCUAsever(max_time=3600.0)
        elif license_type== 5:
            print(f"Simluate 3 minute test License ")
            await DVOPCUAsever(max_time=180.0)
            print(f"Simluate 3 minute test License , 3 minutes reached, stop the service,you can restart the servcie to rerun")
        elif license_type== 6:
            print(f"Simluate 10 minute or 100 DST test License ")
            await DVOPCUAsever(max_time=600.0,max_items=100)
            print(f"Simluate 10 minute or 100 DST  test License ,10 minutes or  100 itmes reached, stop the service,you can restart the servcie to rerun")
        elif license_type== 3:
            print(f"uSE Demo License ,DEMO lCIENSE  SUPPORT A DEMO at least  4 hours demo")
            rand_time=random.randint(14400., 2592000)
            await DVOPCUAsever(max_time=rand_time)
            print(f"Demo license reached, you can restart the servcie to re run the demo")
        elif license_type== 89:
            await DVOPCUAsever(max_time=1138406000.0,max_items=100000)
        elif license_type== 88:
            await DVOPCUAsever(max_time=3758937600.0,max_items=100000)
        elif license_type== 87:
            await DVOPCUAsever(max_time=379468800.0,max_items=100000)
        elif license_type== 86:
            await DVOPCUAsever(max_time=189734400.0,max_items=100000)
        elif license_type== 85:
            await DVOPCUAsever(max_time=94867200.0,max_items=100000)
        elif license_type== 79:
            await DVOPCUAsever(max_time=1138406000.0,max_items=50000)
        elif license_type== 78:
            await DVOPCUAsever(max_time=3758937600.0,max_items=50000)
        elif license_type== 77:
            await DVOPCUAsever(max_time=379468800.0,max_items=50000)
        elif license_type== 76:
            await DVOPCUAsever(max_time=189734400.0,max_items=50000)
        elif license_type== 59:
            await DVOPCUAsever(max_time=1138406000.0,max_items=20000)
        elif license_type== 58:
            await DVOPCUAsever(max_time=3758937600.0,max_items=20000)
        elif license_type== 57:
            await DVOPCUAsever(max_time=379468800.0,max_items=20000)
        elif license_type== 56:
            await DVOPCUAsever(max_time=189734400.0,max_items=20000)
        elif license_type== 49:
            await DVOPCUAsever(max_time=1138406000.0,max_items=10000)
        elif license_type== 48:
            await DVOPCUAsever(max_time=3758937600.0,max_items=10000)
        elif license_type== 47:
            await DVOPCUAsever(max_time=379468800.0,max_items=10000)
        elif license_type== 46:
            await DVOPCUAsever(max_time=189734400.0,max_items=10000)
        elif license_type== 39:
            await DVOPCUAsever(max_time=1138406000.0,max_items=5000)
        elif license_type== 38:
            await DVOPCUAsever(max_time=3758937600.0,max_items=5000)
        elif license_type== 37:
            await DVOPCUAsever(max_time=379468800.0,max_items=5000)
        elif license_type== 36:
            await DVOPCUAsever(max_time=189734400.0,max_items=5000)
        elif license_type== 29:
            await DVOPCUAsever(max_time=1138406000.0,max_items=3000)
        elif license_type== 28:
            await DVOPCUAsever(max_time=3758937600.0,max_items=3000)
        elif license_type== 27:
             await DVOPCUAsever(max_time=379468800.0,max_items=3000)
        elif license_type== 26:
            await DVOPCUAsever(max_time=189734400.0,max_items=3000)
        elif license_type== 19:
            await DVOPCUAsever(max_time=1138406000.0,max_items=1000)
        elif license_type== 18:
            await DVOPCUAsever(max_time=3758937600.0,max_items=1000)
        elif license_type== 17:
            await DVOPCUAsever(max_time=379468800.0,max_items=1000)
        elif license_type== 16:
            await DVOPCUAsever(max_time=189734400.0,max_items=1000)
        else:
            await DVOPCUAsever(max_time=300,max_items=50)
    finally:
        # Clean up background tasks
        for task in [rotate_task, cleanup_task]:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                        logging.debug("_OPCDAWrapper_.start: Handled CancelledError in finally block")
                        pass
                except: 
                        pass


if __name__ == "__main__":

    asyncio.run(main())





    

  
   
    
    