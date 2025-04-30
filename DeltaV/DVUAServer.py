
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
        "V1-WIC-1/PID1/MODE.TARGET",
        "V1-AIC-1/HI_ALM.CUALM",
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
          
            
            start_task = asyncio.create_task(wrapper.start())   
            # 初始添加节点

            await asyncio.sleep(10)
            server_status= await wrapper.GetServerStatus()
            logging.info(f"OPC UA SERVER status :{json.dumps(server_status, indent=6,ensure_ascii=False)}")
            
            print(f"_OPCDAWrapper_.main: add simulate items {items} ")
            await wrapper.da_manager.add_items(simulate_items, "MODULES.AREA_V1")
            await asyncio.sleep(5)
            await wrapper.da_manager.add_items(diagnostics_items, f"DIAGNOSTICS.Physical Network.Control Network.{wrapper._nodename}")
            await asyncio.sleep(5)
            # 示例：动态调用 update_node
            new_item = await wrapper.da_manager.update_node("MODULES.AREA_V2.V2-EM.V2-AIC-DO.FS_CTRL1.IN_SCALE.EU100")
            print(f"_OPCDAWrapper_.main: Added new item: {new_item}")
            await asyncio.sleep(5)          
            # 示例：动态调用 broswe_folder
            await wrapper.da_manager.broswe_folder(base_path=f"DIAGNOSTICS.Physical Network.Control Network.{wrapper._nodename}")
            print(f"_OPCDAWrapper_.main: Browsed and updated structure under DIAGNOSTICS.Physical Network.Control Network.{wrapper._nodename}")
            # await asyncio.sleep(5)
            # await wrapper.da_manager.remove_items(simulate_items)
            # print("_OPCDAWrapper_.main: Remove items from subcrible")
            # Example: Call update_parameters_from_json
            await asyncio.sleep(5)
            sample_config = {

           
                "_manual_stop": False,
                "da_manager": {
                    "_da_update_rate": 2000,
                    "_ua_update_rate": 2,
                    "_da_subscribe_waittime": 2
                   
            
                },
                "history_manager": {
                    "_event_update_rate": 5,
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
            # await asyncio.sleep(5)
            # print("_OPCDAWrapper_.main: auto load task for V2")
            # await wrapper.da_manager.add_items(["V2-COMMON/BATCH_START.CV"], "MODULES.AREA_V2")
            # alarm_config = {
            #                 "MODULES.AREA_V2.ALARMS.CUALM":[
            #                 "V2-AI-1/HI_ALM.CUALM",
            #                 "V2-AI-1/HI_HI_ALM.CUALM",
            #                 "V2-AI-1/LO_ALM.CUALM",
            #                 "V2-AI-1/LO_LO_ALM.CUALM",
            #                 "V2-AI-1/PVBAD_ALM.CUALM",
            #                 "V2-AI-2/HI_ALM.CUALM",
            #                 "V2-AI-2/HI_HI_ALM.CUALM",
            #                 "V2-AI-2/LO_ALM.CUALM",
            #                 "V2-AI-2/LO_LO_ALM.CUALM",
            #                 "V2-AI-2/PVBAD_ALM.CUALM",
            #                 "V2-AI-3/HI_ALM.CUALM",
            #                 "V2-AI-3/HI_HI_ALM.CUALM",
            #                 "V2-AI-3/LO_ALM.CUALM",
            #                 "V2-AI-3/LO_LO_ALM.CUALM",
            #                 "V2-AI-3/PVBAD_ALM.CUALM",
            #                 "V2-AI-4/HI_ALM.CUALM",
            #                 "V2-AI-4/HI_HI_ALM.CUALM",
            #                 "V2-AI-4/LO_ALM.CUALM",
            #                 "V2-AI-4/LO_LO_ALM.CUALM",
            #                 "V2-AI-4/PVBAD_ALM.CUALM",
            #                 "V2-AI-5/HI_ALM.CUALM",
            #                 "V2-AI-5/HI_HI_ALM.CUALM",
            #                 "V2-AI-5/LO_ALM.CUALM",
            #                 "V2-AI-5/LO_LO_ALM.CUALM",
            #                 "V2-AI-5/PVBAD_ALM.CUALM",
            #                 "V2-AI-6/HI_ALM.CUALM",
            #                 "V2-AI-6/HI_HI_ALM.CUALM",
            #                 "V2-AI-6/LO_ALM.CUALM",
            #                 "V2-AI-6/LO_LO_ALM.CUALM",
            #                 "V2-AI-6/PVBAD_ALM.CUALM",
            #                 "V2-AI-7/HI_ALM.CUALM",
            #                 "V2-AI-7/HI_HI_ALM.CUALM",
            #                 "V2-AI-7/LO_ALM.CUALM",
            #                 "V2-AI-7/LO_LO_ALM.CUALM",
            #                 "V2-AI-7/PVBAD_ALM.CUALM",
            #                 "V2-AI-8/HI_ALM.CUALM",
            #                 "V2-AI-8/HI_HI_ALM.CUALM",
            #                 "V2-AI-8/LO_ALM.CUALM",
            #                 "V2-AI-8/LO_LO_ALM.CUALM",
            #                 "V2-AI-8/PVBAD_ALM.CUALM",
            #                 "V2-FIC-1/DV_HI_ALM.CUALM",
            #                 "V2-FIC-1/DV_LO_ALM.CUALM",
            #                 "V2-FIC-1/HI_ALM.CUALM",
            #                 "V2-FIC-1/HI_HI_ALM.CUALM",
            #                 "V2-FIC-1/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-1/LO_ALM.CUALM",
            #                 "V2-FIC-1/LO_LO_ALM.CUALM",   
            #                 "V2-FIC-1/PVBAD_ALM.CUALM",
            #                 "V2-FIC-2/DV_HI_ALM.CUALM",
            #                 "V2-FIC-2/DV_LO_ALM.CUALM",
            #                 "V2-FIC-2/HI_ALM.CUALM",
            #                 "V2-FIC-2/HI_HI_ALM.CUALM",
            #                 "V2-FIC-2/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-2/LO_ALM.CUALM",
            #                 "V2-FIC-2/LO_LO_ALM.CUALM",    
            #                 "V2-FIC-2/PVBAD_ALM.CUALM",
            #                 "V2-FIC-3/DV_HI_ALM.CUALM",
            #                 "V2-FIC-3/DV_LO_ALM.CUALM",
            #                 "V2-FIC-3/HI_ALM.CUALM",
            #                 "V2-FIC-3/HI_HI_ALM.CUALM",
            #                 "V2-FIC-3/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-3/LO_ALM.CUALM",
            #                 "V2-FIC-3/LO_LO_ALM.CUALM",     
            #                 "V2-FIC-3/PVBAD_ALM.CUALM",
            #                 "V2-FIC-4/DV_HI_ALM.CUALM",
            #                 "V2-FIC-4/DV_LO_ALM.CUALM",
            #                 "V2-FIC-4/HI_ALM.CUALM",
            #                 "V2-FIC-4/HI_HI_ALM.CUALM",
            #                 "V2-FIC-4/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-4/LO_ALM.CUALM",
            #                 "V2-FIC-4/LO_LO_ALM.CUALM",  
            #                 "V2-FIC-4/PVBAD_ALM.CUALM",
            #                 "V2-FIC-5/DV_HI_ALM.CUALM",
            #                 "V2-FIC-5/DV_LO_ALM.CUALM",
            #                 "V2-FIC-5/HI_ALM.CUALM",
            #                 "V2-FIC-5/HI_HI_ALM.CUALM",
            #                 "V2-FIC-5/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-5/LO_ALM.CUALM",
            #                 "V2-FIC-5/LO_LO_ALM.CUALM",     
            #                 "V2-FIC-5/PVBAD_ALM.CUALM",
            #                 "V2-FIC-6/DV_HI_ALM.CUALM",
            #                 "V2-FIC-6/DV_LO_ALM.CUALM",
            #                 "V2-FIC-6/HI_ALM.CUALM",
            #                 "V2-FIC-6/HI_HI_ALM.CUALM",
            #                 "V2-FIC-6/INTERLOCK_ALM.CUALM",
            #                 "V2-FIC-6/LO_ALM.CUALM",
            #                 "V2-FIC-6/LO_LO_ALM.CUALM",   
            #                 "V2-FIC-6/PVBAD_ALM.CUALM",
        ]}
      
            # batch_cotrol_task=asyncio.create_task(wrapper.da_manager.batch_control_area("V2/BATCH_START.CV", json_data=alarm_config))
           
           
            if max_time :  
               # await batch_cotrol_task   
                await asyncio.wait([start_task], timeout=max_time)                  
            else:
               # await batch_cotrol_task
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
    opcua_loggeer.set_logging_level(1)
    
    # Start daily log rotation task
    rotate_task  = asyncio.create_task(opcua_loggeer.rotate_daily_logs(log_file))
    
    # Start log cleanup task (example: monthly cleanup)
    cleanup_task =asyncio.create_task(opcua_loggeer.cleanup_old_logs('month', log_dir))
    logging.getLogger('asyncua').setLevel(logging.WARNING)
    try:
        license_manager=_DVLicManager_()
        license_manager.run()
        license_type=license_manager._license_type  

        if license_type== 1:
            print(f"valid license not found, Running in simulate mode with license")
            await DVOPCUAsever(max_time=3600.0)
        elif license_type== 2:
            print(f"valid license for simluate 4 hours license")
            await DVOPCUAsever(max_time=14400.0)
            print(f"Simluate 4 hours treached, stop the service,you can restart the servcie to rerun")
        elif license_type== 3:
            print(f"uSE Demo License ,DEMO lCIENSE  SUPPORT A DEMO at least  4 hours demo")
            rand_time=random.randint(14400., 2592000)
            await DVOPCUAsever(max_time=rand_time)
            print(f"Demo license reached, you can restart the servcie to re run the demo")  
        elif license_type== 5:
            print(f"Simluate 3 minute test License ")
            await DVOPCUAsever(max_time=180.0)
            print(f"Simluate 3  minutes reached, stop the service,you can restart the servcie to rerun")
        elif license_type== 6:
            print(f"Simluate 10 minute and max 100 DST test License ")
            await DVOPCUAsever(max_time=600.0,max_items=100)
            print(f"Simluate 10 minute max 100 DST  test License,time reached, stop the service,you can restart the servcie to rerun")
        elif license_type== 7:
            print(f"Simluate 30 minute and max 500 DST test License ")
            await DVOPCUAsever(max_time=1800.0,max_items=500)
            print(f"Simluate 30 minute and max 500 DST time reached,stop the service,you can restart the servcie to rerun")
        elif license_type== 8:
            print(f"Simluate 60 minute and max 1000 DST test License ")
            await DVOPCUAsever(max_time=3600.0,max_items=1000)
            print(f"Simluate 60 minute and max 1000 DST time reached,stop the service,you can restart the servcie to rerun")
        elif license_type== 9:
            print(f"Simluate 1 day and 10000 DST test License ")
            await DVOPCUAsever(max_time=86400.0,max_items=10000)
            print(f"Simluate 1 day and 10000 DST  time reached,, stop the service,you can restart the servcie to rerun")
        elif license_type== 10:
            print(f"valid license for simluate 1 day license")
            await DVOPCUAsever(max_time=86400.0)
            print(f"Simluate 4 hours treached, stop the service,you can restart the servcie to rerun")
        elif license_type== 69:
            print(f"Simluate 10 minute and 100 DST test License ")
            await DVOPCUAsever(max_time=600.0,max_items=100)
            print(f"Simluate 10 minute or 100 DST  test License ,10 minutesand max 100 itmes reached, stop the service,you can restart the servcie to rerun")
        elif license_type== 100:
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





    

  
   
    
    
