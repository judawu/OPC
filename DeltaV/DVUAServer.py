
import logging
import os
import json
import asyncio
from asyncua import  ua
from _DVWrapper_ import _OPCWrapper_
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
        wrapper = _OPCWrapper_()
       
      
        # 启动服务
        await wrapper.da_manager.append_items(items)
       
       
        start_task = asyncio.create_task(wrapper.start())
        
        # 初始添加节点
        await asyncio.sleep(10)
        server_status= await wrapper.GetServerStatus()
        logging.info(f"OPC UA SERVER status :{json.dumps(server_status, indent=6,ensure_ascii=False)}")
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

            "_max_time": 2000.0,
            "_manual_stop": False,
            "da_manager": {
                "_da_update_rate": 2000,
                "_ua_update_rate": 5,
                "_da_subscribe_waittime": 2,
           
            },
            "history_manager": {
                "_event_update_rate": 10,
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
        while not wrapper.event.shutdown.is_set():
            if wrapper.manual_stop:
                await asyncio.sleep(10)
                print("_OPCDAWrapper_.main: manual_stop enabled, waithing for manual stop from client ")
                if not wrapper.event.shutdown.is_set():
                    await wrapper.stop()
            elif wrapper.max_time:
                await asyncio.wait([start_task], timeout=wrapper.max_time)
            # else:
            #     await start_task
    
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