# **DeltaV系统的上位机操作**

## **写在前面**
自从自动化专业本科毕业以后，从事的都是工控行业的工作，从最初的拧螺丝给配电柜接线，到给PLC编程，上位机组态。到进行DCS系统的项目维护，开发和系统升级，转眼快20年了。也见到了国产设备的自动化水平越来越高，总想做点什么。
总结一些经验分享给同行吧，特别是那些正在进行系统自研的自动化专家们。

30多年来，OPC协议一直是上位机和和PLC，CPU通讯的标准协议，无论是西门子的WinCC与S7系列PLC通讯，还是RockWell的AB系列PLC与Wonderware，还是Emerson公司的DeltaV与ifix通讯，抑或是其他种类的，只要是基于windows系统的开发，OPC协议始终是上下位通讯的主流。

最近的趋势是工业设备现场化和智能化，随着一些技术上的下沉，越来越多的应用层通讯协议下沉到设备层，智能芯片越来越通用的被应用到仪表和控制端，传统的上位机和控制器的通讯方式或许会引来一出基于AI的革命。特别是那些自动化公司的不开放的通讯协议会越来越受到挑战。

我在这里实现的是对应传统OPCDA系统的一个客户端实现，记得我最初工作的时候对于IFIX软件的强大特别印象深刻，它可以安装很多的驱动协议，比如Modbus RTU/TCP协议,EthetNet/IP协议，OPCDA协议，特别是利用Kepware 做为OPC中转连接各家PLC的强大能力。我记得我做的一套电厂辅助控制系统采用这种架构至少运行了10年（就算我只干了1年就离开了那家公司）

我下面发布的内容如果让某些同行觉得不适，，我只是做为技术来研究的， 不考虑商业上的行为，如果对于知识产权有侵犯，请通知我删除。

进入主题，之前我开发的OPCDA的客户端连接的是OPC.DELTAV.1服务器，这是DELTAV的标准OPC服务器，但是emerson有一个很鸡贼的设定（也许是任何一家卖软件授权公司的设定），你如果访问OPC.DELTAV.1服务器，需要按找DST数量进行授权认证。市面上所有的OPC商业软件都是这样的设定。学习的都是微软的授权模式。不过后者现在转到订阅模式了，软件公司们也在跟着转成订阅模式。

有没有一种办法，不使用基于授权模式的OPC服务器就能访问控制器或者PLC数据?就是下面的方法，通过它，你就绕过了IFIX直接访问了DELTAV的应用层数据，是不是给你的开发打开了思路，想想你自己做一个上位机会是什么样子的？

开始之前，首先要理解上位机DELTAV ifix是怎么访问DELTAV服务的，没错通过OPC服务器，这个opc服务器就是DVSYS， 最新的DELTAV LIVE上位机用的是DLSYS ，这两个都是OPC Server

## **源代码地址**： https://github.com/judawu/OPC

## **代码**
用于与DeltaV系统交互的Python代码，基于win32com.client实现，支持连接、读取、写入、轮询和订阅等功能。
```
...
def __init__(self, server_name: str = "DeltaV.DVSYSsvr.1", client_name: str = "DefaultOPCDAClient"):
...
```
## **测试报告**
### **测试环境**
**日期**: 2025年4月7日
**OPC服务器**: DeltaV.DVSYSsvr.1
**客户端**: Python脚本，使用win32com.client与OPC DA服务器交互
**操作系统**: Windows 10
### **测试结果**
#### 1. **连接测试**
**描述**: 测试客户端是否能成功连接到OPC服务器DeltaV.DVSYSsvr.1。
**结果**: 成功连接。
**日志**:
```
2025-04-07 17:32:08,494 - INFO - _OPCDA_: Successfully connected to OPC server DeltaV.DVSYSsvr.1
Connected to DeltaV.DVSYSsvr.1
```
**输出**: 列出了可用OPC服务器和方法，确认连接正常。
#### 2. **读取测试**
**描述**: 从指定项路径读取数据。
**项路径**: ["V1-IO/DO1_NA_PV.F_CV", "V1-IO/PH1_MV_PV.F_CV", "PROPLUS/FREMEM.F_CV"]
**结果**: 成功读取所有项的值。
**输出**:
```
Read from V1-IO/DO1_NA_PV.F_CV: Value=0.12188154458999634, Quality=192, Timestamp=2025-04-07 17:32:11+00:00
Read from V1-IO/PH1_MV_PV.F_CV: Value=-18.968231201171875, Quality=192, Timestamp=2025-04-07 17:32:11+00:00
Read from PROPLUS/FREMEM.F_CV: Value=41998108.0, Quality=192, Timestamp=2025-04-07 17:32:11+00:00
```
### 3. **写入测试**
**描述**: 向指定项路径写入值并验证。
**项路径**: ["V1-IO/AI1_SCI1.F_EU100", "V1-AIC-DO/PID1/MODE.F_TARGET", "V1-AI-1/FS_CTRL1/MOD_DESC.A_CV"]
**写入值**: [32767, 8, "AI1 test"]
**结果**: 成功写入并验证。
**输出**:
```
Successfully wrote 32767 to V1-IO/AI1_SCI1.F_EU100
Successfully wrote 8 to V1-AIC-DO/PID1/MODE.F_TARGET
Successfully wrote AI1 test to V1-AI-1/FS_CTRL1/MOD_DESC.A_CV
Read from V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:32:12+00:00
Read from V1-AIC-DO/PID1/MODE.F_TARGET: Value=8.0, Quality=192, Timestamp=2025-04-07 17:32:12+00:00
Read from V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=AI1 test, Quality=192, Timestamp=2025-04-07 17:32:12+00:00
```
### 4. **轮询测试**
**描述**: 测试定期轮询功能，设置最大时间3秒。
**结果**: 成功轮询并在3秒后停止。
**输出**:
```
testing poll for 3 seconds then stop
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
_OPCDA_: Poll/Subscribe V1-AIC-DO/PID1/MODE.F_TARGET: Value=8.0, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=AI1 test, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
2025-04-07 17:32:16,018 - DEBUG - _OPCDA_: Reached max time (3.0 seconds), stopping poll
```
### 5. **订阅测试**
**描述**: 测试订阅功能，观察数据变化时的回调。
**项路径**: ["V1-IO/AI1_SCI1.F_EU100", "V1-AIC-DO/PID1/MODE.F_TARGET", "V1-AI-1/FS_CTRL1/MOD_DESC.A_CV"]
**结果**: 成功订阅并检测到数据变化。
**输出**:
```
Testing subscribe with user input to stop
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=HELLO, Quality=192, Timestamp=2025-04-07 17:36:10+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=SUCEFFUL, Quality=192, Timestamp=2025-04-07 17:36:18+00:00
_OPCDA_: Poll/Subscribe V1-AIC-DO/PID1/MODE.F_TARGET: Value=16.0, Quality=192, Timestamp=2025-04-07 17:37:17+00:00
User requested stop, stopping subscription...
```
### 6. **断开连接测试**
**描述**: 测试客户端是否能正常断开与OPC服务器的连接。
**结果**: 成功断开。
**日志**:
```
2025-04-07 17:37:45,626 - INFO - _OPCDA_: Successfully disconnected to opc da server DeltaV.DVSYSsvr.1
```
## **总结**
**成功点**: 连接、读取、写入、轮询和订阅功能均正常工作，能够正确处理数据变化和用户输入停止。
**问题**:
- 日志中出现带宽值为-1，可能是服务器未提供带宽信息或实现问题。
- Broswer 方法服务器端不支持，只能根据经验测试Item。
- 与OPC.DELTAV.1不同，后面的filed项需要将CV/EU0/TARGET改成F_CV/F_EU0/F_TARGET（浮点数）， 或者A_CV/A_TARGET（字符串）

## **日志记录**
```
025-04-07 17:32:05,157 - DEBUG - _OPCDA_: Attempting to connect to DeltaV.DVSYSsvr.1
2025-04-07 17:32:05,202 - DEBUG - _OPCDA_: dir(self.opc): ['Bandwidth', 'BuildNumber', 'CLSID', 'ClientName', 'Connect', 'CreateBrowser', 'CurrentTime', 'Disconnect', 'GetErrorString',
'GetItemProperties', 'GetOPCServers', 'LastUpdateTime', 'LocaleID', 'LookupItemIDs', 'MajorVersion', 'MinorVersion', 'OPCGroups', 'PublicGroupNames', 'QueryAvailableLocaleIDs', 'QueryAv
ailableProperties', 'ServerName', 'ServerNode', 'ServerState', 'StartTime', 'VendorInfo', '_ApplyTypes_', '__call__', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq
__', '__firstlineno__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__int__', '__iter__', '__le__'
, '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__static_attributes__', '__str__', '__subclasshook__', '__weakref
__', '_get_good_object_', '_get_good_single_object_', '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid']
2025-04-07 17:32:07,266 - DEBUG - _OPCDA_: self.opc Servers: ('OPC.DeltaV.1', 'DeltaV.DVSYSsvr.1', 'DELTAV.SisOpcSvr.1', 'Intellution.OPCEDA.3', 'Intellution.OPCiFIX.1')
2025-04-07 17:32:08,489 - DEBUG - _OPCDA_: opc server: Fisher-Rosemount Systems - DeltaV to iFIX Server
['CLSID', '__bool__', '__call__', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__firstlineno__', '__format__', '__ge__', '__getattr__', '__getattribute__', '
__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__int__', '__iter__', '__le__', '__len__', '__lt__', '__maybe__bool__', '__maybe__call__', '__maybe__int__', '__ma
ybe__iter__', '__maybe__len__', '__maybe__str__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__static_attributes__', '__
str__', '__subclasshook__', '__weakref__', '_dispobj_', 'coclass_interfaces', 'coclass_sources', 'default_interface', 'default_source']
<class 'win32com.gen_py.28E68F91-8D75-11D1-8DC3-3C302A000000x0x1x0.IOPCGroups'>
[<class 'win32com.gen_py.28E68F91-8D75-11D1-8DC3-3C302A000000x0x1x0.IOPCGroups'>]
[<class 'win32com.gen_py.28E68F91-8D75-11D1-8DC3-3C302A000000x0x1x0.DIOPCGroupsEvent'>]
<class 'win32com.gen_py.28E68F91-8D75-11D1-8DC3-3C302A000000x0x1x0.DIOPCGroupsEvent'>
2025-04-07 17:32:08,494 - INFO - _OPCDA_: Successfully connected to OPC server DeltaV.DVSYSsvr.1
 Connected to DeltaV.DVSYSsvr.1
2025-04-07 17:32:10,096 - DEBUG - _OPCDA_: Found 5 OPC DA servers: ['OPC.DeltaV.1', 'DeltaV.DVSYSsvr.1', 'DELTAV.SisOpcSvr.1', 'Intellution.OPCEDA.3', 'Intellution.OPCiFIX.1']
Available OPC Servers: ['OPC.DeltaV.1', 'DeltaV.DVSYSsvr.1', 'DELTAV.SisOpcSvr.1', 'Intellution.OPCEDA.3', 'Intellution.OPCiFIX.1']

2025-04-07 17:32:10,100 - DEBUG - _OPCDA_:Available methods and attributes for DeltaV.DVSYSsvr.1: ['Bandwidth', 'BuildNumber', 'CLSID', 'ClientName', 'Connect', 'CreateBrowser', 'Curren
tTime', 'Disconnect', 'GetErrorString', 'GetItemProperties', 'GetOPCServers', 'LastUpdateTime', 'LocaleID', 'LookupItemIDs', 'MajorVersion', 'MinorVersion', 'OPCGroups', 'PublicGroupNam
es', 'QueryAvailableLocaleIDs', 'QueryAvailableProperties', 'ServerName', 'ServerNode', 'ServerState', 'StartTime', 'VendorInfo', '_ApplyTypes_', '__call__', '__class__', '__delattr__',
 '__dict__', '__dir__', '__doc__', '__eq__', '__firstlineno__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subc
lass__', '__int__', '__iter__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__static_attributes__', '
__str__', '__subclasshook__', '__weakref__', '_get_good_object_', '_get_good_single_object_', '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid']
Available methods and attributes: ['Bandwidth', 'BuildNumber', 'CLSID', 'ClientName', 'Connect', 'CreateBrowser', 'CurrentTime', 'Disconnect', 'GetErrorString', 'GetItemProperties', 'Ge
tOPCServers', 'LastUpdateTime', 'LocaleID', 'LookupItemIDs', 'MajorVersion', 'MinorVersion', 'OPCGroups', 'PublicGroupNames', 'QueryAvailableLocaleIDs', 'QueryAvailableProperties', 'Ser
verName', 'ServerNode', 'ServerState', 'StartTime', 'VendorInfo', '_ApplyTypes_', '__call__', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__firstlineno__',
'__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__int__', '__iter__', '__le__', '__lt__', '__module__'
, '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__static_attributes__', '__str__', '__subclasshook__', '__weakref__', '_get_good_object_'
, '_get_good_single_object_', '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid']

2025-04-07 17:32:10,104 - DEBUG - _OPCDA_: opc da Server DeltaV.DVSYSsvr.1 status: {'ServerName': 'DeltaV.DVSYSsvr.1', 'ServerState': 1, 'MajorVersion': 14, 'MinorVersion': 3, 'BuildNum
ber': 1, 'VendorInfo': 'Fisher-Rosemount Systems - DeltaV to iFIX Server'}
 explore_server_details:
 {'ServerName': 'DeltaV.DVSYSsvr.1', 'ServerState': 1, 'MajorVersion': 14, 'MinorVersion': 3, 'BuildNumber': 1, 'VendorInfo': 'Fisher-Rosemount Systems - DeltaV to iFIX Server'}

2025-04-07 17:32:10,199 - DEBUG - _OPCDA_: Server DeltaV.DVSYSsvr.1 status: {'ServerState': 1, 'CurrentTime': pywintypes.datetime(2025, 4, 7, 17, 32, 10, tzinfo=TimeZoneInfo('GMT Standa
rd Time', True)), 'StartTime': pywintypes.datetime(2025, 4, 7, 17, 32, 7, tzinfo=TimeZoneInfo('GMT Standard Time', True)), 'LastUpdateTime': pywintypes.datetime(1601, 1, 1, 8, 0, tzinfo
=TimeZoneInfo('GMT Standard Time', True)), 'ServerNode': ''}
Server Status::

{
    "ServerState": 1,
    "CurrentTime": "2025-04-07 17:32:10",
    "StartTime": "2025-04-07 17:32:07",
    "LastUpdateTime": "1601-01-01 08:00:00",
    "ServerNode": ""
}

2025-04-07 17:32:10,306 - DEBUG - _OPCDA_:  Client name set to: MyPythonClient
Client name set to: MyPythonClient
Current client name: MyPythonClient

 testing OPC read
Read from V1-IO/DO1_NA_PV.F_CV: Value=0.12188154458999634, Quality=192, Timestamp=2025-04-07 17:32:11+00:00
Read from V1-IO/PH1_MV_PV.F_CV: Value=-18.968231201171875, Quality=192, Timestamp=2025-04-07 17:32:11+00:00
Read from PROPLUS/FREMEM.F_CV: Value=41998108.0, Quality=192, Timestamp=2025-04-07 17:32:11+00:00

 testing OPC Write
2025-04-07 17:32:11,791 - DEBUG - _OPCDA_: Successfully wrote 32767 to V1-IO/AI1_SCI1.F_EU100 to OPC da server  DeltaV.DVSYSsvr.1
2025-04-07 17:32:11,834 - DEBUG - _OPCDA_: Successfully wrote 8 to V1-AIC-DO/PID1/MODE.F_TARGET to OPC da server  DeltaV.DVSYSsvr.1
2025-04-07 17:32:11,881 - DEBUG - _OPCDA_: Successfully wrote AI1 test to V1-AI-1/FS_CTRL1/MOD_DESC.A_CV to OPC da server  DeltaV.DVSYSsvr.1
Successfully wrote 32767 to V1-IO/AI1_SCI1.F_EU100
Successfully wrote 8 to V1-AIC-DO/PID1/MODE.F_TARGET
Successfully wrote AI1 test to V1-AI-1/FS_CTRL1/MOD_DESC.A_CV
Read from V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:32:12+00:00
Read from V1-AIC-DO/PID1/MODE.F_TARGET: Value=8.0, Quality=192, Timestamp=2025-04-07 17:32:12+00:00
Read from V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=AI1 test, Quality=192, Timestamp=2025-04-07 17:32:12+00:00

 testing OPC poll
testing poll for 3 seconds then stop
2025-04-07 17:32:12,965 - DEBUG - Starting poll for ['V1-IO/AI1_SCI1.F_EU100', 'V1-AIC-DO/PID1/MODE.F_TARGET', 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV'] every 2.0 seconds
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
_OPCDA_: Poll/Subscribe V1-AIC-DO/PID1/MODE.F_TARGET: Value=8.0, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=AI1 test, Quality=192, Timestamp=2025-04-07 17:32:14+00:00
2025-04-07 17:32:16,018 - DEBUG - _OPCDA_: Reached max time (3.0 seconds), stopping poll
testing poll for 5 times then stop
2025-04-07 17:32:16,021 - DEBUG - Starting poll for ['V1-IO/AI1_SCI1.F_EU100', 'V1-AIC-DO/PID1/MODE.F_TARGET', 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV'] every 2.0 seconds
2025-04-07 17:32:19,090 - DEBUG - _OPCDA_: Reached max time (3.0 seconds), stopping poll
2025-04-07 17:32:19,091 - DEBUG - _OPCDA_: Error -2147467259 (0x80004005): Unspecified error

Error Description (0x80004005): Unspecified error

2025-04-07 17:32:19,093 - DEBUG - _OPCDA_: Error -2147467259 (0x80004005): Unspecified error

Error Description (-2147467259): Unspecified error

2025-04-07 17:32:19,095 - DEBUG - _OPCDA_: Error 0 (0x00000000): The operation completed successfully.

Error Description (0): The operation completed successfully.


2025-04-07 17:32:19,097 - INFO - _OPCDA_: OPC DA SEVER DeltaV.DVSYSsvr.1 Current bandwidth: -1
Bandwidth: -1

testing subscribe meothod, try to simulate data change to obersve the callback

Subscribed, waiting for data changes... (Press Ctrl+C to stop)
Enter max count do you want the subscribe to stop: 20

Testing subscribe with max_count=20 (controlled in main)
2025-04-07 17:35:06,016 - DEBUG - _OPCDA_:Subscribed to ['V1-IO/AI1_SCI1.F_EU100', 'V1-AIC-DO/PID1/MODE.F_TARGET', 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV'] with update rate 1000ms from OPC da
server DeltaV.DVSYSsvr.1
Subscribe count start...
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=21.0, Quality=192, Timestamp=2025-04-07 17:35:14+00:00
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:35:21+00:00
Reached max count (5 iterations), stopping subscription...
2025-04-07 17:35:26,037 - DEBUG - _OPCDA_: Subscription SubscribeCountGroup stopped successfully from OPC da server DeltaV.DVSYSsvr.1

Enter max seconds do you want the subscribe to stop: 20

Testing subscribe with max_time=20 seconds (controlled in main)
2025-04-07 17:35:33,101 - DEBUG - _OPCDA_:Subscribed to ['V1-IO/AI1_SCI1.F_EU100', 'V1-AIC-DO/PID1/MODE.F_TARGET', 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV'] with update rate 1000ms from OPC da
server DeltaV.DVSYSsvr.1
Subscribe timer start...
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=12.0, Quality=192, Timestamp=2025-04-07 17:35:37+00:00
_OPCDA_: Poll/Subscribe V1-IO/AI1_SCI1.F_EU100: Value=32767.0, Quality=192, Timestamp=2025-04-07 17:35:41+00:00
20.0 seconds elapsed, stopping subscription...
2025-04-07 17:35:53,127 - DEBUG - _OPCDA_: Subscription SubscribeTimeGroup stopped successfully from OPC da server DeltaV.DVSYSsvr.1


Testing subscribe with user input to stop
2025-04-07 17:35:54,164 - DEBUG - _OPCDA_:Subscribed to ['V1-IO/AI1_SCI1.F_EU100', 'V1-AIC-DO/PID1/MODE.F_TARGET', 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV'] with update rate 1000ms from OPC da
server DeltaV.DVSYSsvr.1
Type 'stop' to end subscription (runs until stopped)...
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=HELLO, Quality=192, Timestamp=2025-04-07 17:36:10+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=SUCEFFUL, Quality=192, Timestamp=2025-04-07 17:36:18+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=HAHA, Quality=192, Timestamp=2025-04-07 17:36:23+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=V1-AIC-DO/PID1/MODE.A_TARGET, Quality=192, Timestamp=2025-04-07 17:36:41+00:00
_OPCDA_: Poll/Subscribe V1-AI-1/FS_CTRL1/MOD_DESC.A_CV: Value=8, Quality=192, Timestamp=2025-04-07 17:36:53+00:00
_OPCDA_: Poll/Subscribe V1-AIC-DO/PID1/MODE.F_TARGET: Value=16.0, Quality=192, Timestamp=2025-04-07 17:37:17+00:00
_OPCDA_: Poll/Subscribe V1-AIC-DO/PID1/MODE.F_TARGET: Value=8.0, Quality=192, Timestamp=2025-04-07 17:37:36+00:00
User requested stop, stopping subscription...
2025-04-07 17:37:45,614 - DEBUG - _OPCDA_: Subscription ManualStopGroup stopped successfully from OPC da server DeltaV.DVSYSsvr.1
{'V1-IO/AI1_SCI1.F_EU100': 32767.0, 'V1-AIC-DO/PID1/MODE.F_TARGET': 8.0, 'V1-AI-1/FS_CTRL1/MOD_DESC.A_CV': '8'}
2025-04-07 17:37:45,616 - DEBUG - Attempting to disconnect from OPC server DeltaV.DVSYSsvr.1
2025-04-07 17:37:45,626 - INFO - _OPCDA_:Successfully disconnected to opc da server DeltaV.DVSYSsvr.1
```
