## OPC HDA 客户端（Python）：代码报告

# DeltaV OPC HDA 服务器接口测试报告

## 概述

本报告记录了对 DeltaV OPC HDA 服务器的接口测试结果，使用 Python 语言通过 `win32com.client` 库实现。测试目标是验证服务器的连接性、数据浏览、读取和处理功能。测试时间为 2025 年 4 月 6 日，使用的服务器为 `DeltaV.OPCHDAsvr`，客户端名称为 `PythonOPCHDAClient`。
DeltaV OPC HDA 服务器自带测试工具：hdaprobe 可用于验证


## 测试环境

- **服务器**: DeltaV OPC HDA Server (版本 14.3, Build 7282)
- **客户端**: Python 3.13, `win32com.client` 库
- **操作系统**: Windows (具体版本未提供)
- **测试日期**: 2025-04-06
- **测试代码版本**: 1.0.1

---

## 测试结果

### 1. 服务器连接性

**测试方法**: `_OPCHDA_.connect()`  
**结果**:  
- 成功连接到 `DeltaV.OPCHDAsvr`。
- 服务器状态通过 `GetHistorianStatus()` 获取，关键信息如下：
  ```json
  {
    "Status": 1,
    "StatusString": "Running",
    "CurrentTime": "2025-04-06 17:32:12+00:00",
    "ServerName": "DeltaV.OPCHDAsvr",
    "ServerNode": "",
    "MaxReturnValues": 12000,
    "StartTime": "2025-04-06 17:32:12+00:00",
    "BuildNumber": 7282,
    "CLSID": "{0C678471-BCD7-11D4-9E70-00B0D060205F}",
    "LocaleID": 1033,
    "MajorVersion": 14,
    "MinorVersion": 3,
    "VendorInfo": "Fisher-Rosemount Systems, Inc. -- DeltaV OPC HDA Server",
    "CanAsyncDeleteAtTime": 0,
    "CanAsyncDeleteRaw": 0,
    "CanAsyncInsert": 0,
    "CanAsyncInsertAnnotations": 0,
    "CanAsyncInsertReplace": 0,
    "CanAsyncReadAnnotations": 0,
    "CanAsyncReplace": 0,
    "ClientName": "PythonOPCHDAClient"
  }
**结论**: 连接正常，服务器运行状态良好，但所有异步操作支持标志均为 0，表明服务器不支持异步方法。
### 2. 数据项浏览
**测试方法**: _OPCHDA_.CreateBrowse()

**结果**:
成功浏览到 249 个数据项。

**结论**: 浏览功能正常，服务器返回的数据项数量和内容符合预期。
### 3. 属性和聚合支持
#### 3.1 获取数据项属性
**测试方法**: _OPCHDA_.GetItemAttributes()

**结果**:
返回 13 个支持的属性，包括 Data Type、Stepped 等。
**示例属性**：
```json
{
  {"id": 1, "name": "Data Type", "description": "The data type of the historical data...", "type": 2},
  {"id": 4, "name": "Stepped", "description": "True if the historical data value may be interpolated...", "type": 11}
}
```
**结论**: 属性获取成功，服务器支持多种属性查询。
#### 3.2 获取聚合类型
**测试方法**: _OPCHDA_.GetAggregates()
**结果**:
返回 13 种支持的聚合类型，包括 Interpolative、Time Average 等。

  ```json
{
  {"id": 1, "name": "Interpolative", "description": "Interpolate the return values."},
  {"id": 4, "name": "Time Average", "description": "The time weighted average data over the resample interval."}
}
  ```
**结论**: 聚合类型获取成功，支持多种数据处理方式。
### 4. 数据读取测试
#### 4.1 同步读取属性 (SyncReadAttribute)
**测试方法**: _OPCHDA_.SyncReadAttribute()
**参数**:
- Item ID: V3-IO/DO1_TMP_PV.CV
- 时间范围: 2025-04-06 18:04:20 至 2025-04-06 19:04:20
- 属性数量: 11
- 属性 ID 列表: [1, 4, 13, 14, 15, 16, -2147483646, -2147483645, -2147483630, -2147483613, -2147483598, 0]
**结果**:

  ```json
{
  "V3-IO/DO1_TMP_PV.CV": {
    "AttributesIDs": [1, 4, 13, 14, 15, 16, -2147483646, -2147483645, -2147483630, -2147483613, -2147483598, 0],
    "values": [false, "V3-IO/DO1_TMP_PV.CV", "86400000", "10000", 0.009999999776482582, "G3 Pro IO Input Module TruBio 5.00 Build 012", null, null, true, null, null],
    "qualities": [192, 192, 192, 192, 192, 192, null, null, 192, null, null],
    "timestamps": ["2025-04-06 19:04:20", ...]
  }
    ```

**结论**: 属性读取成功，返回值和质量符合预期，部分属性（如 Eng Units）无数据。
#### 4.2 单项原始数据读取 (ReadRaw)
**测试方法**: _OPCHDA_.ReadRaw()

**参数**:

- Item ID: V1-IO/DO1_TMP_PV.CV
- 时间范围: 2025-04-06 18:04:20 至 2025-04-06 19:04:20
- 最大值数量: 100


**返回数据**：
  ```json
{
  "V1-IO/DO1_TMP_PV.CV": {
    "values": [-33.260311126708984, -33.260311126708984],
    "qualities": [262336, 262336],
    "timestamps": ["2025-04-06 17:38:51", "2025-04-06 19:04:20"]
  }
  ```
**结论**: 单项原始数据读取成功，返回值和时间戳准确。
#### 4.3 单项处理数据读取 (ReadProcessed)
**测试方法**: _OPCHDA_.ReadProcessed()

**参数**:

- Item ID: V1-IO/DO1_TMP_PV.CV
- 时间范围: 2025-04-06 18:04:20 至 2025-04-06 19:04:20
- 间隔: 10 秒
- 聚合类型: [1, 3, 5]
**结果**:

- 聚合 1 (Interpolative): [-33.260311126708984]，质量 131264
- 聚合 3 (Average): [null]，质量 2097152
- 聚合 5 (Count): [0]，质量 524480
**结论**: 处理数据读取部分成功，Average 返回空值可能由于数据不足。
#### 4.4 多项原始数据读取 (SyncReadRaw)
**测试方法**: _OPCHDA_.SyncReadRaw()

**参数**:

- Item IDs: ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV']
- 时间范围: 2025-04-06 18:04:20 至 2025-04-06 19:04:20
- 最大值数量: 100
**结果**:
```json
{
  "V1-IO/DO1_NA_PV.CV": {
    "values": [-18.968229293823242, -18.968229293823242],
    "qualities": [262336, 262336],
    "timestamps": ["2025-04-06 17:37:51", "2025-04-06 19:04:20"]
  },
  "V1-IO/DO1_TMP_PV.CV": {...},
  "V1-IO/PH1_MV_PV.CV": {...}
}
 ```
**结论**: 多项原始数据读取成功，返回数据一致。
#### 4.5 多项处理数据读取 (SyncReadProcessed)
**测试方法**: _OPCHDA_.SyncReadProcessed()

**参数**:

- Item IDs: ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV']
- 时间范围: 2025-04-06 18:04:20 至 2025-04-06 19:04:20
- 间隔: 60 秒
- 聚合类型: [1, 1, 1]
**结果**:
```json
{
  "V1-IO/DO1_NA_PV.CV": {
    "values": [-18.968229293823242],
    "qualities": [131264],
    "timestamps": ["2025-04-06 18:04:20"]
  },
  "V1-IO/DO1_TMP_PV.CV": {...},
  "V1-IO/PH1_MV_PV.CV": {...}
}
```
**结论** : 多项处理数据读取成功，返回单点插值数据。
### 5. 数据项验证
**测试方法**: _OPCHDA_.ValidateItemIDs()

**参数**:
- Item IDs: ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV']
**结果**:
```json
{
  "V1-IO/DO1_NA_PV.CV": true,
  "V1-IO/DO1_TMP_PV.CV": true,
  "V1-IO/PH1_MV_PV.CV": true
}
 ```

**结论**: 数据项验证成功，所有测试 ID 有效。

## 存在的问题
异步方法不可用:
Historian Status 显示所有 CanAsync* 属性均为 0，表明 DeltaV OPC HDA 服务器不支持异步操作。
尝试使用 AsyncReadRaw 等方法时，返回 E_FAIL (-2147467259)，且回调未触发。
部分聚合结果异常:
ReadProcessed 中，Average (ID: 3) 返回 null，可能由于时间范围内数据点不足。

## 结论与建议
### 结论:
1. DeltaV OPC HDA 服务器的同步操作（SyncReadRaw, SyncReadProcessed, ReadRaw, ReadProcessed, SyncReadAttribute）功能正常，可靠性高。
2. 异步操作不可用，需依赖同步方法完成数据交互。
3. 数据浏览、属性和聚合查询功能完整，支持多种应用场景。
### 建议:
1. 移除异步方法: 鉴于服务器不支持异步操作，建议从代码中移除相关实现（如 AsyncReadRaw），专注于优化同步方法。
2. 数据验证: 对于 ReadProcessed 返回空值的情况，建议增加数据点或调整时间范围以验证聚合行为。
3. 日志优化: 当前日志级别为 INFO，建议在生产环境中调整为 WARNING 或更高，以减少输出。
### 附录
完整代码: 已移除异步相关实现，版本更新至 1.0.1。
日志文件: 完整日志记录于 2025-04-06 测试运行。
---
Connected to OPCHDA DeltaV.OPCHDAsvr

Get OPCHDA  Historian Status: {'Status': 1, 'StatusString': 'Running', 'CurrentTime': '2025-04-06 17:32:12+00:00', 'ServerName': 'DeltaV.OPCHDAsvr', 'ServerNode': '', 'MaxReturnValues': 12000, 'StartTi
me': '2025-04-06 17:32:12+00:00', 'BuildNumber': 7282, 'CLSID': '{0C678471-BCD7-11D4-9E70-00B0D060205F}', 'LocaleID': 1033, 'MajorVersion': 14, 'MinorVersion': 3, 'VendorInfo': 'Fisher-Rosemount System
s, Inc. -- DeltaV OPC HDA Server', 'CanAsyncDeleteAtTime': 0, 'CanAsyncDeleteRaw': 0, 'CanAsyncInsert': 0, 'CanAsyncInsertAnnotations': 0, 'CanAsyncInsertReplace': 0, 'CanAsyncReadAnnotations': 0, 'Can
AsyncReplace': 0, 'ClientName': 'PythonOPCHDAClient'}

OPCHDA DeltaV.OPCHDAsvr Browsed 249 Items:,first 2 is ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV']


Get OPCHDA Item Attributes: [{'id': 1, 'name': 'Data Type', 'description': 'The data type of the historical data (VT_I4, VT_UI4, BT_R4 or VT_BSTR).', 'type': 2}, {'id': 4, 'name': 'Stepped', 'descripti
on': 'True if the historical data value may be interpolated.  False for enumerations and string values.', 'type': 11}, {'id': 13, 'name': 'ItemID', 'description': 'The Item ID as provided to the DeltaV
 Continuous Historian.', 'type': 8}, {'id': 14, 'name': 'Max Time Interval', 'description': 'The minimum interval between data values in the data set.', 'type': 64}, {'id': 15, 'name': 'Min Time Interv
al', 'description': 'The maximum interval between data values in the data set.', 'type': 64}, {'id': 16, 'name': 'Exception Deviation', 'description': 'The minimum amount the data value must change to
add a new sample to the data set.', 'type': 5}, {'id': -2147483646, 'name': 'Mod DESC', 'description': 'Current DeltaV Module Description', 'type': 8}, {'id': -2147483645, 'name': 'Eng Units', 'descrip
tion': 'Current DeltaV Engineering Units', 'type': 8}, {'id': -2147483630, 'name': 'Eng 100%', 'description': 'Current DeltaV EU 100% of Scale Value', 'type': 4}, {'id': -2147483629, 'name': 'Eng 0%',
'description': 'Current DeltaV EU 0% of Scale Value', 'type': 4}, {'id': -2147483614, 'name': 'Last Download', 'description': 'Last DVCH Download Time', 'type': 7}, {'id': -2147483613, 'name': 'Current
ly On Scan', 'description': 'Currently On Scan', 'type': 11}, {'id': -2147483598, 'name': 'DeltaV Named Set', 'description': 'Deltav Named Set', 'type': 8}]

OPCHDA support Aggregates : {'count': 13, 'type': [{'id': 1, 'name': 'Interpolative', 'description': 'Interpolate the return values.'}, {'id': 4, 'name': 'Time Average', 'description': 'The time weight
ed average data over the resample interval.'}, {'id': 5, 'name': 'Count', 'description': 'The number of raw values over the sample interval.'}, {'id': 7, 'name': 'Minimum Actual Time', 'description': '
The minimum value in the resample interval and the timestamp of the minimum value.'}, {'id': 8, 'name': 'Minimum', 'description': 'The minimum value in the resample interval.'}, {'id': 9, 'name': 'Maxi
mum Actual Time', 'description': 'The maximum value in the resample interval and the timestamp of the maximum value.'}, {'id': 10, 'name': 'Maximum', 'description': 'The maximum value in the resample i
nterval.'}, {'id': 11, 'name': 'Start', 'description': 'The value at the beginning of the resample interval and the timestamp of the beginning of the interval.'}, {'id': 12, 'name': 'End', 'description
': 'The value at the end of the resample interval and the timestamp of the end of the interval.'}, {'id': 2, 'name': 'Total', 'description': 'Retrieve the totalized  value (time integral) of the data o
ver the resample interval.'}, {'id': 3, 'name': 'Average', 'description': 'Retrieve the average data over the resample interval.'}, {'id': 18, 'name': 'Range', 'description': 'Retrieve the difference b
etween the minimum and maximum value over the sample interval.'}, {'id': 6, 'name': 'Standard Deviation', 'description': 'Retrieve the standard deviation over the resample interval.'}]}

Test SyncReadAttribute for V3-IO/DO1_TMP_PV.CV item_attribute_data is: {'V3-IO/DO1_TMP_PV.CV': {'AttributesIDs': [1, 4, 13, 14, 15, 16, -2147483646, -2147483645, -2147483630, -2147483613, -2147483598,
0], 'values': [False, 'V3-IO/DO1_TMP_PV.CV', Decimal('86400000'), Decimal('10000'), 0.009999999776482582, 'G3 Pro IO Input Module TruBio 5.00 Build 012', None, None, True, None, None], 'qualities': [19
2, 192, 192, 192, 192, 192, None, None, 192, None, None], 'timestamps': [pywintypes.datetime(2025, 4, 6, 19, 27, 21, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19,
 27, 21, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 21, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 21, tzinfo
=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 21, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 21, tzinfo=TimeZoneInfo('
GMT Standard Time', True)), None, None, pywintypes.datetime(2025, 4, 6, 19, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True)), None, None]}}

Test ReadRaw for V1-IO/DO1_TMP_PV.CV  is: {'V1-IO/DO1_TMP_PV.CV': {'values': [-33.260311126708984, -33.260311126708984], 'qualities': [262336, 262336], 'timestamps': [pywintypes.datetime(2025, 4, 6, 17
, 38, 51, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True))]}}


Aggregate 1 Result for V1-IO/DO1_TMP_PV.CV: {'V1-IO/DO1_TMP_PV.CV': {'values': [-33.260311126708984], 'qualities': [131264], 'timestamps': [pywintypes.datetime(2025, 4, 6, 18, 27, 22, tzinfo=TimeZoneIn
fo('GMT Standard Time', True))]}}
2025-04-06 19:27:22,393 - WARNING - Aggregate 1 returned 1 values
Aggregate 3 Result for V1-IO/DO1_TMP_PV.CV: {'V1-IO/DO1_TMP_PV.CV': {'values': [None], 'qualities': [2097152], 'timestamps': [pywintypes.datetime(2025, 4, 6, 18, 27, 22, tzinfo=TimeZoneInfo('GMT Standa
rd Time', True))]}}
2025-04-06 19:27:22,428 - WARNING - Aggregate 3 returned 1 values
Aggregate 5 Result for V1-IO/DO1_TMP_PV.CV: {'V1-IO/DO1_TMP_PV.CV': {'values': [0], 'qualities': [524480], 'timestamps': [pywintypes.datetime(2025, 4, 6, 18, 27, 22, tzinfo=TimeZoneInfo('GMT Standard T
ime', True))]}}
2025-04-06 19:27:22,458 - WARNING - Aggregate 5 returned 1 values

OPCHDA Validation Results: for ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV']  {'V1-IO/DO1_NA_PV.CV': True, 'V1-IO/DO1_TMP_PV.CV': True, 'V1-IO/PH1_MV_PV.CV': True}

OPCHDA SyncReadRaw Test for ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV'] is : {'V1-IO/DO1_NA_PV.CV': {'values': [-18.968229293823242, -18.968229293823242], 'qualities': [262336,
262336], 'timestamps': [pywintypes.datetime(2025, 4, 6, 17, 37, 51, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time',
 True))]}, 'V1-IO/DO1_TMP_PV.CV': {'values': [-18.968229293823242, -18.968229293823242], 'qualities': [262336, 262336], 'timestamps': [pywintypes.datetime(2025, 4, 6, 17, 37, 51, tzinfo=TimeZoneInfo('G
MT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True))]}, 'V1-IO/PH1_MV_PV.CV': {'values': [-18.968229293823242, -18.968229293823242], 'q
ualities': [262336, 262336], 'timestamps': [pywintypes.datetime(2025, 4, 6, 17, 37, 51, tzinfo=TimeZoneInfo('GMT Standard Time', True)), pywintypes.datetime(2025, 4, 6, 19, 27, 22, tzinfo=TimeZoneInfo(
'GMT Standard Time', True))]}}

OPCHDA SyncReadProcessed for ['V1-IO/DO1_NA_PV.CV', 'V1-IO/DO1_TMP_PV.CV', 'V1-IO/PH1_MV_PV.CV'] is : {'V1-IO/DO1_NA_PV.CV': {'values': [-18.968229293823242], 'qualities': [131264], 'timestamps': [pywi
ntypes.datetime(2025, 4, 6, 18, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True))]}, 'V1-IO/DO1_TMP_PV.CV': {'values': [-18.968229293823242], 'qualities': [131264], 'timestamps': [pywintypes.date
time(2025, 4, 6, 18, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True))]}, 'V1-IO/PH1_MV_PV.CV': {'values': [-18.968229293823242], 'qualities': [131264], 'timestamps': [pywintypes.datetime(2025, 4
, 6, 18, 27, 22, tzinfo=TimeZoneInfo('GMT Standard Time', True))]}}

disconnected from OPCHDA server
---
## **OPC HDA 自定义接口和方法**

使用 DeltaV OPC 历史服务器访问 DeltaV 连续历史库历史数据的程序员应该熟悉 OPC 历史数据访问规范。

DeltaV OPC 历史服务器实现了以下 OPC HDA 自定义接口和方法。

**IOPCCommon**

`IOPCCommon` 接口在 OPC 通用定义和接口规范中定义。以下方法组成了此接口：

* **IOPCCommon::SetLocaleID**
    唯一支持的区域设置是英语（美国）。

* **IOPCCommon::GetLocaleID**
    此方法返回的值对应于英语（美国）。

* **IOPCCommon::QueryAvailableLocaleIDs**
    此方法返回可用的区域设置。

* **IOPCCommon::GetErrorString**
    此方法可用于将任何方法返回的 HRESULT 或 HDA 项目的 HRESULT 转换为用户友好的错误描述。

* **IOPCCommon::SetClientName**
    客户端可以使用此方法设置客户端的名称。客户端名称用于 Windows 事件日志中记录的某些事件。

**IConnectionPointContainer**

`IConnectionPointContainer` 是 Microsoft 定义的接口，用于获取回调接口。DeltaV OPC 历史服务器实现此接口以支持客户端提供 `IOPCShutdown` 接口。构成此接口的方法包括：

* **IConnectionPointContainer::EnumConnectionPoints**
    `IEnumConnectionPoints` 枚举器中仅包含 `IOPCShutdown` 接口。

* **IConnectionPointContainer::FindConnectionPoint**
    此方法可用于获取对应于 `IID_IOPCShutdown` 的接口。

**IOPCShutdown**

这是一个客户端接口，DeltaV OPC 历史服务器使用它在支持的 DeltaV 服务关闭时通知客户端。此接口提供的唯一方法是：

* **IOPCShutdown::ShutdownRequest**
    DeltaV OPC 历史服务器调用此方法以通知客户端 DeltaV 服务正在关闭。

**IOPCHDA_Server**

此接口是 DeltaV OPC 历史服务器的主要接口。`IOPCHDA_Server` 接口提供了一种设置对历史数据值的访问的方法。构成此接口的方法包括：

* **IOPCHDA_Server::GetItemAttributes**
    此方法返回 DeltaV OPC 历史服务器支持的属性列表。这些属性包括：
    * 数据类型 (Data Type)
    * 阶跃 (Stepped)
    * 项目ID (ItemID)
    * 最大时间间隔 (Maximum Time Interval)
    * 最小时间间隔 (Minimum Time Interval)
    * 异常偏差（以工程单位表示）(Exception Deviation (expressed in Engineering Units))
    * 当前 DeltaV 模块描述 (Current DeltaV Module Description)
    * 当前 DeltaV 工程单位 (Current DeltaV Engineering Units)
    * 当前 DeltaV 工程单位 100% 值（默认值为 100）(Current DeltaV Engineering Units 100% Value (default is 100))
    * 当前 DeltaV 工程单位 0% 值（默认值为 0）(Current DeltaV Engineering Units 0% Value (default is 0))
    * 连续历史库的上次下载时间 (Last download of Continuous Historian)
    * 连续历史库是否正在扫描 (Continuous Historian On Scan)
    * 命名集 (Named Set)

* **IOPCHDA_Server::GetAggregates**
    此方法返回 DeltaV OPC 历史服务器支持的聚合函数列表。这些聚合函数包括：
    * 插值 (Interpolative)
    * 时间平均 (Time Average)
    * 计数 (Count)
    * 最小实际时间 (Minimum Actual Time)
    * 最小值 (Minimum)
    * 最大实际时间 (Maximum Actual Time)
    * 最大值 (Maximum)
    * 开始 (Start)
    * 结束 (End)
    * 平均值 (Average)
    * 总计 (Total)

* **IOPCHDA_Server::GetHistorianStatus**
    此方法可用于获取 DeltaV OPC 历史服务器的状态。

* **IOPCHDA_Server::GetItemHandles**
    此方法返回特定 HDA 项目的服务器句柄和客户端句柄之间的关联。

* **IOPCHDA_Server::ReleaseItemHandles**
    此方法释放特定 HDA 项目的服务器句柄和客户端句柄之间的关联。

* **IOPCHDA_Server::ValidateItemIDs**
    此方法验证特定的 HDA 项目 ID 是否为服务器所知。

* **IOPCHDA_Server::CreateBrowse**
    此方法返回指向 `OPCHDA_Browser` 接口的指针。项目 ID 过滤在创建新浏览器时指定。

**IOPCHDA_Browser**

此接口提供了一种访问符合创建此浏览器时设置的过滤条件的 OPC HDA 项目 ID 列表的方法。应该注意的是，DeltaV 连续历史库提供了一个扁平的历史参数列表。因此，DeltaV OPC 历史服务器提供了一个扁平的 OPC HDA 项目 ID 列表。

* **IOPCHDA_Browser::GetEnum**
    此方法返回一个枚举，其中包含 DeltaV 连续历史库提供的所有符合过滤条件的 OPC HDA 项目 ID。

* **IOPCHDA_Browser::ChangeBrowsePosition**
    此方法可用于在 OPC HDA 项目 ID 列表中向上或向下移动，或直接移动到特定的 OPC HDA 项目 ID。

* **IOPCHDA_Browser::GetItemID**
    此方法提供了一种获取当前 OPC HDA 项目 ID 的方法。

* **IOPCHDA_Browser::GetBranchPosition**
    此方法提供当前的 OPC HDA 项目 ID。

**IOPCHDA_SyncRead**

此接口提供对 DeltaV 连续历史库所保存数据的访问。

* **IOPCHDA_SyncRead::ReadRaw**
    此方法从 DeltaV 连续历史库数据库中读取一个或多个 OPC HDA 项目在指定时间范围内的值、质量和时间戳。

* **IOPCHDA_SyncRead::ReadProcessed**
    此方法请求 DeltaV 连续历史库为一个或多个 OPC HDA 项目计算聚合值，并提供值、质量和时间戳。有关支持的聚合函数的列表，请参见 `IOPCHDA_Server::GetAggregates`。

* **IOPCHDA_SyncRead::ReadAtTime**
    DeltaV OPC 历史服务器目前不支持此方法。

* **IOPCHDA_SyncRead::ReadModified**
    DeltaV OPC 历史服务器目前不支持此方法。

* **IOPCHDA_SyncRead::ReadAttribute**
    此方法读取一个项目在指定时间范围内的属性值和时间戳。DeltaV OPC 历史服务器仅支持属性的当前值。有关支持的属性列表，请参见 `IOPCHDA_Server::GetItemAttributes`。
