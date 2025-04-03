## OPC HDA 客户端（Python）：代码报告

本报告分析了提供的 Python 代码，该代码实现了一个用于与 OPC 历史数据访问 (HDA) 服务器交互的客户端。该代码利用 `win32com` 库与 OPC HDA 自动化接口进行通信。

### 1. 引言

该 Python 代码定义了一个名为 `_OPCHDA_` 的类，该类封装了连接到 OPC HDA 服务器、浏览其项目、验证项目 ID、读取历史数据以及处理服务器关闭事件的逻辑。它还包含一个名为 `OPCShutdownHandler` 的辅助类，用于管理来自服务器的关闭通知。`main` 函数演示了如何使用 `_OPCHDA_` 类连接到服务器、获取其状态、浏览项目和读取原始历史数据。

### 2. 代码结构

代码主要组织成以下几个部分：

* **导入 (Imports):** 导入必要的库，包括 `win32com.client`、`pythoncom`、`pywintypes`、`logging`、`datetime` 和 `timedelta`。
* **`OPCHDA_SERVER_STATUS` 字典:** 此字典将来自 OPC HDA 服务器的整数状态代码映射到人类可读的字符串描述。
* **`_OPCHDA_` 类:** 此类包含与 OPC HDA 服务器交互的核心功能。
    * **`__init__(self, server_name: str = "DeltaV.OPCHDAsvr", client_name: str = "PythonOPCHDAClient")`:** 使用服务器名称和客户端名称初始化 `_OPCHDA_` 对象。
    * **`connect(self) -> bool`:** 使用 `win32com.client.Dispatch("OpcHda.Automation")` 建立与指定的 OPC HDA 服务器的连接。它还检索服务器的父对象并设置关闭处理程序。
    * **`disconnect(self)`:** 断开与 OPC HDA 服务器的连接并释放 COM 对象。
    * **`on_shutdown(self, reason: str)`:** 当 OPC HDA 服务器请求关闭时调用的回调函数。它记录原因并断开客户端的连接。
    * **`get_historian_status(self) -> dict`:** 检索 OPC HDA 服务器的当前状态，包括其状态代码、当前时间、服务器名称和最大返回值。
    * **`get_item_attributes(self) -> list`:** 获取 OPC HDA 服务器为其项目支持的属性列表。
    * **`browse_items(self) -> list`:** 尝试浏览 OPC HDA 服务器上可用的项目 ID。当前的实现仅检索根级别的项目。
    * **`validate_item_ids(self, item_ids: list) -> dict`:** 验证项目 ID 列表以检查它们在服务器上是否有效。它最初尝试使用 `Validate` 方法（如果可用），否则回退到单独添加和删除每个项目。
    * **`_validate_single_item_add(self, item_id: str) -> bool`:** 一个辅助方法，用于通过尝试添加项目到服务器然后将其删除来验证单个项目 ID。
    * **`read_raw(self, item_ids: list, start_time: datetime, end_time: datetime, max_values: int = 0) -> dict`:** 在指定的时间范围内读取项目 ID 列表的原始历史数据。
* **`OPCShutdownHandler` 类:** 此类处理来自 OPC HDA 服务器的 `ShutdownRequest` 事件。
* **`main()` 函数:** 此函数演示了 `_OPCHDA_` 类的用法，包括连接到服务器、获取其状态、浏览项目和读取原始数据。

### 3. 功能分解

* **连接和断开连接:** `connect` 方法初始化 COM 环境并建立与 OPC HDA 服务器的连接。`disconnect` 方法优雅地断开连接并取消初始化 COM 环境。
* **服务器状态:** `get_historian_status` 方法使用 `OPCHDA_SERVER_STATUS` 字典检索并解释服务器的状态。
* **项目属性:** `get_item_attributes` 方法检索有关可以为历史项目查询的属性的信息。
* **项目浏览:** `browse_items` 方法尝试从服务器的根级别检索项目 ID 列表。它指出，更全面的浏览实现可能需要递归遍历。
* **项目验证:** `validate_item_ids` 方法检查给定的项目 ID 列表在服务器上是否有效。它优先使用 `Validate` 方法以提高效率，但如果 `Validate` 不可用或遇到错误，则会回退到单独添加和删除项目。
* **原始数据读取:** `read_raw` 方法检索指定时间范围内给定项目 ID 的历史数据。它处理服务器响应并将数据组织成一个字典，其中键是项目 ID，值是包含值、质量和时间戳列表的字典。
* **关闭处理:** `OPCShutdownHandler` 类和 `on_shutdown` 方法确保客户端可以通过优雅地断开连接来响应来自 OPC HDA 服务器的关闭请求。

### 4. 潜在问题和观察

* **`read_raw` 中不一致的项目处理:** `read_raw` 方法中的注释表明在处理项目数量方面存在不确定性。它使用 `AddItems` 添加 `num_items - 1` 个项目，然后使用 `AddItem` 单独添加最后一个项目。这表明 `AddItems` 方法的使用方式可能存在问题或误解。
* **冗余的 `ServerHandle` 追加:** 在 `read_raw` 方法中，`last_item.ServerHandle` 被重复追加到 `server_handles` 列表中。这似乎是冗余的，可能表明试图解决处理项目数量的问题。
* **有限的项目浏览:** `browse_items` 方法目前仅检索根级别的项目。对于具有分层结构的服务器，这不会提供完整的可用项目列表。对于此类服务器，需要使用递归浏览机制。
* **临时的验证方法:** 注释“验证指定的 Item IDs 是否有效 (使用 Validate 方法 - 临时方案)” 表明当前的验证方法，特别是回退到单独 `AddItem` 的方式，可能不是最有效或最健壮的长期解决方案。
* **`read_raw` 中的错误处理:** 虽然 `read_raw` 方法中存在错误处理，但注释“why not working for last server\_handles” 表明可能存在尚未解决的问题，这可能导致数据检索不完整。随后在 `SyncReadRaw` 中使用 `len(server_handles)-1` 也与之前关于项目处理不一致的观点一致。
* **日志记录:** 代码包含广泛的日志记录，这对于调试和监控很有用。但是，在生产环境中，可能需要调整日志记录级别以避免过多的输出。
* **COM 对象管理:** 代码似乎通过在 `disconnect` 方法和 `read_raw` 方法中（当 `sync_read` 对象超出范围时隐式地）释放 COM 对象来正确管理 COM 对象。

### 5. 结论

提供的 Python 代码提供了一个功能性的 OPC HDA 客户端实现。它演示了连接到服务器、检索状态信息、浏览项目、验证其存在以及读取历史数据的能力。但是，在某些方面，尤其是在 `read_raw` 方法和项目浏览方面，可能需要进一步调查和改进以提高其健壮性和完整性。验证方法的临时性质也表明这是一个潜在的改进领域。总的来说，该代码为在 Python 环境中与 OPC HDA 服务器交互提供了一个良好的基础。

---

**OPC HDA 自定义接口和方法**

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
