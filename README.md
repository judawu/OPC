# 这是基于opcua实现的一个包装opcda的桥接项目，主要处理emerson的DELTAV系统的opc.deltav.1的opc server的访问
- _OPCDA_： opcda客户端
- _OPHDA_： opcHda客户端
- _OPCAE_： opcAE客户端
-  _OPCUAWrapper_: opcua服务器
-  _OPCUAClient_: opcua客户端

OpcDxPs.dll,OpcCmdPs.dll,opc_aeps.dll  came from https://opcfoundation.org/forum/classic-opc-da-ae-hda-xml-da-etc/ ,  
~~~
win32com.client.Dispatch("OPC.Automation")   for opcda
win32com.client.Dispatch("OPCHDA.Automation")  fro opchda
win32com.client.Dispatch("Opc_auto_ae.OpcEventServer")  for opcae
~~~
## 项目概述
本项目实现了一个基于 OPC UA 协议的客户端-服务器交互系统，包含三个客户端（`opcuaclient1`、`opcuaclient2`、`opcuaclient3`）和一个服务器，用于测试证书管理、安全策略配置、数据读写以及权限控制功能。系统使用 Python 的 `asyncua` 库构建，运行于本地环境（`opc.tcp://localhost:4840`），时间戳为 2025 年 3 月 24 日。

主要功能包括：
- **证书管理**：客户端动态获取、生成和恢复服务器证书。
- **安全策略配置**：支持多种安全策略（如 `Basic256Sha256`、`Aes256_Sha256_RsaPss`）并允许动态切换。
- **数据交互**：客户端对服务器执行读取、写入和方法调用。
- **权限控制**：通过自定义 `UserManager` 实现用户认证和角色分配。

## 系统流程
1. **初始化与等待**：
   - 三个客户端启动时等待 5 秒，确保服务器准备就绪。
   - 示例输出：opcuaclient1 is waiting 5 seconds for server to start first..
     
2. **无证书连接**：
- 客户端以无安全策略（`SecurityPolicy#None`）连接，获取服务器证书。
- 示例日志：2025-03-24 21:24:25,316 - INFO - Client connect: use_certificate set to False, Connecting with no security policy

- 
3. **证书更新与方法调用**：
- `opcuaclient1` 调用 `generate_server_certificate` 和 `set_server_policy` 重置服务器证书和安全策略。
- 示例输出：opcuaclient1 reset server security policy by call set_server_policy moethod...

- 
4. **有证书连接与操作**：
- 客户端使用证书验证重新连接，执行读写操作和安全策略查询。
- 示例输出：connecting opcuaclient2 with certficate verification...
read value to the server from opcuaclient2...


5. **断开与恢复**：
- 客户端断开连接，`opcuaclient1` 调用 `restore_server_certificate` 恢复初始证书。
- 示例日志：2025-03-24 21:24:48,417 - INFO - estore_server_certificate: Calling restore_initial_certificate...: True

- 

## 会话管理

### 设计与实现
会话管理负责跟踪客户端与服务器之间的连接状态，包括会话创建、活动状态监控和会话关闭。以下是主要特点：

- **会话创建**：
  - 每次客户端连接时，服务器创建一个会话，并记录相关信息（如客户端 IP、用户名、证书使用情况等）。
  - 日志示例：
2025-03-24 21:19:45,522 - INFO - Session added: {"client_ip": "127.0.0.1", "username": "EMERSON", "has_certificate": false, "userrole": 5, ...}
2025-03-24 21:19:47,617 - INFO - Session added: {"client_ip": "127.0.0.1", "username": "EMERSON", "has_certificate": true, "userrole": 1, ...}

- **活动状态监控**：
- `CustomUserManager` 定期检查活动传输（transports），用于跟踪当前连接的客户端。

- **会话关闭**：
- 客户端主动断开连接时，服务器关闭会话并清理资源。

- **解析**：客户端请求关闭会话（`CloseSessionRequest`），服务器确认断开。



## 权限控制



权限控制是系统的核心功能之一，旨在根据用户身份和角色分配不同的访问权限。以下是其主要设计特点：

- **用户认证**：
  - 支持两种认证方式：
    1. **匿名用户（Anonymous）**：无用户名和密码，默认分配低权限角色。
    2. **用户名认证（Username）**：基于用户名和密码，可结合证书增强安全性。
   
**角色分配**：
- 系统定义了多种用户角色：
- `UserRole.Anonymous`：匿名用户，默认最低权限。
- `UserRole.User: 3`：普通用户，可能限制敏感操作。
- `UserRole.Admin: 0`：管理员，拥有完全权限。
- 自定义角色（如 `1` 和 `5`）：根据证书或特定条件分配。


   
**权限应用**：
- 浏览与读取:普通用户可浏览和读取部分节点
- 方法调用:敏感方法（如 restore_initial_certificate）需管理员权限。


## 核心成果
### 1. 动态证书管理(这种灵活性为系统提供了证书更新的能力，避免了手动配置的繁琐，确保了长期运行的安全性。)
项目成功实现了证书的动态获取、生成和恢复流程：
- **无证书连接**：客户端以 `SecurityPolicy#None` 模式连接，获取服务器证书。
- **证书更新**：`opcuaclient1` 通过调用 `generate_server_certificate` 和 `restore_server_certificate` 方法，重置和恢复服务器证书。
### 2. 安全策略的多样性与切换
服务器支持多种安全策略，从无加密（`SecurityPolicy#None`）到高级加密（`Aes256_Sha256_RsaPss`），客户端可动态查询和应用：

### 3. 数据交互与多客户端协作(通过 `set_server_policy` 方法，系统允许运行时调整安全级别，适应不同场景需求，从开发测试到生产部署的无缝过渡。)
三个客户端展示了良好的协作性，按序执行操作，避免冲突：

### 4. 权限控制的创新实现(多客户端协同工作模拟了真实工业场景，为分布式系统设计提供了宝贵经验)
通过自定义 `CustomUserManager`，项目实现了用户认证和角色分配：
- **认证与角色**：
- 匿名用户：`UserRole.User: 3`。
- 用户 `EMERSON`：无证书时为 `5`，有证书时为 `1`（可能为管理员）。
如 `transfer_client_certificate` 和 `restore_server_certificate`，展示了客户端对服务器的控制能力。


## 价值


- **灵活性**：证书和安全策略的动态管理适应了多种使用场景。
- **协作性**：多客户端按序操作，展示了系统的高效协调能力。
- **安全性**：权限控制和加密策略的结合，为工业通信提供了坚实保障。
- **可追溯性**：详尽的日志记录（如会话创建、方法调用）便于调试和优化。



## 未来展望
本项目为 OPC UA 在工业自动化中的应用奠定了基础，未来的发展方向包括：
- **生产就绪**：优化超时机制、增强错误处理，适配真实工业环境。
- **权限细化**：实现节点级权限控制，支持更复杂的访问策略。
- **分布式扩展**：支持多服务器、多站点协作，探索 OPC UA 的分布式潜力。
- **用户界面**：开发图形化管理工具，便于配置证书和权限。

## 结语
这个项目不仅是一个技术实现的尝试，更是对 OPC UA 协议在安全性和权限管理方面潜力的深入探索。从证书管理到权限控制，从多客户端协作到安全策略切换，每一步都体现了团队对工业通信未来的思考。虽然仍有改进空间，但成果已足以证明系统的可行性和创新性。带着这些经验，我们有信心将项目推向更高层次，为智能制造和工业 4.0 贡献一份力量。
 ```
opcuaclient1 is waiting 5 seconds for server to start first..
opcuaclient2 is waiting 5 seconds for server to start first..
opcuaclient3 is waiting 5 seconds for server to start first..
opcuaclient1 connect to the server without certficate to  get server certificate ...
opcuaclient2 is waiting 10 seconds for server to update certificate ..
opcuaclient3 is waiting 10 seconds for server to update certificate ..
opcuaclient1 disconnected and connect to the server again with certficate to  reset server certificate by call generate_server_certificate moethod...
opcuaclient1 reset server security policy by call set_server_policy moethod...
New certificate applied to the opc ua server, opcuaclient1 disconnect to the server...
opcuaclient1 is waiting 10 seconds for server to update certificate ..
waiting client to init for opcuaclient2..
waiting client to init for opcuaclient3..
get server certificate for opcuaclient2 without certficate verification...
get server certificate for opcuaclient3 without certficate verification...
connecting  opcuaclient2 with certficate verification...
print the server from opcuaclient2...
read value to the server from opcuaclient2...
write value to the server from opcuaclient2....
waiting client to init for opcuaclient1..
get server certificate for opcuaclient1 without certficate verification...
connecting  opcuaclient1 with certficate verification...
use query_security_policies method at opcuaclient2 for  Security policies query : ['http://opcfoundation.org/UA/SecurityPolicy#None', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss']
opcuaclient2 disconnect to the server...
print the server from opcuaclient1...
read value to the server from opcuaclient1...
opcuaclient1 transfer client certificate.by call transfer_client_certificate...
write value to the server from opcuaclient1....
use query_security_policies method at opcuaclient1 for  Security policies query : ['http://opcfoundation.org/UA/SecurityPolicy#None', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss']
opcuaclient1 disconnect to the server...
connecting  opcuaclient3 without certficate verification...
print the server from opcuaclient3...
read value to the server from opcuaclient3...
read value  at opcuaclient3....
use query_security_policies method at opcuaclient3 for  Security policies query : ['http://opcfoundation.org/UA/SecurityPolicy#None', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss', 'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss']
opcuaclient3 disconnect to the server...
opcuaclient1 call restore_server_certificate to restore server certficate..
```
