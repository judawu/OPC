import logging
import os
import time
import datetime
import socket
import pythoncom
import json
import hashlib
from typing import List, Dict, Tuple, Optional
import asyncio
from asyncua import Server, ua
from asyncua.server.users import User, UserRole  # Correct import for v1.1.5
from asyncua.crypto.security_policies import (
    SecurityPolicy,
    SecurityPolicyBasic256Sha256,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyAes128Sha256RsaOaep
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from _OPCDA_ import _OPCDA_, OPCDADataCallback



class CustomUserManager:

    
    def __init__(self):
        """CustomUserManager init..."""
        self.connected_clients = {
            "count": 0,
            "sessions": {}
        }
        self.version='1.0.0'
        self.anonymous_sessions = {}  # (client_addr, start_time) pairs
        self.recently_closed = {}    # (client_addr, close_time)
        self.blacklist = {}    # (client_addr, close_time)
        self.timeout = 60            # 会话超时时间（秒）
        self.cooldown = 180           # 重连冷却时间（秒）
        self.user_roles = {
            "deltavadmin": 0,
            "EMERSON": 1,
            "FINESSE": 1,
            "CONFIGURE": 2,
            "SUPERVISE": 13,
            "OPERATE": 14,
            "CALIBRATE": 15,
            "AUDIT": 16,
            "VIEWONLY": 17,
            "default": 18,
          
        }
        self.user_passwords = {
            "deltavadmin": "Fin3ss3!",
            "EMERSON": "DeltaVE1",
            "FINESSE": "TruBioDV01",
            "CONFIGURE": "DeltaVC1",
            "SUPERVISE": "DeltaVS1",
            "OPERATE": "DeltaVO1",
            "CALIBRATE": "calibrate",
            "AUDIT": "audit",
            "VIEWONLY": "viewonly",
            "default": "password"
        }
    
    def _hash_password(self,username: str, password: str, nonce: str) -> str:
       
        return hashlib.sha256((password + username + nonce).encode('utf-8')).hexdigest()
    
    def get_user(self, iserver, username=None, password=None, certificate=None):
      
        # 尝试从 iserver 或其 session 中获取客户端地址
        client_addr = ('unknown', 0)
        transport = None
        if hasattr(iserver, 'asyncio_transports') and iserver.asyncio_transports:
            transport = iserver.asyncio_transports[-1]  # Get the most recent transport
        if transport and hasattr(transport, 'get_extra_info'):
            client_addr = transport.get_extra_info('peername') or client_addr
        elif transport and hasattr(transport, 'peername'):
            client_addr = transport.peername
        logging.debug(f"CustomUserManager: User check called: addr={client_addr[0]} at port {client_addr[1]}, username={username}, password={password}, cert={certificate is not None}")
        client_ip = client_addr[0]
        current_time = time.time()
        session_id = iserver.isession.session_id.to_string().split('=')[1]  # only get the value of session id
        if session_id in self.blacklist:
             if current_time < self.blacklist[session_id]+ self.cooldown :
                    logging.warning(f"CustomUserManager: Rejecting client session {session_id} due to blacklist")
 
                    return None
             del self.blacklist[session_id]  # 过期则移除
        
       
        client_hostname = "unknown"
        try:
            client_hostname = socket.gethostbyaddr(client_ip)[0]
            logging.debug(f"CustomUserManager: Resolved hostname for {client_ip}: {client_hostname}")
        except (socket.herror, socket.gaierror) as e:
            logging.debug(f"CustomUserManager: Failed to resolve hostname for {client_ip}: {str(e)}")

        app_name = "unknown"
        if hasattr(iserver.isession, 'application_description'):
            app_name = iserver.isession.application_description.ApplicationName.Text
            logging.debug(f"CustomUserManager: ApplicationName: {app_name}")
       
        logging.debug(f"CustomUserManager: isession.session_id: {session_id}")
        # 认证逻辑
       
   
        if username and password:
            client_password = password
            nonce = ""
            if  ":" in password:
                client_password, nonce = password.split(":")
                server_password = self._hash_password(username, self.user_passwords.get(username, "anonymous"), nonce)
            else:
                server_password = 'canyouguess?'
        # 获取会话详细信息
       
        userrole =  self.user_roles.get(username, 100)  # 默认匿名用户
        if username in self.user_passwords and password:
            
            logging.debug(f"CustomUserManager: User name {username}  exist in the user list,check userrole:")
            if certificate is not None and client_password == server_password:
               
                userrole = min(userrole, 9)  # 有证书时最低为 9
                logging.debug(f"CustomUserManager: User name {username}  have a valid cerficate,and password match  and  the pasword is encrypted,get userrole {userrole} ")
          
            elif client_password != self.user_passwords[username] and client_password != server_password and certificate is None:
                userrole = 100 # 密码不匹配，设为匿名用户
                logging.debug(f"CustomUserManager: User name {username} is in user list without a valid certficate, but password didn't match , get userrole {userrole}")
             
            elif client_password == server_password and certificate is None:
    
                    userrole =  userrole + 20
                    logging.debug(f"CustomUserManager: User name {username} and password match and the pasword is encrypted,but don't have a valid cerficate,get userrole {userrole} ")
            elif certificate is not None and client_password== self.user_passwords[username]:
                    userrole =  userrole + 10
                    logging.debug(f"CustomUserManager: User name {username} match password without encrypted , but have a valid cerficate ,get userrole {userrole} ")
            elif certificate is not None :
                    userrole =  userrole + 30
                    logging.debug(f"CustomUserManager: User name {username}  in user list pssword not right, but have a valid cerficate ,get userrole {userrole} ")
            else:
                    userrole = userrole + 40
                    logging.debug(f"CustomUserManager: User name {username} and password match but the pasword is not encrypted and don't have a valid cerficate ,get userrole {userrole} ")
            
        elif certificate is not None :
                userrole = 50
                logging.debug(f"CustomUserManager: User name {username} not in user list, but have a valid cerficate ,get userrole {userrole}")
        else:
               userrole = 100 # 密码不匹配，设为匿名用户
               logging.debug(f"CustomUserManager: User is not in user list and don't have a valid cerficate ,get userrole 100")
        if userrole>99:    
            if client_ip in self.recently_closed:
                time_since_closed = current_time - self.recently_closed[client_ip]
                if time_since_closed < self.cooldown:
                    logging.warning(f"CustomUserManager: Rejecting {client_addr} due to cooldown: {time_since_closed:.2f}s < {self.cooldown}s")
                    return None
                self.recently_closed = {ip: t for ip, t in self.recently_closed.items() if current_time - t < self.cooldown}
            if client_addr not in self.anonymous_sessions:
               
                self.anonymous_sessions[client_addr] = current_time
                logging.debug(f"CustomUserManager: New anonymous session for {client_addr}")
               
            # 如果认证成功，记录会话信息
        else:
                self.connected_clients["count"] += 1
                self.connected_clients["sessions"][session_id] = {
                    "client_ip": client_ip,
                    "client_hostname": client_hostname,
                    "application_name": app_name,
                    "has_certificate": certificate is not None,
                    "username": username if username else "None",
                    "userrole": userrole,
                    "start_time": time.time(),
                    "client_addr": client_addr
                }
                logging.debug(f"CustomUserManager: Session added: {json.dumps(self.connected_clients['sessions'][session_id], indent=2)}")
                
                if client_addr in self.anonymous_sessions:
                    del self.anonymous_sessions[client_addr]
                if client_addr[0] in self.recently_closed:
                    del self.recently_closed[client_addr[0]]
        
        if userrole < 13:
         return User(UserRole.Admin)
        elif userrole < 51:
         return User(UserRole.User)
        else:
         return User(UserRole.Anonymous)
    def check_method_permission(self, allowrole: int, userrole: int) -> bool:
        """检查用户是否有权限调用指定方法"""
       
        if allowrole == 0 and  userrole  != 0:
            allowed = False  # for superadmin
        elif userrole  == 0:
            allowed = True  # for superadmin
        else:
            allowed = userrole <= allowrole
        logging.debug(f"CustomUserManager: Checking permission : User role={userrole}, Required={allowrole} , Allowed={allowed}")
        return allowed  
        
    async def monitor_anonymous_sessions(self,iserver):
                logging.debug("CustomUserManager: Starting anonymous session monitor")
                while True:
                    try:
                        current_time = time.time()
                        transports = {t.get_extra_info('peername'): t for t in iserver.asyncio_transports} if hasattr(iserver, 'asyncio_transports') else {}
                        if transports:
                           logging.debug(f"CustomUserManager: Active transports: {transports.keys()}")

                        # 处理匿名会话
                        if self.anonymous_sessions:
                            logging.debug(f"CustomUserManager: Checking anonymous sessions: {self.anonymous_sessions}")
                            expired_sessions = [
                                addr for addr, start_time in self.anonymous_sessions.items()
                                if current_time - start_time > self.timeout
                            ]
                            for addr in expired_sessions:
                                logging.debug(f"CustomUserManager: Found expired session {addr}, duration: {current_time - self.anonymous_sessions[addr]:.2f}s")
                                if addr in transports:
                                    await self._close_session(iserver, addr)
                                else:
                                    logging.debug(f"CustomUserManager: Anonymous session {addr} already disconnected, cleaning up")
                                    del self.anonymous_sessions[addr]
                                    self.recently_closed[addr[0]] = current_time

                        # 更新非匿名会话状态
                        if self.connected_clients["sessions"]:
                            logging.debug(f"CustomUserManager: Checking connected_clients: {json.dumps(self.connected_clients, indent=2)}")
                            for session_id in list(self.connected_clients["sessions"].keys()):
                                session = self.connected_clients["sessions"][session_id]
                                client_addr = session["client_addr"]
                                if client_addr not in transports:
                                    self.connected_clients["count"] -= 1
                                    del self.connected_clients["sessions"][session_id]
                                    logging.debug(f"CustomUserManager: Removed disconnected session {session_id}, updated count: {self.connected_clients['count']}")
                                    self.recently_closed[session["client_ip"]] = current_time
                                else:
                                    session["last_active"] = current_time

                        await asyncio.sleep(10)  # 每 10 秒检查一次
                    except Exception as e:
                        logging.error(f"CustomUserManager: Error in monitor_anonymous_sessions: {str(e)}", exc_info=True)
                        await asyncio.sleep(10)  # 出错后继续运行
    async def _close_session(self, iserver,client_addr):
          
                if client_addr not in self.anonymous_sessions:
                    logging.debug(f"CustomUserManager: Session {client_addr} not found in anonymous_sessions, skipping")
                    return
                duration = time.time() - self.anonymous_sessions[client_addr]
                logging.warning(f"CustomUserManager: Closing anonymous session {client_addr} after {duration:.2f}s")
                transports = {t.get_extra_info('peername'): t for t in iserver.asyncio_transports} if hasattr(iserver, 'asyncio_transports') else {}
                transport = transports.get(client_addr)
                if transport:
                    transport.close()
                    logging.debug(f"CustomUserManager: Transport closed for {client_addr}")
                else:
                    logging.debug(f"CustomUserManager: No active transport found for {client_addr}, assuming already closed")
                del self.anonymous_sessions[client_addr]
                self.recently_closed[client_addr[0]] = time.time()
                # 清理 connected_clients
                for session_id, session in list(self.connected_clients["sessions"].items()):
                    if session["client_addr"] == client_addr:
                        self.connected_clients["count"] -= 1
                        del self.connected_clients["sessions"][session_id]
                        logging.debug(f"CustomUserManager: Removed session {session_id} from connected_clients due to timeout")
    
    async def query_connected_clients(self):
            return json.dumps(self.connected_clients)

    async def disconnect_session(self, iserver, session_id: str) -> bool:
        """
        根据 session_id 断开指定客户端的连接。
        返回 True 表示成功，False 表示失败。
        """
        current_time = time.time()
        session_found = False

        # 检查 session_id 是否存在于 connected_clients
        if session_id in self.connected_clients["sessions"]:
            session_info = self.connected_clients["sessions"][session_id]
            client_addr = session_info["client_addr"]
          
            logging.debug(f"CustomUserManager.disconnect_client_by_session_id: Attempting to disconnect session {session_id} for {client_addr}")

            # 查找对应的 transport 并关闭
            if hasattr(iserver, 'asyncio_transports'):
                for transport in iserver.asyncio_transports:
                    peername = transport.get_extra_info('peername')
                    if peername == client_addr:
                        transport.close()
                        logging.debug(f"CustomUserManager.disconnect_client_by_session_id: Closed transport for session {session_id}, client {client_addr}")

                        session_found = True
                        break

            if session_found:
                # 更新 connected_clients
                self.connected_clients["count"] -= 1
                del self.connected_clients["sessions"][session_id]
                self.recently_closed[session_info["client_ip"]] = current_time
                self.blacklist[session_id]=current_time
                logging.debug(f"CustomUserManager.disconnect_client_by_session_id: Session {session_id} removed from connected_clients")
                return True
            else:
                logging.warning(f"CustomUserManager.disconnect_client_by_session_id: No active transport found for session {session_id}")
                return False
        else:
            logging.warning(f"CustomUserManager.disconnect_client_by_session_id: Session {session_id} not found in connected_clients")
            return False
    
class _OPCDAWrapper_:

    class Event:
        def __init__(self):
            self.running = asyncio.Event()
            self.polling = asyncio.Event()
            self.writing = asyncio.Event()
            self.shutdown = asyncio.Event()
            self.restart = asyncio.Event()
            self.broswe_opcda_struture = asyncio.Event()
            self.update_structure = asyncio.Event()        
    class Node:
        def __init__(self,name:str= 'UASERVER', endpoint: str = 'opc.tcp://0.0.0.0:4840'):
            self.endpoint = endpoint
          
            self.name = name
            self.application_uri = "http://OPC.DELTAV.1"
            self.idx = None
            self.da_folder = None
            self.cert_node = None
            self.nodes = {}  # Dict[str, ua.Node]
            self.folders = {}  # 新增: 用于存储文件夹节点
            self.items = []
            self.last_error_code = None  # 用于存储错误状态的节点
            self.last_error_desc = None  # 用于存储错误状态的节点
        async def __get_server_info__(self):
             server_details = {
                "ServerName":  self.name,
                "application_uri": self.application_uri,
                "idx": self.idx,
                "endpoint": self.endpoint,
                "version": '1.0.9',
                "VendorInfo": 'Juda.monster'
            }
    class Cert:
        def __init__(self):
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
            self.cert_dir = os.path.join(self.base_dir, "cert")
            self.initial_cert_path = os.path.join(self.cert_dir, "server_init_cert.pem")
            self.initial_key_path = os.path.join(self.cert_dir, "server_init_key.pem")
            self.cert_path = os.path.join(self.cert_dir, "server_cert.pem")
            self.key_path = os.path.join(self.cert_dir, "server_key.pem")
            self.trustedcert_dir=os.path.join(self.cert_dir, "trusted")
           
            self.security_policies = None # 运行时动态填充
    class OPCDAstack:
        def __init__(self):
            self.group_name :str = "OPCDAGroup"
           
            self.update_rate: int= 1000
            self.write_lock = asyncio.Lock()
            self.poll_queue = Queue()
            self.write_queue = Queue()
            self.update_count = 0
            self.max_updates = None
        
            self.max_level = 1
            self.path_lock = asyncio.Lock()
            self.path =None
          
            self.structure={}
    def _update_from_json(self, config: Dict):
        """从 JSON 配置更新子对象的属性"""
        for group, values in config.items():
            if hasattr(self, group):
                target = getattr(self, group)
                for key, value in values.items():
                    if hasattr(target, key):
                        setattr(target, key, value)
   
    def __init__(self, opc_da: '_OPCDA_',name:str= 'OPC.DELTAV.1', endpoint: str = 'opc.tcp://0.0.0.0:4840',config: Dict = None):
        """init the server"""
        self.event = self.Event()
        self.node = self.Node(name=name,endpoint=endpoint)
        self.cert = self.Cert()
        self.opcdastack = self.OPCDAstack()
       
        if config:
            self._update_from_json(config)
        self.opc_da = opc_da
        self.callback = OPCDADataCallback(self.custom_callback)
        self.user_manager = CustomUserManager()  # 强制初始化，避免 None
        self.server = Server(user_manager=self.user_manager)
        self.server.set_server_name(self.node.name)
        self.server.set_endpoint(self.node.endpoint)  # 设置端点
        logging.info(f"_OPCDAWrapper_.init: Server type: {type(self.server)}, iserver type: {type(self.server.iserver)},user_manager set to Custom user manager ")
        self.executor = ThreadPoolExecutor(max_workers=1)
       
       
        # logging.info(f"server attributes: {dir(self.server)}")
     
        # logging.info(f"iserver attributes: {dir(self.server.iserver)}")
        # logging.info(f"iserver check_user_token attributes: {dir(self.server.iserver.check_user_token)}")
        # logging.info(f"iserver isession attributes: {dir(self.server.iserver.isession)}")
        # logging.info(f"iserver isession iserver attributes: {dir(self.server.iserver.isession.iserver)}")
        # logging.info(f"iserver _known_servers attributes: {dir(self.server.iserver._known_servers)}")
        # logging.info(f"iserver _mangle_endpoint_url attributes: {dir(self.server.iserver._mangle_endpoint_url)}")
        # logging.info(f"iserver _set_current_time_loop attributes: {dir(self.server.iserver._set_current_time_loop)}")
        # logging.info(f"iserver _time_task_stop attributes: {dir(self.server.iserver._time_task_stop)}")
        # logging.info(f"iserver allow_remote_admin' attributes: {dir(self.server.iserver.allow_remote_admin)}")
        # logging.info(f"iserver aspace attributes: {dir(self.server.iserver.aspace)}")
        # logging.info(f"iserver asyncio_transports attributes: {dir(self.server.iserver.asyncio_transports)}")
        # logging.info(f"iserver attribute_service' attributes: {dir(self.server.iserver.aspace)}")
        # logging.info(f"iserver aspace attributes: {dir(self.server.iserver.attribute_service)}")
        # logging.info(f"iserver bind_condition_methods attributes: {dir(self.server.iserver.bind_condition_methods)}")
        # logging.info(f"iserver callback_service attributes: {dir(self.server.iserver.callback_service)}")
        # logging.info(f"iserver certificate attributes: {dir(self.server.iserver.certificate)}")
        # logging.info(f"iserver certificate_validator attributes: {dir(self.server.iserver.certificate_validator)}")
        # logging.info(f"iserver check_user_token attributes: {dir(self.server.iserver.check_user_token)}")
        # logging.info(f"iserver create_session attributes: {dir(self.server.iserver.create_session)}")
        # logging.info(f"iserver current_time_node attributes: {dir(self.server.iserver.current_time_node)}")
        # logging.info(f"iserver endpoints attributes: {dir(self.server.iserver.endpoints)}")
        # logging.info(f"iserver find_servers attributes: {dir(self.server.iserver.find_servers)}")
        # logging.info(f"iserver method_service attributes: {dir(self.server.iserver.method_service)}")
        # logging.info(f"iserver match_discovery_endpoint_url attributes: {dir(self.server.iserver.match_discovery_endpoint_url)}")
        # logging.info(f"iserver match_discovery_source_ip attributes: {dir(self.server.iserver.match_discovery_source_ip)}")
        # logging.info(f"iserver method_service attributes: {dir(self.server.iserver.method_service)}")
        # logging.info(f"iserver node_mgt_service attributes: {dir(self.server.iserver.node_mgt_service)}")
        # logging.info(f"iserver register_server attributes: {dir(self.server.iserver.register_server)}")
        # logging.info(f"iserver register_server2 attributes: {dir(self.server.iserver.register_server2)}")
        # logging.info(f"iserver set_attribute_value_callback attributes: {dir(self.server.iserver.set_attribute_value_callback)}")
        # logging.info(f"iserver set_attribute_value_setter attributes: {dir(self.server.iserver.set_attribute_value_setter)}")
        # logging.info(f"iserver setup_condition_methods attributes: {dir(self.server.iserver.setup_condition_methods)}")
        # logging.info(f"iserver setup_nodes attributes: {dir(self.server.iserver.setup_nodes)}")
        # logging.info(f"iserver subscribe_server_callback attributes: {dir(self.server.iserver.subscribe_server_callback)}")
        # logging.info(f"iserver subscription_service attributes: {dir(self.server.iserver.subscription_service)}")
        # logging.info(f"iserver supported_tokens attributes: {dir(self.server.iserver.supported_tokens)}")
        # logging.info(f"iserver time_task attributes: {dir(self.server.iserver.time_task)}")
        # logging.info(f"iserver unsubscribe_server_callback attributes: {dir(self.server.iserver.unsubscribe_server_callback)}")
        # logging.info(f"iserver user_manager attributes: {dir(self.server.iserver.user_manager)}")
        # logging.info(f"iserver view_service attributes: {dir(self.server.iserver.view_service)}")
        # logging.info(f"iserver write_attribute_value attributes: {dir(self.server.iserver.write_attribute_value)}")
        # logging.info(f"iserver disabled_clock attributes: {dir(self.server.iserver.disabled_clock)}")
        # logging.info(f"iserver dump_address_space attributes: {dir(self.server.iserver.dump_address_space)}")
        # logging.info(f"iserver get_endpoints attributes: {dir(self.server.iserver.get_endpoints)}")
        # logging.info(f"iserver get_new_channel_id attributes: {dir(self.server.iserver.get_new_channel_id)}")
        # logging.info(f"iserver history_manager attributes: {dir(self.server.iserver.history_manager)}")
       
        # logging.info(f"iserver load_standard_address_space attributes: {dir(self.server.iserver.load_standard_address_space)}")
        # logging.info(f"iserver load_address_space attributes: {dir(self.server.iserver.load_address_space)}")
        # logging.info(f"iserver logger attributes: {dir(self.server.iserver.logger)}")
        # logging.info(f"iserver init attributes: {dir(self.server.iserver.init)}")
        # logging.info(f"iserver isession _current_connections attributes: {dir(self.server.iserver.isession._current_connections)}")
        # logging.info(f"iserver isession activate_session attributes: {dir(self.server.iserver.isession.activate_session)}")
        # logging.info(f"iserver isession browse attributes: {dir(self.server.iserver.isession.browse)}")
        # logging.info(f"iserver isession close_session attributes: {dir(self.server.iserver.isession.close_session)}")
        # logging.info(f"iserver isession create_monitored_items attributes: {dir(self.server.iserver.isession.create_monitored_items)}")
        # logging.info(f"iserver isession create_session attributes: {dir(self.server.iserver.isession.create_session)}")
        # logging.info(f"iserver isession create_subscription attributes: {dir(self.server.iserver.isession.create_subscription)}")
        # logging.info(f"iserver isession delete_monitored_items attributes: {dir(self.server.iserver.isession.delete_monitored_items)}")
        # logging.info(f"iserver isession delete_nodes attributes: {dir(self.server.iserver.isession.delete_nodes)}")
        # logging.info(f"iserver isession add_references attributes: {dir(self.server.iserver.isession.add_references)}")
        # logging.info(f"iserver isession delete_references attributes: {dir(self.server.iserver.isession.delete_references)}")
        # logging.info(f"iserver isession delete_subscriptions attributes: {dir(self.server.iserver.isession.delete_subscriptions)}")
        # logging.info(f"iserver isession external attributes: {dir(self.server.iserver.isession.external)}")
        # logging.info(f"iserver isession get_endpoints attributes: {dir(self.server.iserver.isession.get_endpoints)}")
        # logging.info(f"iserver isession is_activated attributes: {dir(self.server.iserver.isession.is_activated)}")
        # logging.info(f"iserver isession iserver attributes: {dir(self.server.iserver.isession.iserver)}")
        # logging.info(f"iserver isession max_connections attributes: {dir(self.server.iserver.isession.max_connections)}")
        # logging.info(f"iserver isession modify_monitored_items attributes: {dir(self.server.iserver.isession.modify_monitored_items)}")
        # logging.info(f"iserver isession modify_subscription attributes: {dir(self.server.iserver.isession.modify_subscription)}")
        # logging.info(f"iserver isession name attributes: {dir(self.server.iserver.isession.name)}")
        # logging.info(f"iserver isession nonce attributes: {dir(self.server.iserver.isession.nonce)}")
        # logging.info(f"iserver isession publish attributes: {dir(self.server.iserver.isession.publish)}")
        # logging.info(f"iserver isession read attributes: {dir(self.server.iserver.isession.read)}")
        # logging.info(f"iserver isession register_nodes attributes: {dir(self.server.iserver.isession.register_nodes)}")
        # logging.info(f"iserver isession session_id attributes: {dir(self.server.iserver.isession.session_id)}")
        # logging.info(f"iserver isession state attributes: {dir(self.server.iserver.isession.state)}")
        # logging.info(f"iserver isession session_timeout attributes: {dir(self.server.iserver.isession.session_timeout)}")
        # logging.info(f"iserver isession subscription_service attributes: {dir(self.server.iserver.isession.subscription_service)}")
        # logging.info(f"iserver isession transfer_subscriptions attributes: {dir(self.server.iserver.isession.transfer_subscriptions)}")
        # logging.info(f"iserver isession translate_browsepaths_to_nodeids attributes: {dir(self.server.iserver.isession.translate_browsepaths_to_nodeids)}")
        # logging.info(f"iserver isession call attributes: {dir(self.server.iserver.isession.call)}")
        # logging.info(f"iserver isession browse_next attributes: {dir(self.server.iserver.isession.browse_next)}")
        # logging.info(f"iserver isession auth_token attributes: {dir(self.server.iserver.isession.auth_token)}")
        # logging.info(f"iserver isession aspace attributes: {dir(self.server.iserver.isession.aspace)}")
        # logging.info(f"iserver isession auth_token attributes: {dir(self.server.iserver.isession.auth_token)}")
        # logging.info(f"iserver isession unregister_nodes attributes: {dir(self.server.iserver.isession.unregister_nodes)}")
        # logging.info(f"iserver isession user attributes: {dir(self.server.iserver.isession.user)}")
        # logging.info(f"iserver isession write attributes: {dir(self.server.iserver.isession.write)}")
       
    async def generate_self_signed_cert(self,cert_path:str=None, key_path:str=None):
        if cert_path is None or key_path is None:
            cert_path= self.cert.cert_path
            key_path=self.cert.key_path
        name = self.node.name
        application_uri=self.node.application_uri
        logging.debug(f"_OPCDAWrapper_.generate_self_signed_cert: Generating self-signed certificate at {cert_path} and key at {key_path}")
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "xAI"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            hostname = socket.gethostname()
            san = x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(hostname),
                x509.UniformResourceIdentifier(application_uri),  # 确保与 server.set_application_uri 一致
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.UTC))
                .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
                .add_extension(san, critical=False)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                    critical=False
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(
                    x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
                    critical=False
                )
                .sign(key, hashes.SHA256())
            )
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            logging.info(f"_OPCDAWrapper_.generate_self_signed_cert:Successfully generated certificate at {cert_path} and key at {key_path}")
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.generate_self_signed_cert:Failed to generate certificate: {str(e)}")
            if self.node.last_error_desc is not None:
               await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.generate_self_signed_cert: Failed to generate certificate: {str(e)}")
            raise
    async def restore_initial_certificate(self,parent=None):
            userrole = await self._get_current_userrole()
            if not self.user_manager.check_method_permission(12, userrole):
                logging.warning(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate by")
                if self.node.last_error_code is not None and self.node.last_error_desc is not None:
                    await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            try:
                await self.server.load_certificate(self.cert.initial_cert_path)
                await self.server.load_private_key(self.cert.initial_key_path)
                self.server.set_security_policy(self.cert.security_policies)
                with open(self.cert.initial_cert_path, "rb") as f:
                    
                    await self.node.cert_node.write_value(f.read())
                logging.info("_OPCDAWrapper_.restore_initial_certificate:Restored initial certificate and security policies")
                return [ua.Variant(True, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate: {str(e)}")
                if self.node.last_error_desc is not None: 
                    await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate:,Error Occured: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]     
    async def add_client_certificate(self,parent,client_cert_variant):
        """动态添加客户端证书到信任列表"""
        userrole = await self._get_current_userrole()
        if not self.user_manager.check_method_permission(50, userrole):
                logging.warning(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate")
                await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
        client_cert_data = client_cert_variant.Value
        
        # 解析证书以确认有效性
        try:
            cert = x509.load_pem_x509_certificate(client_cert_data)
            logging.debug(f"_OPCDAWrapper_.add_client_certificate:Received client certificate: Subject={cert.subject}, Serial={cert.serial_number}")
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate: {e}")
            await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate,Error Occured: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]

        # 定义信任证书路径
        trust_dir = self.cert.trustedcert_dir # 替换为你的信任目录
        if not os.path.exists(trust_dir):
            os.makedirs(trust_dir, exist_ok=True)
        
        # 将证书写入文件
        client_cert_path = os.path.join(trust_dir, f"client_cert_{cert.serial_number}.pem")
        with open(client_cert_path, "wb") as f:
            f.write(client_cert_data)
        logging.debug(f"_OPCDAWrapper_.add_client_certificate:Added client certificate to {client_cert_path}")

       
     
        return [ua.Variant(True, ua.VariantType.Boolean)]  
    async def generate_server_certificate(self, parent):
            userrole = await self._get_current_userrole()
          
            if not self.user_manager.check_method_permission(4, userrole):
                logging.warning(f"_OPCDAWrapper_.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            
            try:
              
                await self.generate_self_signed_cert()
              
                return [ua.Variant(True, ua.VariantType.Boolean)]  # 正确返回 OPC UA Variant 列表
            
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.generate_server_certificate:Failed to generate certificate: {str(e)}")
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.generate_server_certificate:FFailed to generate certificate,Error Occured: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表
    async def set_server_policy(self, parent, security_policy_variant, sign_and_encrypt_variant):
            userrole = await self._get_current_userrole()
           
            if not self.user_manager.check_method_permission(12, userrole):
                logging.warning("_OPCDAWrapper_.set_server_policy:Unauthorized attempt to call set_server_policy")
                await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.set_server_policy:nauthorized attempt to call set_server_policy ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            try:
                security_policy = security_policy_variant.Value
                sign_and_encrypt = sign_and_encrypt_variant.Value

               
                policy_map = {
                    "Basic256Sha256": SecurityPolicyBasic256Sha256,
                    "AES256Sha256RsaPss": SecurityPolicyAes256Sha256RsaPss,
                    "AES128Sha256RsaOaep": SecurityPolicyAes128Sha256RsaOaep
                }
                policy_class = policy_map.get(security_policy, SecurityPolicyBasic256Sha256)
                mode = ua.MessageSecurityMode.SignAndEncrypt if sign_and_encrypt else ua.MessageSecurityMode.Sign
                self.cert.security_policies = [SecurityPolicy(), policy_class]
                for policy in self.cert.security_policies:
                    if policy != SecurityPolicy():
                        policy.ClientCertificateDir = self.cert.trustedcert_dir
                
                logging.debug(f"_OPCDAWrapper_.set_server_policy:Updated security policy to {security_policy}:{'SignAndEncrypt' if sign_and_encrypt else 'Sign'}")
               
                self.server.set_security_policy(self.cert.security_policies)
                logging.debug(f"_OPCDAWrapper_.set_server_policy:Security policies set: {[policy.URI for policy in self.cert.security_policies]}")
                return [ua.Variant(True, ua.VariantType.Boolean)]  # 失败时也返回列表
            
          
            
            except Exception as e:
                logging.error(f"_OPCDAWrapper_:Failed to update Security policies: {str(e)}")
                await self.node.last_error_desc.write_value(f"Failed to update Security policies: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表
    async def _get_current_userrole(self):
        # 默认用户角色，假设未识别时为最低权限（如 Anonymous）
            userrole = 100  # 或根据需求改为其他默认值，例如 12 表示 Anonymous

            # 步骤 1：尝试获取外部客户端的 userrole
            client_addr = None
            if hasattr(self.server.iserver, 'asyncio_transports') and self.server.iserver.asyncio_transports:
                transport = self.server.iserver.asyncio_transports[-1]
                client_addr = transport.get_extra_info('peername') or ('unknown', 0)
                for session_id, session_info in self.user_manager.connected_clients["sessions"].items():
                    if session_info["client_addr"] == client_addr:
                        userrole = session_info["userrole"]
                        logging.debug(f"_get_current_userrole: Found external client session, userrole={userrole}, client_addr={client_addr}")
                        return userrole

            # 步骤 2：如果没有外部客户端连接，检查服务器内部会话
            if hasattr(self.server.iserver, 'isession') and self.server.iserver.isession:
                session_user = self.server.iserver.isession.user
                if session_user:
                    # 根据 UserRole 映射到你的自定义 userrole
                    role_map = {
                        UserRole.Admin: 0,    # 假设 Admin 映射到 deltavadmin (最高权限)
                        UserRole.User: 15,    
                        UserRole.Anonymous: 50  
                    }
                    userrole = role_map.get(session_user.role, 100)  # 默认匿名用户
                    logging.debug(f"_get_current_userrole: No external client, using internal session user, role={session_user.role}, mapped userrole={userrole}")
                    return userrole

            # 步骤 3：如果仍然没有找到用户角色，返回默认值
            logging.debug(f"_get_current_userrole: No client or session found, returning default userrole={userrole}")
            return userrole
    async def get_connected_clients(self, parent) -> list:
            """
            OPC UA 方法：返回当前连接的客户端信息。
            返回值：[String] - JSON 格式的 connected_clients 数据
            """
            userrole = await self._get_current_userrole()
            if not self.user_manager.check_method_permission(50, userrole):  # 限制为 OPERATE 或更高权限
                logging.warning(f"_OPCDAWrapper_.get_connected_clients: Unauthorized attempt to query clients")
                await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.node.last_error_desc.write_value("Unauthorized attempt to query clients")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            clients_json = await self.user_manager.query_connected_clients()
            return [ua.Variant(clients_json, ua.VariantType.String)]
    async def disconnect_client(self, parent, session_id_variant) -> list:
        """
        OPC UA 方法：根据 session_id 断开客户端连接。
        输入参数：session_id (String)
        返回值：[Boolean] - True 表示成功，False 表示失败
        """
        userrole = await self._get_current_userrole()
        if not self.user_manager.check_method_permission(12, userrole):  # 限制为 Admin 权限 (userrole <= 0)
            logging.warning(f"_OPCDAWrapper_.disconnect_client: Unauthorized attempt to disconnect client")
            await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.node.last_error_desc.write_value("Unauthorized attempt to disconnect client")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

        session_id = session_id_variant.Value
        try:
            success = await self.user_manager.disconnect_session(self.server.iserver, session_id)
            if success:
                logging.debug(f"_OPCDAWrapper_.disconnect_client: Successfully disconnected session {session_id}")
                return [ua.Variant(True, ua.VariantType.Boolean)]
            else:
                logging.warning(f"_OPCDAWrapper_.disconnect_client: Failed to disconnect session {session_id}")
                await self.node.last_error_desc.write_value(f"Failed to disconnect session {session_id}")
                return [ua.Variant(False, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.disconnect_client: Error disconnecting session {session_id}: {str(e)}")
            await self.node.last_error_desc.write_value(f"Error disconnecting session {session_id}: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]


    async def setup_opc_ua_server(self):
          # 设置用户管理器
        
        
            # 检查节点是否存在
       
        await self.server.init()
        uri = self.node.application_uri
        self.node.idx = await self.server.register_namespace(uri)
        await self.server.set_application_uri(uri)
        logging.info(f"_OPCDAWrapper_.setup_opc_ua_server:Registered namespace index: {self.node.idx}")
        objects = self.server.nodes.objects
        self.node.da_folder = await objects.add_folder(self.node.idx, self.node.name)   
        logging.info(f"_OPCDAWrapper_.setup_opc_ua_server:add foulder to self.node.da_folder: {self.node.idx}: {self.node.name}")
        if self.server.iserver.isession:
          logging.debug(f"_OPCDAWrapper_.setup_opc_ua_server:Initial isession.user after init: name={self.server.iserver.isession.user.name}, role={self.server.iserver.isession.user.role}")


        if not os.path.exists(self.cert.initial_cert_path) or not os.path.exists(self.cert.initial_key_path):
            logging.info("_OPCDAWrapper_.setup_opc_ua_server:init Certificate or key not found, generating new ones...")
            await self.generate_self_signed_cert(self.cert.initial_cert_path, self.cert.initial_key_path)
        
        
        
        self.server.set_security_IDs(["Anonymous", "Username"])  # 调整顺序，确保 Anonymous 在前
      

        self.node.cert_node = await self.node.da_folder.add_variable(
            self.node.idx, "ServerCertificate", b"", ua.VariantType.ByteString
        )

      
        cert_path = self.cert.cert_path if os.path.exists(self.cert.cert_path) else self.cert.initial_cert_path
        key_path = self.cert.key_path if os.path.exists(self.cert.key_path) else self.cert.initial_key_path

        # 加载证书和私钥
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            await self.server.load_certificate(cert_path)
        with open(key_path, "rb") as f:
            key_data = f.read()
            await self.server.load_private_key(key_path)
        await self.node.cert_node.write_value(cert_data)
        logging.info("_OPCDAWrapper_.setup_opc_ua_server: Server certificate loaded and available at ServerCertificate node")

       
       
        self.cert.security_policies = [SecurityPolicy(), SecurityPolicyBasic256Sha256,SecurityPolicyAes256Sha256RsaPss,SecurityPolicyAes128Sha256RsaOaep]
        for policy in self.cert.security_policies:
                    if policy != SecurityPolicy():
                        policy.ClientCertificateDir = self.cert.trustedcert_dir

        # self.server.set_security_policy(self.cert.security_policies)
        # logging.info(f"_OPCDAWrapper_.setup_opc_ua_server: Security policies set: {[policy.URI for policy in self.cert.security_policies]}")
      
        self.node.last_error_code = await self.node.da_folder.add_variable(
            self.node.idx, "LastErrorStatus", 0, ua.VariantType.Int64
        )
        await self.node.last_error_code.set_writable()

        self.node.last_error_desc = await self.node.da_folder.add_variable(
            self.node.idx, "LastErrorDesc", "", ua.VariantType.String
        )
        await self.node.last_error_desc.set_writable()
        # 添加方法并设置权限
        method_nodes = {
            "write_items": await self.node.da_folder.add_method(
                self.node.idx, "write_items", self.write_items,
                [ua.VariantType.Variant,ua.VariantType.String], [ua.VariantType.Boolean]
            ),
            "add_client_cert": await self.node.da_folder.add_method(
                self.node.idx, "add_client_cert", self.add_client_certificate,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "generate_server_certificate": await self.node.da_folder.add_method(
                self.node.idx, "generate_server_certificate", self.generate_server_certificate,
                [], [ua.VariantType.Boolean]
            ),
            "set_server_policy": await self.node.da_folder.add_method(
                self.node.idx, "set_server_policy", self.set_server_policy,
                [ua.VariantType.String, ua.VariantType.Boolean], [ua.VariantType.Boolean]
            ),
            "restore_initial_certificate": await self.node.da_folder.add_method(
                self.node.idx, "restore_initial_certificate", self.restore_initial_certificate,
                [], [ua.VariantType.Boolean]
            ),
             "get_connected_clients":await self.node.da_folder.add_method(
                                        self.node.idx, "get_connected_clients", self.get_connected_clients,
                                        [], [ua.VariantType.String]
             ),
             "disconnect_client": await self.node.da_folder.add_method(  
                self.node.idx, "disconnect_client", self.disconnect_client,
                [ua.VariantType.String], [ua.VariantType.Boolean]
            ),

            "restart_server": await self.node.da_folder.add_method(  
                self.node.idx, "restart_server", self.restart,
                [], [ua.VariantType.Boolean]
            ),

            "add_item": await self.node.da_folder.add_method(  
                self.node.idx, "add_item", self.update_item,
                [ua.VariantType.String,ua.VariantType.Int32],  [ua.VariantType.String]  # 返回值类型
            )


        }

        # 为每个方法设置角色权限
    async def restart(self,parent=None):
            userrole = await self._get_current_userrole()
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
                 self.disconnect_client(session_id)
                 
        # self.user_manager.connected_clients["count"] = 0
        # self.user_manager.connected_clients["sessions"].clear()
        try:
            self.executor.shutdown(wait=True)
            logging.debug("_OPCDAWrapper_.stop:Executor shutdown completed")
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.stop:Executor shutdown error: {str(e)}")
            self.executor.shutdown(wait=False)
        await asyncio.sleep(1)
        if self.user_manager.connected_clients["count"] == 0 and restore_init_cert:
           
               await self.restore_initial_certificate(None)
            

  
        #仅在服务器仍运行时调用 stop()
        if self.server and hasattr(self.server, 'bserver') and self.server.bserver is not None:
            await self.server.stop()
          
        logging.info(f"_OPCDAWrapper_.stop:Shutdown complete at {time.strftime('%H:%M:%S')}")
    async def add_items(self, items: List[str],base_path: str = 'MODULES'):
       
            last_values = {}
            logging.debug(f"_OPCDAWrapper_.add_items: try to  add items node for {items} at {base_path}...")

            await self.async_poll(items, interval=1.0, max_time=2.0)
       
            

            for item in items:             
                data = self.callback.get_data(item)              
                if data and data[1] != 0:  # 检查数据有效性
                    if item not in self.node.items:
                        self.node.items.append(item)
                        logging.debug(f"_OPCDAWrapper_.add_items: Added {item} to self.node.items")
                    value, quality, timestamp = data
                    status = ua.StatusCode(ua.StatusCodes.Good) if quality == 192 else ua.StatusCode(ua.StatusCodes.Bad)                   
                    # 处理时间戳
                    if isinstance(timestamp, str):
                        try:
                            source_timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        except ValueError as e:
                            logging.warning(f"_OPCDAWrapper_.add_items Invalid timestamp format for {item}: {timestamp}, using current time. Error: {e}")
                            source_timestamp = datetime.datetime.now(datetime.UTC)
                    elif isinstance(timestamp, datetime.datetime):
                        source_timestamp = timestamp
                    else:
                        logging.warning(f"_OPCDAWrapper_.add_items: Unsupported timestamp type for {item}: {type(timestamp)}, using current time")
                        source_timestamp = datetime.datetime.now(datetime.UTC)
                    
                    # 如果值有变化或节点不存在，则更新或创建节点
                    
                    if item not in last_values or last_values[item] != value:
                       
                        if item not in self.node.nodes:
                            #item_path='.'.join([base_path, item.split('/')[0]])                           
                            target_folder=await self.create_folder(base_path)                                                         
                            
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
                            
                            # 在目标文件夹下创建节点
                            node_name = item  
                            node = await target_folder.add_variable(self.node.idx, node_name, initial_value, varianttype=variant_type)
                            await node.set_writable(True)
                            self.node.nodes[item] = node
                            node_id = node.nodeid
                            logging.debug(f"_OPCDAWrapper_.add_items: Added UA node for {item} with type {variant_type}, NodeId: {node_id}")
                            # 添加 PollItem 方法
                            async def poll_item_wrapper(parent,item=item):
                                    logging.debug(f"_OPCDAWrapper_.poll_item: Client called PollItem for {item}")
                                    return await self.poll_item(parent, item)
                            
                            await node.add_method(
                                self.node.idx,
                                f"PollItem_{item.replace('/', '_')}",  # 避免特殊字符影响方法名
                                poll_item_wrapper,
                                [],  
                                [ua.VariantType.Boolean]  # 返回布尔值表示成功与否
                            )

                        
                            # 添加 WriteItem 方法
                            async def write_item_wrapper(parent,value_variant,item=item):
                                logging.debug(f"_OPCDAWrapper_.write_item: Client called WriteItem for {item} with value {value_variant.Value}")
                                return await self.write_items(parent,value_variant,item)
                            
                            await node.add_method(
                                self.node.idx,
                                f"WriteItem_{item.replace('/', '_')}",
                                write_item_wrapper,
                                [ua.VariantType.Variant],  # 输入值为任意类型
                                [ua.VariantType.Boolean]  # 返回布尔值表示成功与否
                            )


                        
                        # 更新节点值
                        node = self.node.nodes[item]
                       
                        node_type = await node.read_data_type()
                      
                        if node_type == ua.NodeId(11, 0):  # Double
                            variant_value = float(value)
                        elif node_type == ua.NodeId(12, 0):  # String
                            variant_value = str(value)
                        elif node_type == ua.NodeId(6, 0):  # Int32
                            variant_value = int(value)
                        elif node_type == ua.NodeId(1, 0):  # Boolean
                            variant_value = bool(value)
                        else:
                            logging.warning(f"_OPCDAWrapper_.add_items: Unsupported node type for {item}")
                            continue
                        
                        try:
                            variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                            await node.write_value(ua.DataValue(variant, status, source_timestamp))
                            self.opcdastack.update_count += 1
                            last_values[item] = value
                            if self.opcdastack.max_updates and self.opcdastack.update_count >= self.opcdastack.max_updates:
                                logging.debug(f"_OPCDAWrapper_.add_items: Reached max updates ({self.opcdastack.max_updates}), stopping subscription...")
                                self.event.shutdown.set()
                        except ua.UaStatusCodeError as e:
                            logging.error(f"Failed to write {item}: {str(e)}")
                            await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_items: Failed to write {item}, Error Occured: {str(e)}")
                    else:
                         logging.warning(f"_OPCDAWrapper_.add_items: iem {item}: not in last values ot it's value doesn't change")
                else:
                     logging.warning(f"_OPCDAWrapper_.add_items: iiem {item}: is not valid in opc data server,check your item path")
    async def update_ua_nodes(self):
            """Update OPC UA nodes with values from OPC DA items"""
            
            while not  self.event.shutdown.is_set():
                for item in List(self.node.nodes.keys()):

                    data = self.callback.get_data(item)              
                    if data and data[1] != 0:  # 检查数据有效性
                        value, quality, timestamp = data
                        status = ua.StatusCode(ua.StatusCodes.Good) if quality == 192 else ua.StatusCode(ua.StatusCodes.Bad)                   
                        # 处理时间戳
                        if isinstance(timestamp, str):
                            try:
                                source_timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                            except ValueError as e:
                                logging.warning(f"_OPCDAWrapper_.update_ua_nodes: Invalid timestamp format for {item}: {timestamp}, using current time. Error: {e}")
                                source_timestamp = datetime.datetime.now(datetime.UTC)
                        elif isinstance(timestamp, datetime.datetime):
                            source_timestamp = timestamp
                        else:
                            logging.warning(f"_OPCDAWrapper_.update_ua_nodes: Unsupported timestamp type for {item}: {type(timestamp)}, using current time")
                            source_timestamp = datetime.datetime.now(datetime.UTC)
                
                    # 更新节点值
                    node = self.node.nodes[item]
                    node_type = await node.read_data_type()             
                    if node_type == ua.NodeId(11, 0):  # Double
                        variant_value = float(value)
                    elif node_type == ua.NodeId(12, 0):  # String
                        variant_value = str(value)
                    elif node_type == ua.NodeId(6, 0):  # Int32
                        variant_value = int(value)
                    elif node_type == ua.NodeId(1, 0):  # Boolean
                        variant_value = bool(value)
                    else:
                        logging.warning(f"_OPCDAWrapper_.update_ua_nodes: Unsupported node type for {item}")
                        continue
                    
                    try:
                        variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                        await node.write_value(ua.DataValue(variant, status, source_timestamp))
                                         
                    except ua.UaStatusCodeError as e:
                        logging.error(f"Failed to write {item}: {str(e)}")
                        await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.update_ua_nodes: Failed to write {item}, Error Occured: {str(e)}")            
    async def update_item(self, parent, path_variant,level_variant):
                """OPC UA 方法：对指定 item path 执行 add 操作"""
                userrole = await self._get_current_userrole()
          
                if not self.user_manager.check_method_permission(50, userrole):
                    logging.warning(f"_OPCDAWrapper_.update_node_call:Unauthorized attempt to call update_node_call ")
                    await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.update_node_call:Unauthorized attempt to call generate_server_certificate ")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
                try:
                    path = path_variant.Value
                    if not isinstance(path, str):
                            await self.node.last_error_desc.write_value("_OPCDAWrapper_.update_node_call: Invalid input - path must be a string")
                            raise ValueError("Path must be a string")
                    path = path.upper() 
                    path_parts = path.split('.')
                    print(path_parts)
                        # 检查是否有空字符串、'/' 或长度小于4
                    special_chars = {'/', '$', '!', '%', '#', '@', '~', '\\', '`', '(', '{', '[','+','=','^','&','*',')','}',']',',','?','|'}
                    if any(part == '' or any(char in part for char in special_chars) for part in path_parts) or len(path_parts) < 4:
                        await self.node.last_error_desc.write_value("_OPCDAWrapper_.update_node_call: Invalid input - path must not contain empty parts or '/' and must have at least 4 segments")
                        raise ValueError("Invalid path format: must not contain empty parts or '/' and must have at least 4 segments")
              
                    # 检查 level_variant
                    level = level_variant.Value
                    if not isinstance(level, int):
                        await self.node.last_error_desc.write_value("_OPCDAWrapper_.update_node_call: Invalid input - level must be an integer")
                        raise ValueError("Level must be an integer")
                    if level < 2:
                        await self.node.last_error_desc.write_value("_OPCDAWrapper_.update_node_call: Invalid input - level must be >= 2")
                        raise ValueError("Level must be >= 2")
                    logging.debug(f"_OPCDAWrapper_.update_node_call: Client requested update for path={path} and level={level}")
                    item = await self.update_node(path,level)
                    return [ua.Variant(item, ua.VariantType.String)] 
                except ValueError as e:
                    logging.error(f"_OPCDAWrapper_.update_node_call: Input validation failed: {str(e)}")
                    await self.node.last_error_code.write_value(ua.StatusCodes.BadInvalidArgument)
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)   
                except Exception as e:
                        logging.error(f"_OPCDAWrapper_.update_node_call:Failed to update_node_call: {str(e)}")
                        if self.node.last_error_desc is not None: 
                            await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.update_node_call:Failed to call update_node ,Error Occured: {str(e)}")
                        raise           
    async def poll_item(self, parent, item: str) -> list:
        """OPC UA 方法：对指定 item 执行 async_poll 操作"""
        userrole = await self._get_current_userrole()
        if not self.user_manager.check_method_permission(50, userrole):  # 与 update_item 相同的权限级别
            logging.warning(f"_OPCDAWrapper_.poll_item: Unauthorized attempt to poll item {item}")
            await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.poll_item: Unauthorized attempt to poll item {item}")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
        
        try:
            await self.async_poll([item], interval=1.0, max_time=2.0)  # 默认参数，可根据需要调整
            logging.info(f"_OPCDAWrapper_.poll_item: Successfully polled item {item}")
            return [ua.Variant(True, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.poll_item: Failed to poll item {item}: {str(e)}")
            await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.poll_item: Failed to poll item {item}, Error Occurred: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
     
    async def create_structure(self,parent_node,structure: Dict = None, base_path: str = None):
            """Recursively create folder structure in OPC UA based on OPC DA structure."""
            start_time = time.time()
            logging.debug(f"_OPCDAWrapper_.create_structure: Starting structure creation for base_path={base_path}")
            structure = structure if structure is not None else self.opcdastack.structure
            base_path = base_path if base_path is not None else self.opcdastack.path
            logging.debug(f"_OPCDAWrapper_.create_structure:Creating folder structure under {parent_node} with base_path={base_path}, structure={structure}")
            node =parent_node
            for key, value in structure.items():
                
                path = f"{base_path}.{key}" if base_path else key                                 
                #folder = await node.add_folder(self.node.idx, key)
                folder = await self.create_folder(path)
           
                
             
               
                if isinstance(value, dict):
                    await self.create_structure(folder,value, path)
                elif value is not None:
                    # value 是 OPC DA item 路径，记录但不立即更新
                    logging.debug(f"_OPCDAWrapper_.create_structure: Found item path {value}, awaiting client call to update")
                    # 添加方法到 folder，客户端可调用
                    method_name = f"UpdateItem_{key}"
                    # 检查当前节点下是否已存在同名方法
                    method_exists = False
                    try:
                        # 尝试获取特定子节点
                        await folder.get_child(f"{self.node.idx}:{method_name}")
                        method_exists = True
                        logging.debug(f"_OPCDAWrapper_.create_structure: Method '{method_name}' already exists under folder {path}, skipping creation")
                    except ua.UaStatusCodeError as e:
                        # 如果子节点不存在，会抛出 BadNodeIdUnknown 异常
                        if e.code == ua.StatusCodes.BadNodeIdUnknown:
                            logging.debug(f"_OPCDAWrapper_.create_structure: Method '{method_name}' does not exist, will create it")
                        else:
                            logging.warning(f"_OPCDAWrapper_.create_structure: Error checking method '{method_name}' for {path}: {str(e)}")
                    # 如果方法不存在，则创建
                    if not method_exists:
                            async def update_node_wrapper(parent,level:int=3,key=key,value=value):
                                logging.debug(f"_OPCDAWrapper_.create_structure: Client called UpdateNode_{key} with preset value={value}")
                                return await self.update_item(parent, ua.Variant(value, ua.VariantType.String),ua.Variant(level, ua.VariantType.Int32))
                            
                            # 添加方法到 folder，客户端调用时无需参数

                            await folder.add_method(
                                self.node.idx, 
                                method_name, 
                                update_node_wrapper, 
                                [ua.VariantType.Int32],  
                                [ua.VariantType.String]  # 返回值类型
                            )
            logging.debug(f"_OPCDAWrapper_.create_structure: Structure creation completed in {time.time() - start_time:.2f} seconds")              
    async def create_folder(self,base_path: str):
            """Recursively create folder structure in OPC UA based on OPC DA structure."""
            node=self.node.da_folder
            
            paths=base_path.split('.')
            
            for i in range(len(paths)):
                path=".".join(paths[:i+1])
                if path not in self.node.folders:
                    node = await node.add_folder(self.node.idx, paths[i])
                    self.node.folders[path]=node
                    # 定义一个无需输入参数的包装方法，直接使用 path 作为 base_path
                    async def browse_folder_wrapper(parent,path=path):
                        logging.debug(f"_OPCDAWrapper_.create_folder: Client called broswer_{path} with preset base_path={path}")
                        await self.broswe_folder(max_level=1, base_path=path)
                        return [ua.Variant(f"Browsed {path}", ua.VariantType.String)]
                    
                    # 添加方法到 folder，客户端调用时无需参数
                    await node.add_method(
                        self.node.idx,
                        f"broswer_{path}",
                        browse_folder_wrapper,
                        [],  # 输入参数为空
                        [ua.VariantType.String]  # 返回值类型
                    )
                    logging.debug(f"_OPCDAWrapper_.create_folder:node create for base_path={base_path}, node={node}")    
                else:
                    node = self.node.folders[path]
                    logging.debug(f"_OPCDAWrapper_.create_folder:node already existed for base_path={base_path}, node={node}")    
                     
            return  node
    async def broswe_folder(self,max_level:int=1,base_path: str= ""):
             start_time = time.time()
             logging.debug(f"_OPCDAWrapper_.broswe_folder: Starting browse for base_path={base_path}")
             async with self.opcdastack.path_lock:  # 使用锁确保顺序执行
                logging.debug(f"_OPCDAWrapper_.broswe_folder:browse sub structure and create sub node for base_path={base_path}") 
                self.opcdastack.path=base_path
                self.opcdastack.max_level=max_level
                            
                self.event.broswe_opcda_struture.set()
                await asyncio.sleep(1)
                if not self.event.update_structure.is_set():
                # 等待事件被 clear（需要其他协程调用 .clear()）
                    await self.event.update_structure.wait()  # 阻塞直到事件被 clear
              
                logging.debug(f"_OPCDAWrapper_.broswe_folder:structure ={self.opcdastack.structure}") 
                parent_node = self.node.da_folder if base_path == "" else self.node.folders.get(base_path)
                if not parent_node and base_path:
                    parent_node = await self.create_folder(base_path)
                await self.create_structure(parent_node,self.opcdastack.structure,base_path)
                self.event.update_structure.clear()
                logging.debug(f"_OPCDAWrapper_.broswe_folder: Browse completed in {time.time() - start_time:.2f} seconds")
    async def update_node(self,path: str,level:int=3):                         
                parts = path.split('.')
                if len(parts) > level:
                    folder = '.'.join(parts[:level])  # 前 level 项是 folder
                    item_parts = parts[level:]        # 剩下的部分是 item
                    item = '/'.join(item_parts[:-1]) + '.' + item_parts[-1] if len(item_parts) > 1 else item_parts[0]
                else:
                    folder = parts[0]
                    item = '/'.join(parts[1:-1]) + '.' + parts[-1] if len(parts) > 1 else parts[-1]
                
                logging.debug(f"_OPCDAWrapper_.update_node: Try to create item {item} node under {folder}")
                await self.add_items([item], folder)
                return item
    async def write_items(self,parent, values_variant, items_variant):
            userrole = await self._get_current_userrole()
            if not self.user_manager.check_method_permission(13, userrole):
                logging.warning(f"_OPCDAWrapper_.write_items:Unauthorized attempt to call write_items ")
                await self.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.write_items:Unauthorized attempt to call write_items ")
                return [ua.Variant(False, ua.VariantType.Boolean), ua.Variant("BadUserAccessDenied", ua.VariantType.String)]
            logging.debug(f"_OPCDAWrapper_.write_items: called with items_variant: {items_variant}, values_variant: {values_variant}")
            try:
                if isinstance(items_variant, str):
                    items = [items_variant]
                    values = [values_variant.Value]
                elif not isinstance(items_variant.Value, list) or not isinstance(values_variant.Value, list):
                    logging.error(f"_OPCDAWrapper_.write_items: Invalid input types: items={type(items_variant.Value)}, values={type(values_variant.Value)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]
                  
                else:
                    items = items_variant.Value
                    values = [val.Value for val in values_variant.Value]
                await self.async_poll(items, interval=1.0, max_time=2.0)
                for i in range(len(items)):
                       
                       current_data = self.callback.get_data(items[i])
                       if current_data and current_data[1] != 0:  # 数据有效
                            current_value, quality, timestamp = current_data
                            expected_type = type(current_value)
                        
                       else:
                           
                            expected_type = None 
                       # 类型转换
                       if expected_type:
                            try:
                                if expected_type == float and not isinstance(values[i], (int, float)):
                                    values[i] = float(values[i])
                                    logging.debug(f"_OPCDAWrapper_.write_item: Converted {values[i]} to float")
                                elif expected_type == int and not isinstance(values[i], int):
                                    values[i] = int(values[i])
                                    logging.debug(f"_OPCDAWrapper_.write_item: Converted {values[i]} to int")
                                elif expected_type == bool and not isinstance(values[i], bool):
                                    values[i] = bool(values[i])
                                    logging.debug(f"_OPCDAWrapper_.write_item: Converted {values[i]} to bool")
                                elif expected_type == str and not isinstance(values[i], str):
                                    values[i] = str(values[i])
                                    logging.debug(f"_OPCDAWrapper_.write_item: Converted {values[i]} to str")
                            except (ValueError, TypeError) as e:
                               
                                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.write_item: Type mismatch for {items[i]}, expected {expected_type}, got {type(values[i])}")
                                return [ua.Variant(False, ua.VariantType.Boolean)]

                results = await self.async_write(values,items)
                for item, value, success in zip(items, values, results):
                    if not success:
                        continue
                    #ua_name = item.replace('/', '_')
                    ua_name = item
                    if item not in self.node.nodes:
                        if isinstance(value, int):
                            variant_type = ua.VariantType.Int64
                        elif isinstance(value, float):
                            variant_type = ua.VariantType.Double
                        elif isinstance(value, str):
                            variant_type = ua.VariantType.String
                        elif isinstance(value, bool):
                                variant_type = ua.VariantType.Boolean
                               
                        else:
                            variant_type = ua.VariantType.Variant
                        node = await self.node.da_folder.add_variable(self.node.idx, ua_name, value, varianttype=variant_type)
                        self.node.nodes[item] = node
                    else:
                        node = self.node.nodes[item]
                        data_value = await node.read_data_value()
                        current_type = data_value.Value.VariantType
                        try:
                            if current_type == ua.VariantType.Double and isinstance(value, int):
                                value = float(value)
                            elif current_type == ua.VariantType.Int64 and isinstance(value, float):
                                value = int(value)
                            await node.write_value(value)
                        except ua.UaStatusCodeError as e:
                            logging.warning(f"_OPCDAWrapper_.write_items:Failed to update UA node {item}: {e}")
                #return [ua.Variant(results, ua.VariantType.Boolean)]
                return [ua.Variant(all(results), ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.write_items:Error in write_items: {str(e)}")
                await self.node.last_error_desc.write_value(f"_OPCDAWrapper_.write_items:Error in write_items,Error Occured: {str(e)}")
                raise

    def opc_da_thread(self, items:List[str]):

        pythoncom.CoInitialize()
        try:
            
            if not self.opc_da.connected:
                self.opc_da.connect()



            self.opc_da.subscribe(items, group_name=self.opcdastack.group_name, update_rate=self.opcdastack.update_rate, callback=self.custom_callback)
            logging.debug(f"_OPCDAWrapper_.opc_da_thread:Subscription started for group {self.opcdastack.group_name}")
            while not self.event.shutdown.is_set():

                if  self.event.broswe_opcda_struture.is_set():      
                        
                        self.opcdastack.structure={}
                        if self.opcdastack.path !="":
                            move_to_path = self.opc_da.move_to_path(self.opc_da.browser, self.opcdastack.path)
                        else:
                            move_to_path =True
                        if move_to_path:  
                            self.opcdastack.structure = self.opc_da.browse_level(
                            self.opc_da.browser, 1, self.opcdastack.max_level, self.opcdastack.path, self.opcdastack.structure
                            )
                        logging.debug(f"opc_da_thread: Browse structure completed: {self.opcdastack.structure}")
                        self.event.update_structure.set()
                        self.event.broswe_opcda_struture.clear()
                        
                try:
                    poll_data = self.opcdastack.poll_queue.get_nowait()
                    items_to_poll, interval, max_count, max_time = poll_data
                    logging.info(f"_OPCDAWrapper_.opc_da_thread:Starting poll for {items_to_poll} every {interval} seconds")
                    start_time = time.time()
                    count = 0
                    while self.event.polling.is_set() and not self.event.shutdown.is_set() and (max_count is None or count < max_count) and (max_time is None or time.time() - start_time < max_time):
                        try:
                            results = self.opc_da.read(items_to_poll)
                            self.custom_callback(items_to_poll, results)
                        except Exception as e:
                            logging.error(f"_OPCDAWrapper_.opc_da_thread:Poll read error: {str(e)}")
                        count += 1
                        time.sleep(interval)
                    logging.info("_OPCDAWrapper_.opc_da_thread:Polling completed")
                    self.event.polling.clear()
                except Empty:
                    pass

                try:
                    write_data = self.opcdastack.write_queue.get_nowait()
                    items_to_write, values, write_group_name, write_update_rate, future = write_data
                    logging.debug(f"_OPCDAWrapper_.opc_da_thread:Starting write operation for {items_to_write}")
                    start_time = time.time()
                    while self.event.writing.is_set() and not self.event.shutdown.is_set() and (time.time() - start_time < 10):
                        try:
                            results = self.opc_da.write(items_to_write, values, write_group_name, write_update_rate)
                            if all(results):
                                logging.debug(f"_OPCDAWrapper_.opc_da_thread:Successfully wrote {values} to {items_to_write}")
                            else:
                                failed_items = [item for item, success in zip(items_to_write, results) if not success]
                                logging.warning(f"_OPCDAWrapper_.opc_da_thread:Partially succeeded: Failed to write to {failed_items}")
                            #logging.debug(f"Write results for {items_to_write}: {results}")
                            future.set_result(results)
                            break
                        except Exception as e:
                            logging.error(f"_OPCDAWrapper_.opc_da_thread:Write error in opc_da_thread: {str(e)}")
                            future.set_exception(e)
                            break
                    if  self.event.writing.is_set() and time.time() - start_time >= 10:
                        logging.error(f"_OPCDAWrapper_.opc_da_thread:Write to {items_to_write} timed out after 10 seconds")
                        future.set_exception(asyncio.TimeoutError("Write operation timed out"))
                    self.event.writing .clear()
                except Empty:
                    pass

                pythoncom.PumpWaitingMessages()
                time.sleep(0.01)
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.opc_da_thread:OPC DA thread error: {str(e)}")
            
        finally:
            try:
                if self.opcdastack.group_name and self.opc_da.connected:
                    self.opc_da.stop_subscribe(self.opcdastack.group_name)
                    logging.debug(f"_OPCDAWrapper_.opc_da_thread:Subscription {self.opcdastack.group_name} stopped")
                if self.opc_da.connected:
                    self.opc_da.disconnect()
                    logging.debug("_OPCDAWrapper_.opc_da_thread:Disconnected from OPC server")
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.opc_da_thread:Cleanup error in thread: {str(e)}")
               
            finally:
                pythoncom.CoUninitialize()
                logging.info("_OPCDAWrapper_.opc_da_thread:OPC DA thread exiting")

    async def async_poll(self, items: List[str], interval: float = 1.0, max_count: Optional[int] = None, max_time: Optional[float] = None):
        if self.event.polling.is_set():
            logging.warning("_OPCDAWrapper_.async_poll:Polling already in progress")
            return
        self.event.polling.set()
        self.opcdastack.poll_queue.put((items, interval, max_count, max_time))
        try:
            await asyncio.wait_for(self._wait_for_polling(), timeout=max_time or 120)
        except asyncio.TimeoutError:
            logging.warning(f"_OPCDAWrapper_.async_poll:Polling for {items} timed out ")
           
            self.event.polling.clear()
        logging.debug(f"_OPCDAWrapper_.async_poll:Poll task for {items} exited at {time.strftime('%H:%M:%S')}")
    async def _wait_for_polling(self):
        while self.event.polling.is_set() and not self.event.shutdown.is_set():
            await asyncio.sleep(0.1)
        return True
    async def async_write(self,  values: List[any], items: List[str],group_name: str = "WriteGroup", update_rate: int = 1000):
        #logging.info(f"Attempting to write {values} to {items}")
        if not self.event.running.is_set():
            logging.error("_OPCDAWrapper_.async_write:Cannot write: OPC DA wrapper is not running")
            return [False] * len(items)
        if not self.opc_da.connected:
            logging.error("_OPCDAWrapper_.async_write:Cannot write: OPC DA server is not connected")
            return None
        if len(items) != len(values):
            logging.error("_OPCDAWrapper_.async_write:Cannot write: Number of items and values must match")
            return None
        async with self.opcdastack.write_lock:  # 使用锁确保顺序执行
            if self.event.writing.is_set():
                logging.warning("_OPCDAWrapper_.async_write:Write operation already in progress, waiting for lock release")

                # 这里可以选择等待而不是直接返回 None，因为锁会确保顺序执行

        future = asyncio.Future()
        self.event.writing.set()
        self.opcdastack.write_queue.put((items, values, group_name, update_rate, future))
        try:
            results = await asyncio.wait_for(future, timeout=90)
            #logging.debug(f"Write task for {items} completed at {time.strftime('%H:%M:%S')}")
            return results
        except asyncio.TimeoutError:
            logging.error(f"_OPCDAWrapper_.async_write:Write to {items} timed out")
            self.event.writing.clear()
            return None
        finally:
            self.event.writing.clear()

    def custom_callback(self, paths: List[str], results: List[Tuple[any, int, str]]):
        for path, (value, quality, timestamp) in zip(paths, results):
            if quality == 192:
                self.callback.data[path] = (value, quality, timestamp)
                print(f"_OPCDAWrapper_.custom_callback:Poll/Subscribe: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
                logging.debug(f"_OPCDAWrapper_.custom_callback: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
    
    async def start(self, items: List[str], max_updates: Optional[int] = None):
            self.event.running.set()
            self.opcdastack.max_updates = max_updates
            self.event.shutdown.clear()

            await self.setup_opc_ua_server()
                           
            loop = asyncio.get_running_loop()
            opc_da_task = loop.run_in_executor(self.executor, self.opc_da_thread, items)
          
        
            async with self.server:
                try:
                    self.server.set_security_policy(self.cert.security_policies)
                    logging.debug(f"_OPCDAWrapper_.start: Security policies set: {[policy.URI for policy in self.cert.security_policies]}")
                    
                    logging.debug("Performing initial OPC DA browse the top 2 level strture...")
                    await self.broswe_folder(max_level=2)
                   
                    logging.debug("Performing initial poll from opc da server fro 5 seconds...")
                    await self.async_poll(items, interval=1.0, max_time=5.0)

                             
                    
                    
                    # 持续运行的监控任务
                    monitor_task = asyncio.create_task(self.user_manager.monitor_anonymous_sessions(self.server.iserver))
                    logging.debug("_OPCDAWrapper_.start: Monitor anonymous sessions task started")

                    logging.debug("Wait 30 seconds for update_ua_nodes task...")
                    await asyncio.sleep(30)
                    # 启动周期性更新任务
                    update_task = asyncio.create_task(self.update_ua_nodes())
                    logging.debug("_OPCDAWrapper_.start: Periodic update task started")

                    # 主循环，监听事件并支持动态调用
                    while not self.event.shutdown.is_set():
                        if self.event.restart.is_set():
                            logging.debug("_OPCDAWrapper_.start: Restart event detected, shutting down...")
                            self.event.shutdown.set()
                            monitor_task.cancel()
                            update_task.cancel()
                            break
                        await asyncio.sleep(0.5)  # 短暂休眠，避免 CPU 占用过高

                    # 等待任务完成
                    await asyncio.gather(opc_da_task, monitor_task, update_task, return_exceptions=True)
                
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_.start: Error occurred: {str(e)}")
                finally:
                    self.event.running.clear()
                    self.event.shutdown.set()
                    monitor_task.cancel()
                    update_task.cancel()
                    await asyncio.gather(opc_da_task, monitor_task, return_exceptions=True)
                    logging.debug(f"_OPCDAWrapper_.start: Start task completed at {time.strftime('%H:%M:%S')}")
                    await asyncio.sleep(3)

async def main(max_time: Optional[float] = None, max_count: Optional[int] = None, manual_stop: bool = False):
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
    opc_da = _OPCDA_()
    
    
    try:
        wrapper = _OPCDAWrapper_(opc_da)
       
      
        # 启动服务

        subscription_task = asyncio.create_task(wrapper.start(items, max_updates=max_count))
        
        # 初始添加节点
        await asyncio.sleep(15)
        print(f"_OPCDAWrapper_.main: add  {items} ")
        await wrapper.add_items(items1, "MODULES.AREA_V1")
        await asyncio.sleep(10)
        await wrapper.add_items(items2, "DIAGNOSTICS")
        await asyncio.sleep(5)
        # 示例：动态调用 update_node
        new_item = await wrapper.update_node("MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE.EU100")
        print(f"_OPCDAWrapper_.main: Added new item: {new_item}")
        await asyncio.sleep(10)
        
        # 示例：动态调用 broswe_folder
        await wrapper.broswe_folder(base_path="MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
        print("_OPCDAWrapper_.main: Browsed and updated structure under MODULES.AREA_V1.V1-EM.V1-AIC-DO.FS_CTRL1.IN_SCALE")
        
        # 等待手动停止或超时
        if manual_stop:
            await asyncio.sleep(30)
            if not wrapper.event.shutdown.is_set():
                await wrapper.stop()
        elif max_time:
            await asyncio.wait([subscription_task], timeout=max_time)
        else:
            await subscription_task
    
    except Exception as e:
        logging.error(f"_OPCDAWrapper_.main: Error: {str(e)}")
    finally:
        await wrapper.stop(restore_init_cert=True)
        if not subscription_task.done():
            subscription_task.cancel()
            await subscription_task
        print("_OPCDAWrapper_.main: Shutdown complete")

if __name__ == "__main__":
    logging.basicConfig(
        filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'opcuuaserver.log'),
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger('asyncua').setLevel(logging.WARNING)
    asyncio.run(main(max_time=6000, max_count=1099, manual_stop=False))