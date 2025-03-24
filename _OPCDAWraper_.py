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
        # 将 connected_clients 改为字典，包含总数和会话详情
        self.connected_clients = {
            "count": 0,
            "sessions": {}
        }
        self.anonymous_sessions = {}  # (client_addr, start_time) pairs
        self.recently_closed = {}    # (client_addr, close_time)
        self.timeout = 120            # 会话超时时间（秒）
        self.cooldown = 180           # 重连冷却时间（秒）
        self.user_roles = {
            "deltavadmin": 0,
            "EMERSON": 1,
            "FINESSE": 1,
            "CONFIGURE": 2,
            "SUPERVISE": 3,
            "OPERATE": 4,
            "certificate": 5,
            "default": 9,
            "anonymous": 10
        }
        self.user_passwords = {
            "deltavadmin": "Fin3ss3!",
            "EMERSON": "DeltaVE1",
            "FINESSE": "TruBioDV01",
            "CONFIGURE": "DeltaVC1",
            "SUPERVISE": "DeltaVS1",
            "OPERATE": "DeltaVSO",
            "anonymous": "123456789",
            "default": "password"
        }
    
    def _hash_password(self,username: str, password: str, nonce: str) -> str:
       
        return hashlib.sha256((password + username + nonce).encode('utf-8')).hexdigest()
    
    def get_user(self, iserver, username=None, password=None, certificate=None):
      
        # 尝试从 iserver 或其 session 中获取客户端地址
        client_addr = ('unknown', 0)
        if hasattr(iserver, 'asyncio_transports') and iserver.asyncio_transports:
            transport = iserver.asyncio_transports[-1]  # Get the most recent transport
        if hasattr(transport, 'get_extra_info'):
            client_addr = transport.get_extra_info('peername') or client_addr
        elif hasattr(transport, 'peername'):
            client_addr = transport.peername
        logging.debug(f"CustomUserManager: User check called: addr={client_addr[0]} at port {client_addr[1]}, username={username}, password={password}, cert={certificate is not None}")
        
        client_paassowrd, nonce = password.split(":")
        server_password=self._hash_password(username,self.user_passwords[username] ,nonce)
        # 获取会话详细信息
        session_id = iserver.isession.session_id.to_string()
        client_ip = client_addr[0]
        client_hostname = "unknown"
        try:
            client_hostname = socket.gethostbyaddr(client_ip)[0]
            logging.info(f"CustomUserManager: Resolved hostname for {client_ip}: {client_hostname}")
        except (socket.herror, socket.gaierror) as e:
            logging.debug(f"CustomUserManager: Failed to resolve hostname for {client_ip}: {str(e)}")

        app_name = "unknown"
        if hasattr(iserver.isession, 'application_description'):
            app_name = iserver.isession.application_description.ApplicationName.Text
            logging.info(f"CustomUserManager: ApplicationName: {app_name}")
       
        logging.info(f"CustomUserManager: isession.session_id: {session_id}")
        # 认证逻辑
        userrole = 100
        if certificate is not None and username == "deltavadmin" and client_paassowrd ==server_password:
            userrole = 0
           
        elif certificate is not None and (username == "EMERSON" or username ==  "FINESSE")   and client_paassowrd ==server_password:
            userrole = 1
        elif certificate is not None and (username == "CONFIGURE" )  and (client_paassowrd ==server_password):
            userrole = 2
        elif certificate is not None and (username == "SUPERVISE" )  and (client_paassowrd ==server_password):
            userrole = 3
          
        elif certificate is not None and (username == "OPERATE" )  and (client_paassowrd ==server_password):
            userrole = 4
        elif certificate is not None or ( client_paassowrd ==server_password) :
            userrole = 5
        elif (username == "deltavadmin" )  and  (client_paassowrd == self.user_passwords[username]):
            userrole = 6
        elif (username == "EMERSON" or username ==  "FINESSE")  and  (client_paassowrd == self.user_passwords[username]):
            userrole = 7
        elif (username == "CONFIGURE" )  and  (client_paassowrd == self.user_passwords[username]):
            userrole = 8
        elif (username == "SUPERVISE" )  and  (client_paassowrd == self.user_passwords[username]):
            userrole = 9
        elif (username == "OPERATE" )  and  (client_paassowrd == self.user_passwords[username]):
            userrole = 10
        elif username == "default" and (client_paassowrd == self.user_passwords[username]):
            userrole = 11
          
        else:  # 匿名用户
           
            current_time = time.time()
            if client_ip in self.recently_closed:
                time_since_closed = current_time - self.recently_closed[client_ip]
                if time_since_closed < self.cooldown:
                    logging.warning(f"CustomUserManager: Rejecting {client_addr} due to cooldown: {time_since_closed:.2f}s < {self.cooldown}s")
                    return None
                self.recently_closed = {ip: t for ip, t in self.recently_closed.items() if current_time - t < self.cooldown}
            userrole = 12
            if client_addr not in self.anonymous_sessions:
                self.anonymous_sessions[client_addr] = current_time
                logging.info(f"CustomUserManager: New anonymous session for {client_addr}")
               
            # 如果认证成功，记录会话信息
        if userrole <100:
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
                logging.info(f"CustomUserManager: Session added: {json.dumps(self.connected_clients['sessions'][session_id], indent=2)}")
                if userrole < 12:
                    if client_addr in self.anonymous_sessions:
                        del self.anonymous_sessions[client_addr]
                    if client_addr[0] in self.recently_closed:
                        del self.recently_closed[client_addr[0]]
        if userrole < 3:
         return User(UserRole.Admin)
        elif userrole < 12:
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
                logging.info("CustomUserManager: Starting anonymous session monitor")
                while True:
                    try:
                        current_time = time.time()
                        transports = {t.get_extra_info('peername'): t for t in iserver.asyncio_transports} if hasattr(iserver, 'asyncio_transports') else {}
                        if transports.keys() != {}:
                           logging.debug(f"CustomUserManager: Active transports: {transports.keys()}")

                        # 处理匿名会话
                        if self.anonymous_sessions:
                            logging.debug(f"CustomUserManager: Checking anonymous sessions: {self.anonymous_sessions}")
                            expired_sessions = [
                                addr for addr, start_time in self.anonymous_sessions.items()
                                if current_time - start_time > self.timeout
                            ]
                            for addr in expired_sessions:
                                logging.info(f"CustomUserManager: Found expired session {addr}, duration: {current_time - self.anonymous_sessions[addr]:.2f}s")
                                if addr in transports:
                                    await self._close_session(iserver, addr)
                                else:
                                    logging.info(f"CustomUserManager: Anonymous session {addr} already disconnected, cleaning up")
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
                                    logging.info(f"CustomUserManager: Removed disconnected session {session_id}, updated count: {self.connected_clients['count']}")
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
                    logging.info(f"CustomUserManager: Transport closed for {client_addr}")
                else:
                    logging.info(f"CustomUserManager: No active transport found for {client_addr}, assuming already closed")
                del self.anonymous_sessions[client_addr]
                self.recently_closed[client_addr[0]] = time.time()
                # 清理 connected_clients
                for session_id, session in list(self.connected_clients["sessions"].items()):
                    if session["client_addr"] == client_addr:
                        self.connected_clients["count"] -= 1
                        del self.connected_clients["sessions"][session_id]
                        logging.info(f"CustomUserManager: Removed session {session_id} from connected_clients due to timeout")
    
    async def query_connected_clients(self):
            return json.dumps(self.connected_clients)

        
    
class _OPCDAWrapper_:
    def __init__(self, opc_da: '_OPCDA_', endpoint: str = "opc.tcp://0.0.0.0:4840"):
        self.opc_da = opc_da
        self.callback = OPCDADataCallback(self.custom_callback)
        self.endpoint = endpoint
        self.user_manager = CustomUserManager()  # 强制初始化，避免 None
        self.server = Server(user_manager=self.user_manager)
        self.server.set_server_name('DeltaV OPC UA SERVER')
        
        logging.info(f"_OPCDAWrapper_.iniy: Server type: {type(self.server)}, iserver type: {type(self.server.iserver)},user_manager set to Custom user manager ")
        
       
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
       
        self.nodes: Dict[str, ua.Node] = {}
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.running = False
        self.group_name = None
        self.polling = False
        self.writing = False
        self.write_lock = asyncio.Lock()  # 添加异步锁，用于序列化写操作
        self.poll_queue = Queue()
        self.write_queue = Queue()
        self.shutdown_event = asyncio.Event()
        self.da_folder = None
        self.idx = None
        self.update_count = 0
        self.max_updates = None
        self.cert_node = None
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.cert_dir = os.path.join(self.base_dir, "cert")
        self.initial_cert_path = os.path.join(self.cert_dir, "server_init_cert.pem")
        self.initial_key_path = os.path.join(self.cert_dir, "server_init_key.pem")
        self.trustedcert_dir=os.path.join(self.cert_dir, "trusted")
        self.restart_event = asyncio.Event()  # 新增事件
       
        self.application_uri = "urn:opcda:wrapper"
        #self.server.set_application_uri(self.application_uri)
       
    
        self.security_policies = [
        SecurityPolicy(),
        SecurityPolicyBasic256Sha256,
        SecurityPolicyAes256Sha256RsaPss,
        SecurityPolicyAes128Sha256RsaOaep
         ]
        for policy in self.security_policies:
            if policy != SecurityPolicy():
                policy.ClientCertificateDir = self.trustedcert_dir
        
        self.last_error_code = None  # 用于存储错误状态的节点
        self.last_error_desc = None  # 用于存储错误状态的节点


   
    async def generate_self_signed_cert(self, cert_path: str, key_path: str, name: str = "MyOPCUAServer"):
        logging.info(f"_OPCDAWrapper_.generate_self_signed_cert: Generating self-signed certificate at {cert_path} and key at {key_path}")
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
                x509.UniformResourceIdentifier(self.application_uri),  # 确保与 server.set_application_uri 一致
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
            await self.last_error_desc.write_value(f"_OPCDAWrapper_.generate_self_signed_cert:Failed to generate certificate:,Error Occured: {str(e)}")
            raise
    async def restore_initial_certificate(self,parent=None):
            userrole = await self._get_current_userrole()
            if not self.user_manager.check_method_permission(5, userrole):
                logging.warning(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate by")
                await self.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            try:
                await self.server.load_certificate(self.initial_cert_path)
                await self.server.load_private_key(self.initial_key_path)
                self.server.set_security_policy(self.security_policies)
                with open(self.initial_cert_path, "rb") as f:
                    await self.cert_node.write_value(f.read())
                logging.info("_OPCDAWrapper_.restore_initial_certificate:Restored initial certificate and security policies")
                return [ua.Variant(True, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate: {str(e)}")
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate:,Error Occured: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]
            
    async def add_client_certificate(self,parent,client_cert_variant):
        """动态添加客户端证书到信任列表"""
        userrole = await self._get_current_userrole()
        if not self.user_manager.check_method_permission(11, userrole):
                logging.warning(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate")
                await self.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
        client_cert_data = client_cert_variant.Value
        
        # 解析证书以确认有效性
        try:
            cert = x509.load_pem_x509_certificate(client_cert_data)
            logging.info(f"_OPCDAWrapper_.add_client_certificate:Received client certificate: Subject={cert.subject}, Serial={cert.serial_number}")
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate: {e}")
            await self.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate,Error Occured: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]

        # 定义信任证书路径
        trust_dir = self.trustedcert_dir # 替换为你的信任目录
        if not os.path.exists(trust_dir):
            os.makedirs(trust_dir)
        
        # 将证书写入文件
        client_cert_path = os.path.join(trust_dir, f"client_cert_{cert.serial_number}.pem")
        with open(client_cert_path, "wb") as f:
            f.write(client_cert_data)
        logging.info(f"_OPCDAWrapper_.add_client_certificate:Added client certificate to {client_cert_path}")

       
        logging.info("_OPCDAWrapper_.add_client_certificate:Client certificate trusted successfully")
        return [ua.Variant(True, ua.VariantType.Boolean)]  
    async def generate_server_certificate(self, parent):
            userrole = await self._get_current_userrole()
          
            if not self.user_manager.check_method_permission(4, userrole):
                logging.warning(f"_OPCDAWrapper_.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                await self.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            
            try:
                cert_path = os.path.join(self.cert_dir, "server_cert.pem")
                key_path = os.path.join(self.cert_dir, "server_key.pem")
                await self.generate_self_signed_cert(cert_path, key_path, name="MyOPCUAServer")
                #self.restart_event.set() # 添加新变量，初始为 False
                return [ua.Variant(True, ua.VariantType.Boolean)]  # 正确返回 OPC UA Variant 列表
            
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.generate_server_certificate:Failed to generate certificate: {str(e)}")
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.generate_server_certificate:FFailed to generate certificate,Error Occured: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表

    
    async def set_server_policy(self, parent, security_policy_variant, sign_and_encrypt_variant):
            userrole = await self._get_current_userrole()
           
            if not self.user_manager.check_method_permission(4, userrole):
                logging.warning("_OPCDAWrapper_.set_server_policy:Unauthorized attempt to call set_server_policy")
                await self.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.set_server_policy:nauthorized attempt to call set_server_policy ")
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
                self.security_policies = [SecurityPolicy(), policy_class]
                for policy in self.security_policies:
                    if policy != SecurityPolicy():
                        policy.ClientCertificateDir = self.trustedcert_dir
                
                logging.info(f"_OPCDAWrapper_.set_server_policy:Updated security policy to {security_policy}:{'SignAndEncrypt' if sign_and_encrypt else 'Sign'}")
               
                self.server.set_security_policy(self.security_policies)
                logging.info(f"_OPCDAWrapper_.set_server_policy:Security policies set: {[policy.URI for policy in self.security_policies]}")
                return [ua.Variant(True, ua.VariantType.Boolean)]  # 失败时也返回列表
            
          
            
            except Exception as e:
                logging.error(f"_OPCDAWrapper_:Failed to update Security policies: {str(e)}")
                await self.last_error_desc.write_value(f"Failed to update Security policies: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表
    async def _get_current_userrole(self):
        client_addr = None
        if hasattr(self.server.iserver, 'asyncio_transports') and self.server.iserver.asyncio_transports:
            transport = self.server.iserver.asyncio_transports[-1]
            client_addr = transport.get_extra_info('peername') or ('unknown', 0)

        userrole = 100
        for session_id, session_info in self.user_manager.connected_clients["sessions"].items():
            if session_info["client_addr"] == client_addr:
                userrole = session_info["userrole"]
                
                break
        
        
        return userrole
       
    async def setup_opc_ua_server(self):
          # 设置用户管理器
        
       
       
       
        await self.server.init()
        
        
        self.server.set_server_name("OPC_UA_WRAPPER_DA")
        uri = "urn:opcda:wrapper"
        self.idx = await self.server.register_namespace(uri)
        logging.info(f"_OPCDAWrapper_.setup_opc_ua_server:Registered namespace index: {self.idx}")
        objects = self.server.nodes.objects
        self.da_folder = await objects.add_folder(self.idx, "OPCDA.1")       
        if self.server.iserver.isession:
          logging.info(f"_OPCDAWrapper_.setup_opc_ua_server:Initial isession.user after init: name={self.server.iserver.isession.user.name}, role={self.server.iserver.isession.user.role}")


        if not os.path.exists(self.initial_cert_path) or not os.path.exists(self.initial_key_path):
            logging.info("_OPCDAWrapper_.setup_opc_ua_server:init Certificate or key not found, generating new ones...")
            await self.generate_self_signed_cert(self.initial_cert_path, self.initial_key_path)
        
        
        
        self.server.set_security_IDs(["Anonymous", "Username"])  # 调整顺序，确保 Anonymous 在前
      

        self.cert_node = await self.da_folder.add_variable(
            self.idx, "ServerCertificate", b"", ua.VariantType.ByteString
        )

      
        cert_path = os.path.join(self.cert_dir, "server_cert.pem")
        key_path = os.path.join(self.cert_dir, "server_key.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            with open(cert_path, "rb") as f:
                await self.server.load_certificate(cert_path)
                await self.server.load_private_key(key_path)
                #self.server.set_security_policy(self.security_policies)
                await self.cert_node.write_value(f.read())
                logging.info("_OPCDAWrapper_.setup_opc_ua_server:Server certificate is  available at ServerCertificate node")
        else:
             with open(self.initial_cert_path, "rb") as f:
                await self.server.load_certificate(self.initial_cert_path)
                await self.server.load_private_key(self.initial_key_path)
                #self.server.set_security_policy(self.security_policies)
                await self.cert_node.write_value(f.read())
                logging.info("_OPCDAWrapper_.setup_opc_ua_server: Server certificate is not available at ServerCertificate node,use server init Certificate")
        
        
      
        self.last_error_code = await self.da_folder.add_variable(
            self.idx, "LastErrorStatus", 0, ua.VariantType.Int64
        )
        await self.last_error_code.set_writable()

        self.last_error_desc = await self.da_folder.add_variable(
            self.idx, "LastErrorDesc", "", ua.VariantType.String
        )
        await self.last_error_desc.set_writable()
        # 添加方法并设置权限
        method_nodes = {
            "write_to_opc_da": await self.da_folder.add_method(
                self.idx, "write_to_opc_da", self.write_to_opc_da,
                [ua.VariantType.String, ua.VariantType.Variant], [ua.VariantType.Boolean]
            ),
            "add_client_cert": await self.da_folder.add_method(
                self.idx, "add_client_cert", self.add_client_certificate,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            ),
            "generate_server_certificate": await self.da_folder.add_method(
                self.idx, "generate_server_certificate", self.generate_server_certificate,
                [], [ua.VariantType.Boolean]
            ),
            "set_server_policy": await self.da_folder.add_method(
                self.idx, "set_server_policy", self.set_server_policy,
                [ua.VariantType.String, ua.VariantType.Boolean], [ua.VariantType.Boolean]
            ),
            "restore_initial_certificate": await self.da_folder.add_method(
                self.idx, "restore_initial_certificate", self.restore_initial_certificate,
                [], [ua.VariantType.Boolean]
            )
        }

        # 为每个方法设置角色权限
    

       
       
    async def stop(self,restore_init_cert:bool= False):
        self.running = False
        self.polling = False
        self.writing = False
        #self.restart_event = False  # 重置标志
        self.shutdown_event.set()
        # 取消匿名会话任务
       # 清理匿名会话
        if self.user_manager and self.user_manager.anonymous_sessions:
            for client_addr in list(self.user_manager.anonymous_sessions.keys()):
                await self.user_manager._close_session(self.server.iserver,client_addr)
            self.user_manager.anonymous_sessions.clear()
            self.user_manager.recently_closed.clear()
            self.user_manager.connected_clients.clear()
            logging.info("_OPCDAWrapper_.stop:Cleared all anonymous sessions during shutdown")
        else:
            self.user_manager.connected_clients.clear()
          
            logging.warning("_OPCDAWrapper_.stop:No anonymous sessions to clear during shutdown")

    
        try:
            self.executor.shutdown(wait=True)
            logging.info("_OPCDAWrapper_.stop:Executor shutdown completed")
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.stop:Executor shutdown error: {str(e)}")
            self.executor.shutdown(wait=False)
        await asyncio.sleep(1)
        if self.user_manager.connected_clients == 0 and restore_init_cert:
            await self.restore_initial_certificate()

  
        #仅在服务器仍运行时调用 stop()
        if self.server and hasattr(self.server, 'bserver') and self.server.bserver is not None:
            await self.server.stop()
            logging.info(f"_OPCDAWrapper_.stop:Server stopped at {time.strftime('%H:%M:%S')}")
        logging.info(f"_OPCDAWrapper_.stop:Shutdown complete at {time.strftime('%H:%M:%S')}")

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
                            logging.info(f"_OPCDAWrapper_.update_ua_nodes:Added UA node for {item} with type {variant_type}, NodeId: {node_id}")

                        node = self.nodes[item]
                        node_type = await node.read_data_type()
                        if node_type == ua.NodeId(11, 0):
                            variant_value = float(value)
                        elif node_type == ua.NodeId(12, 0):
                            variant_value = str(value)
                        elif node_type == ua.NodeId(6, 0):
                            variant_value = int(value)
                        else:
                            logging.warning(f"_OPCDAWrapper_.update_ua_nodes:Unsupported node type for {item}")
                            continue

                        try:
                            variant = ua.Variant(variant_value, await node.read_data_type_as_variant_type())
                            await node.write_value(ua.DataValue(variant, status))
                            self.update_count += 1
                            last_values[item] = value
                            if self.max_updates and self.update_count >= self.max_updates:
                                logging.info(f"_OPCDAWrapper_.update_ua_nodes:Reached max updates ({self.max_updates}), stopping subscription...")
                                self.shutdown_event.set()
                        except ua.UaStatusCodeError as e:
                            logging.error(f"Failed to write {item}: {str(e)}")
                            await self.last_error_desc.write_value(f"_OPCDAWrapper_.update_ua_nodes:Failed to write {item},Error Occured: {str(e)}")
            await asyncio.sleep(1)
        logging.debug("_OPCDAWrapper_.update_ua_nodes:update_ua_nodes stopped")



    async def write_to_opc_da(self,parent, items_variant, values_variant):
            userrole = await self._get_current_userrole()
            if not self.user_manager.check_method_permission(4, userrole):
                logging.warning(f"_OPCDAWrapper_.write_to_opc_da:Unauthorized attempt to call write_to_opc_da ")
                await self.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.write_to_opc_da:Unauthorized attempt to call write_to_opc_da ")
                return [ua.Variant(False, ua.VariantType.Boolean), ua.Variant("BadUserAccessDenied", ua.VariantType.String)]
            logging.info(f"_OPCDAWrapper_.write_to_opc_da:write_to_opc_da called with items_variant: {items_variant}, values_variant: {values_variant}")
            try:
                items = items_variant.Value
                values = [val.Value for val in values_variant.Value]
                results = await self.async_write(items, values)
                for item, value, success in zip(items, values, results):
                    if not success:
                        continue
                    ua_name = item.replace('/', '_')
                    if item not in self.nodes:
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
                    else:
                        node = self.nodes[item]
                        data_value = await node.read_data_value()
                        current_type = data_value.Value.VariantType
                        try:
                            if current_type == ua.VariantType.Double and isinstance(value, int):
                                value = float(value)
                            elif current_type == ua.VariantType.Int64 and isinstance(value, float):
                                value = int(value)
                            await node.write_value(value)
                        except ua.UaStatusCodeError as e:
                            logging.warning(f"_OPCDAWrapper_.write_to_opc_da:Failed to update UA node {item}: {e}")
                return [ua.Variant(results, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.write_to_opc_da:Error in write_to_opc_da: {str(e)}")
                await self.last_error_desc.write_value(f"_OPCDAWrapper_.write_to_opc_da:Error in write_to_opc_da,Error Occured: {str(e)}")
                raise

    def opc_da_thread(self, items: List[str], group_name: str, update_rate: int):
        pythoncom.CoInitialize()
        try:
            if not self.opc_da.connected:
                self.opc_da.connect()
            self.group_name = group_name
            self.opc_da.subscribe(items, group_name=group_name, update_rate=update_rate, callback=self.custom_callback)
            logging.info(f"_OPCDAWrapper_.opc_da_thread:Subscription started for group {group_name}")

            while not self.shutdown_event.is_set():
                try:
                    poll_data = self.poll_queue.get_nowait()
                    items_to_poll, interval, max_count, max_time = poll_data
                    logging.info(f"_OPCDAWrapper_.opc_da_thread:Starting poll for {items_to_poll} every {interval} seconds")
                    start_time = time.time()
                    count = 0
                    while self.polling and not self.shutdown_event.is_set() and (max_count is None or count < max_count) and (max_time is None or time.time() - start_time < max_time):
                        try:
                            results = self.opc_da.read(items_to_poll)
                            self.custom_callback(items_to_poll, results)
                        except Exception as e:
                            logging.error(f"_OPCDAWrapper_.opc_da_thread:Poll read error: {str(e)}")
                        count += 1
                        time.sleep(interval)
                    logging.info("_OPCDAWrapper_.opc_da_thread:Polling completed")
                    self.polling = False
                except Empty:
                    pass

                try:
                    write_data = self.write_queue.get_nowait()
                    items_to_write, values, write_group_name, write_update_rate, future = write_data
                    logging.debug(f"_OPCDAWrapper_.opc_da_thread:Starting write operation for {items_to_write}")
                    start_time = time.time()
                    while self.writing and not self.shutdown_event.is_set() and (time.time() - start_time < 10):
                        try:
                            results = self.opc_da.write(items_to_write, values, write_group_name, write_update_rate)
                            if all(results):
                                logging.info(f"_OPCDAWrapper_.opc_da_thread:Successfully wrote {values} to {items_to_write}")
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
                    if self.writing and time.time() - start_time >= 10:
                        logging.error(f"_OPCDAWrapper_.opc_da_thread:Write to {items_to_write} timed out after 10 seconds")
                        future.set_exception(asyncio.TimeoutError("Write operation timed out"))
                    self.writing = False
                except Empty:
                    pass

                pythoncom.PumpWaitingMessages()
                time.sleep(0.01)
        except Exception as e:
            logging.error(f"_OPCDAWrapper_.opc_da_thread:OPC DA thread error: {str(e)}")
            self.last_error_desc.write_value(f"_OPCDAWrapper_:OPC DA thread error,Error Occured: {str(e)}")
        finally:
            try:
                if self.group_name and self.opc_da.connected:
                    self.opc_da.stop_subscribe(self.group_name)
                    logging.info(f"_OPCDAWrapper_.opc_da_thread:Subscription {self.group_name} stopped")
                if self.opc_da.connected:
                    self.opc_da.disconnect()
                    logging.info("_OPCDAWrapper_.opc_da_thread:Disconnected from OPC server")
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.opc_da_thread:Cleanup error in thread: {str(e)}")
                self.last_error_desc.write_value(f"_OPCDAWrapper_.opc_da_thread:Cleanup error in thread,Error Occured: {str(e)}")
            finally:
                pythoncom.CoUninitialize()
                logging.debug("_OPCDAWrapper_.opc_da_thread:OPC DA thread exiting")

    async def async_poll(self, items: List[str], interval: float = 1.0, max_count: Optional[int] = None, max_time: Optional[float] = None):
        if self.polling:
            logging.warning("_OPCDAWrapper_.async_poll:Polling already in progress")
            return
        self.polling = True
        self.poll_queue.put((items, interval, max_count, max_time))
        try:
            await asyncio.wait_for(self._wait_for_polling(), timeout=max_time or 120)
        except asyncio.TimeoutError:
            logging.warning(f"_OPCDAWrapper_.async_poll:Polling for {items} timed out ")
            self.polling = False
        logging.debug(f"_OPCDAWrapper_.async_poll:Poll task for {items} exited at {time.strftime('%H:%M:%S')}")

    async def _wait_for_polling(self):
        while self.polling and not self.shutdown_event.is_set():
            await asyncio.sleep(0.1)
        return True

    async def async_write(self, items: List[str], values: List[any], group_name: str = "WriteGroup", update_rate: int = 1000):
        #logging.info(f"Attempting to write {values} to {items}")
        if not self.running:
            logging.error("_OPCDAWrapper_.async_write:Cannot write: OPC DA wrapper is not running")
            return None
        if not self.opc_da.connected:
            logging.error("_OPCDAWrapper_.async_write:Cannot write: OPC DA server is not connected")
            return None
        if len(items) != len(values):
            logging.error("_OPCDAWrapper_.async_write:Cannot write: Number of items and values must match")
            return None
        async with self.write_lock:  # 使用锁确保顺序执行
            if self.writing:
                logging.warning("_OPCDAWrapper_.async_write:Write operation already in progress, waiting for lock release")

                # 这里可以选择等待而不是直接返回 None，因为锁会确保顺序执行

        future = asyncio.Future()
        self.writing = True
        self.write_queue.put((items, values, group_name, update_rate, future))
        try:
            results = await asyncio.wait_for(future, timeout=90)
            #logging.debug(f"Write task for {items} completed at {time.strftime('%H:%M:%S')}")
            return results
        except asyncio.TimeoutError:
            logging.error(f"_OPCDAWrapper_.async_write:Write to {items} timed out")

            return None
        finally:
            self.writing = False

    def custom_callback(self, paths: List[str], results: List[Tuple[any, int, str]]):
        for path, (value, quality, timestamp) in zip(paths, results):
            if quality == 192:
                self.callback.data[path] = (value, quality, timestamp)
                print(f"_OPCDAWrapper_.custom_callback:Poll/Subscribe: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
                logging.debug(f"_OPCDAWrapper_.custom_callbackk: {path} = {value}, Quality={quality}, Timestamp={timestamp}")
    



    async def start(self, items: List[str], group_name: str = "UA_SubscribeGroup", update_rate: int = 1000, max_updates: Optional[int] = None):
           # 定义并保存安全策略
       
        
        self.running = True
        self.max_updates = max_updates
        self.shutdown_event.clear()
       
        await self.setup_opc_ua_server()
     
        
        loop = asyncio.get_running_loop() 
        opc_da_task = loop.run_in_executor(self.executor, self.opc_da_thread, items, group_name, update_rate)
      

     
        
       
        async with self.server:
           
            try:
                self.server.set_security_policy(self.security_policies)
                logging.info(f"_OPCDAWrapper_.start:Security policies set: {[policy.URI for policy in self.security_policies]}")
                #logging.info(f"Endpoints after setup: {endpoints}")
                update_task = asyncio.create_task(self.update_ua_nodes(items))
                monitor_task = asyncio.create_task(self.user_manager.monitor_anonymous_sessions(self.server.iserver))  # 添加监控任务
                logging.info("_OPCDAWrapper_.start:Monitor task created for anonymous sessions")  # 确认任务创建
                
               
             
            # 检查哪个事件触发
                while not self.shutdown_event.is_set():
                    if self.restart_event.is_set():
                        logging.info("_OPCDAWrapper_.start:restart server due to restart event detected")
                        self.shutdown_event.set()  # 设置关闭信号
                        update_task.cancel()
                        monitor_task.cancel()
                        break
                    await asyncio.sleep(0.5)  

              
                await asyncio.gather(opc_da_task, update_task, monitor_task)
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.start:Start failed: {str(e)}")

            finally:
                self.running = False
                self.shutdown_event.set()
                update_task.cancel()
                monitor_task.cancel()
                try:
                    await opc_da_task
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_.start:opc_da_task failed to complete: {str(e)}")
                logging.debug(f"_OPCDAWrapper_.start:Start task completed at {time.strftime('%H:%M:%S')}")
                await asyncio.sleep(3)

async def main(max_time: Optional[float] = None, max_count: Optional[int] = None, manual_stop: bool = False):
   
    items = [
        "V1-IO/AI1_SCI1.EU100",
        "V1-IO/DO1_NA_PV.CV",
        "V1-AI-1/FS_CTRL1/MOD_DESC.CV",
        "V1-TIC-VSL/PID1/MODE.TARGET",
        "V1-AIC-DO/HI_ALM.CUALM",
        "V1-TIC-JKT/HEAT_OUT_D.CV"
    ]
    
    opc_da = _OPCDA_()
    wrapper = _OPCDAWrapper_(opc_da)
    try:
         while True:  # 添加循环以支持重启
            wrapper.__init__(opc_da)
            print('wrapper init,create subscription_task,poll task ...')
            subscription_task = asyncio.create_task(wrapper.start(items, max_updates=max_count))
            other_tasks = []

            poll_task = asyncio.create_task(wrapper.async_poll(items, interval=2.0, max_time=30.0))

            
            other_tasks.append(poll_task)
            
           
            if manual_stop:
                print('if manual_stop set to True , waiting signal to stop ...')
                async def check_manual_stop():
                    await asyncio.sleep(30)
                    if not wrapper.shutdown_event.is_set():
                        logging.info("_OPCDAWrapper_.main:Manual stop triggered")
                        await wrapper.stop()
                manual_task = asyncio.create_task(check_manual_stop())
                other_tasks.append(manual_task)
         

            print(f"_OPCDAWrapper_.main:Starting: subscription_task with max_time={max_time}, {len(other_tasks)} other tasks")

            if max_time:
                done, pending = await asyncio.wait([subscription_task], timeout=max_time)
                if subscription_task in done:
                    print("_OPCDAWrapper_.main: SSubscription task completed within max_time")
                else:
                    subscription_task.cancel()
                    try:
                        await subscription_task
                    except asyncio.CancelledError:
                      print("_OPCDAWrapper_.main:Subscription task cancelled due to timeout")
            else:
                await subscription_task
            



            if other_tasks:
                await asyncio.wait(other_tasks, return_when=asyncio.ALL_COMPLETED)
          
            if wrapper.restart_event.is_set():
                print("_OPCDAWrapper_.main:Restart event detected, restarting all tasks")
                await wrapper.stop()  # 当前任务
               
                continue  # 回到循环开始，重新执行任务
           

            break  # 如果没有新证书，退出循环

    except KeyboardInterrupt:
            print("_OPCDAWrapper_.main:Received Ctrl+C, stopping...")
           
    except Exception as e:
            logging.error(f"_OPCDAWrapper_.main:Main error: {str(e)}")
           
    finally:
            await wrapper.stop(restore_init_cert=True)
            all_tasks = [subscription_task] + other_tasks
            for task in all_tasks:
                if not task.done():
                    print(f"_OPCDAWrapper_.main:Task {task} still running, forcing cancellation")
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        logging.debug(f"_OPCDAWrapper_.main:Task {task} cancelled in finally block")
            print("_OPCDAWrapper_.main:Shutdown complete")

if __name__ == "__main__":
    
    #logging.getLogger('asyncua').setLevel(logging.WARNING)
  
    asyncio.run(main(max_time=6000, max_count=1099, manual_stop=False))