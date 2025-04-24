
import hashlib
import logging
import time
from asyncua.server.users import User, UserRole  # Correct import for v1.1.5
import asyncio
import json
import socket
class _OPCUAUserManager_:

    
    def __init__(self):
        """CustomUserManager init..."""
        self.connected_clients = {
            "count": 0,
            "sessions": {}
        }

     
        self.anonymous_sessions = {}  # (client_addr, start_time) pairs
        self.recently_closed = {}    # (client_addr, close_time)
        self.blacklist = {}    # (client_addr, close_time)
        self._anonymous_timeout = 60            # 会话超时时间（秒）
        self._cooldown_time = 180           # 重连冷却时间（秒）
        self._monitor_period = 10
        self._user_roles = {
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
        self._user_passwords = {
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
             if current_time < self.blacklist[session_id]+ self._cooldown_time :
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
                server_password = self._hash_password(username, self._user_passwords.get(username, "anonymous"), nonce)
            else:
                server_password = 'canyouguess?'
        # 获取会话详细信息
       
        userrole =  self._user_roles.get(username, 100)  # 默认匿名用户
        if username in self._user_passwords and password:
            
            logging.debug(f"CustomUserManager: User name {username}  exist in the user list,check userrole:")
            if certificate is not None and client_password == server_password:
               
                userrole = min(userrole, 9)  # 有证书时最低为 9
                logging.debug(f"CustomUserManager: User name {username}  have a valid cerficate,and password match  and  the pasword is encrypted,get userrole {userrole} ")
          
            elif client_password != self._user_passwords[username] and client_password != server_password and certificate is None:
                userrole = 100 # 密码不匹配，设为匿名用户
                logging.debug(f"CustomUserManager: User name {username} is in user list without a valid certficate, but password didn't match , get userrole {userrole}")
             
            elif client_password == server_password and certificate is None:
    
                    userrole =  userrole + 20
                    logging.debug(f"CustomUserManager: User name {username} and password match and the pasword is encrypted,but don't have a valid cerficate,get userrole {userrole} ")
            elif certificate is not None and client_password== self._user_passwords[username]:
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
                if time_since_closed < self._cooldown_time:
                    logging.warning(f"CustomUserManager: Rejecting {client_addr} due to cooldown: {time_since_closed:.2f}s < {self._cooldown_time}s")
                    return None
                self.recently_closed = {ip: t for ip, t in self.recently_closed.items() if current_time - t < self._cooldown_time}
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
                                if current_time - start_time > self._anonymous_timeout
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

                        await asyncio.sleep(self._monitor_period)  # 每 10 秒检查一次
                    except Exception as e:
                        logging.error(f"CustomUserManager: Error in monitor_anonymous_sessions: {str(e)}", exc_info=True)
                        await asyncio.sleep( self._monitor_period)  # 出错后继续运行
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