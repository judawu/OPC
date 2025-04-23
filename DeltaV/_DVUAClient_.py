from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicy,  # 基类，用于无安全策略
    SecurityPolicyBasic256Sha256,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyAes128Sha256RsaOaep
)
import asyncio
import os

import socket
from typing import List, Dict, Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import logging
import hashlib
import time
# 全局状态码映射
STATUS_CODE_NAMES = {getattr(ua.StatusCodes, attr): attr for attr in dir(ua.StatusCodes) if not attr.startswith('__')}

class _OPCUAClient_:
    def __init__(self, name:str='OPCUAclient',endpoint:str="opc.tcp://localhost:4840",application_uri:str='OPC.DELTAV.1',username: Optional[str] = None, password: Optional[str] = None, cert_dir:str='clientcert'):
        self.name=name
        self.server_node_name=application_uri
        self.endpoint=endpoint
        self.client = Client(self.endpoint)
       # logging.info(f"server attributes: {dir(self.client)}")
        if username and password:
            self.username = username  # 添加这一行
            self.password= password
           
        elif username :
            self.username = username
            self.password= '123456789' 
        else:
            self.username = 'default'  
            self.password = 'password' 
            
        self.encrpt_password, self.nonce = self._hash_password(self.username,self.password)
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.cert_dir = os.path.join(self.base_dir, "cert", cert_dir)
        os.makedirs(self.cert_dir, exist_ok=True)
        self.client_cert_name = f"client_cert_{self.name}"  #{uuid.uuid4().hex}
        self.client_cert_path = os.path.join(self.cert_dir, f"{self.client_cert_name}.pem")
        self.client_key_path = os.path.join(self.cert_dir, f"{self.client_cert_name}_key.pem")
        self.server_cert_path = os.path.join(self.cert_dir, "server_cert.pem")
        
        self.nodes = {}
        self.client.application_uri=application_uri
        self.last_error_code = None
        self.last_error_desc = None
        self.security_policy = (SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.SignAndEncrypt)

   

    def _hash_password(self,username:str, password: str) -> tuple[str, str]:
        """使用 SHA-256 和 nonce 哈希密码"""
        nonce = str(time.time())  # 使用时间戳作为 nonce
        salted_password = password + username
        hashed_password = hashlib.sha256((salted_password + nonce).encode('utf-8')).hexdigest()
        return hashed_password, nonce

    async def _find_node_(self, node,  target_name: str,depth: int = 0, max_depth: int = 10):
            try:
                if target_name in self.nodes:
                    return self.nodes[target_name]
                if depth > max_depth:
                    logging.debug(f"_find_node_: search {target_name}, max_depth {max_depth} reach at{node}, continue")
                    return None   
                # 检查当前节点               
                node_name = await node.read_display_name()
                if node_name.Text == target_name:                
                    self.nodes[node_name.Text]=node
                    logging.debug(f"Found target {target_name} node at:{node}")
                    return node             
                # 递归检查子节点         
                children = await node.get_children()
                for child in children:                         
                    result= await self._find_node_(child, target_name, depth + 1, max_depth)
                    if result:
                        return result      
            except Exception as e:
                    logging.error(f"Error during find node {target_name} : {str(e)}")
                    return None
    async def create_child(self,node):
                items = await node.get_children()
                for item in items:               
                    node_name = await item.read_display_name()               
                    self.nodes[node_name.Text] = item


      
    async def CreateBrowser(self):
            try:
                self.nodes.clear()
                logging.debug(f"CreateBrowser: connected sucessful, try to create browser to nodes")
                parent_node=self.client.get_objects_node()  
                await self.create_child(parent_node)
                if self.server_node_name in self.nodes:
                     server_node = self.nodes[self.server_node_name]
                else:
                    logging.debug(f"CreateBrowser: OPC server folder {self.server_node_name} not found ,try to find it")
                    server_node= await self._find_node_(parent_node,  self.server_node_name, max_depth= 3)        
                await self.create_child(server_node)         
                if   "LastErrorStatus" in self.nodes:
                         self.last_error_code = self.nodes[ "LastErrorStatus"]
                else:
                    logging.debug(f"CreateBrowser Error: LastErrorStatus not found ,try to find it")
                    server_node= await self._find_node_(server_node,   "LastErrorStatus" , max_depth= 5)
                if   "LastErrorDesc" in self.nodes:
                         self.last_error_code = self.nodes[ "LastErrorDesc"]
                else:
                    logging.debug(f"CreateBrowser Error: LastErrorDesc not found ,try to find it")
                    server_node= await self._find_node_(server_node,   "LastErrorDesc" , max_depth= 3)
            except Exception as e:
                    logging.error(f"CreateBrowser during CreateBrowser : {str(e)}")  
                    return False  
    
    async def find_method(self,method_name:str):
        try:
            if method_name in self.nodes:
                     method_node = self.nodes[method_name]
            else:
                    logging.debug(f"method not found in {self.server_node_name} folder,try to find from subfolder in depth search")
                    if self.server_node_name not in self.nodes:
                        await self.CreateBrowser()
                        logging.debug(f"find_method: {self.server_node_name} not build ,build it using CreateBrowser")
                    server_node=self.nodes[self.server_node_name]
                    if method_name in self.nodes:
                         method_node=self.nodes[method_name]
                    else:
                         method_node = await self._find_node_(server_node,method_name,max_depth = 3)
            if method_node and (await method_node.read_node_class()) != ua.NodeClass.Method:
                      return  None
            return method_node
                   
        except Exception as e:
             logging.error(f"Error during find_method : {str(e)}") 

        
        
    async def generate_client_certificate(self):
        if not os.path.exists(self.client_cert_path) or not os.path.exists(self.client_key_path):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # 确保 key_size >= 2048
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.client_cert_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "xAI"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            hostname = socket.gethostname()
            san = x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(hostname),
                x509.UniformResourceIdentifier(self.client.application_uri),  # 确保与 server.set_application_uri 一致
              
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
                .sign(key, hashes.SHA256())  # 确保使用 SHA256
            )
            with open(self.client_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(self.client_key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            logging.debug(f"Generated client certificate {self.client_cert_name} in {self.cert_dir}")
    
    async def transfer_client_certificate(self):
            """将客户端证书传输到服务器并调用 add_client_cert 方法"""
            try:
                
                # 读取客户端证书内容
                with open(self.client_cert_path, "rb") as f:
                    client_cert_data = f.read()
                    logging.debug(f"Loaded client certificate from {self.client_cert_path} for transfer")


                method_node= await self.find_method('add_client_cert')
             
                if not method_node:
                    logging.error(f"add_client_cert method not found in {self.server_node_name} folder")
                    raise RuntimeError("add_client_cert method not found")

                # 调用服务器端的 add_client_cert 方法
                result = await self.client.nodes.objects.call_method(
                    method_node.nodeid,
                    ua.Variant(client_cert_data, ua.VariantType.ByteString)
                )
                if result:
                    logging.debug("Successfully transferred client certificate to server")
                    return result
                else:
                     server_error_status = await self. get_server_last_error()
                     logging.warning(f"transfer_client_certificate: Server error status: {server_error_status}")
              
                
             

            except Exception as e:
                logging.error(f"Failed to transfer client certificate: {str(e)}")    
                raise
    async def connect(self, use_certificate=False):
   
            try:
                self.client.timeout = 240  # 增加到 120 秒
                
                if use_certificate:
                    
                    server_cert = self.server_cert_path
                    if not os.path.exists(server_cert):
                        raise RuntimeError("Client connect: Server certificate not found; connect without certificate first to retrieve it")
                    with open(server_cert, "rb") as f:
                        cert_data = f.read()
                        cert = x509.load_pem_x509_certificate(cert_data)
                        logging.debug(f"Client connect: Using server certificate: Subject={cert.subject}, Serial={cert.serial_number}")

                    
                       
                    self.client.set_user(self.username)
                    self.client.set_password(self.encrpt_password+ ":" + self.nonce)
                    if not os.path.exists(self.client_cert_path) or not os.path.exists(self.client_key_path):
                        logging.info(f"Client connect: Client certificate {self.client_cert_path} or key {self.client_key_path} not found, generating...")
                        await self.generate_client_certificate()
                        # 先生成客户端证书  

                    # 使用 self.security_policy（默认值或已更新的值）
                    selected_policy, selected_mode = self.security_policy
                    logging.debug(f"Client connect: set client security policy: {selected_policy.URI}, mode={selected_mode} (Value={selected_mode.value})")
                   
                    await self.client.set_security(
                        selected_policy,
                        self.client_cert_path,
                        self.client_key_path,
                        server_certificate=server_cert,
                        mode=selected_mode
                    )
                    #self.client.uaclient.user_identity_token = None  # 清除用户身份令牌
                    logging.debug("Client connect: Security policy set successfully")
                else:
                    # 即使不使用证书，也尝试加密连接
                  
                    
                    self.client.security_policy = SecurityPolicy()
                    self.client.set_user(self.username)
                    self.client.set_password(self.encrpt_password + ":" + self.nonce)
                    logging.debug("Client connect: use_certificate set to False,Connecting with no security policy (SecurityPolicy#None)")
                    self.client.uaclient.skip_validation = True
                logging.debug("Client connect: Attempting to connect to server...")
                await self.client.connect()
             
                logging.debug(f"Client connect: Connected to server as {self.username}" + (" with certificate" if use_certificate else " with username/password"))
                await self.CreateBrowser()
            except asyncio.TimeoutError as e:
                logging.error(f"Client connect: Connection timed out: {str(e)}")
                raise
            except Exception as e:
                logging.error(f"Client connect: Connection failed: {str(e)}")
                raise




    async def disconnect(self):
            await self.client.disconnect()
            logging.debug(f"Client disconnect: Disconnected from server as {self.username}")

    async def query_security_policies(self):
        try:
            endpoints = await self.client.get_endpoints()
            supported_policies = [ep.SecurityPolicyUri for ep in endpoints if ep.SecurityPolicyUri]
            logging.debug(f"query_security_policies: Queried server security policies: {supported_policies}")
           
            return supported_policies
        except Exception as e:
            logging.error(f"query_security_policies: Failed to query security policies: {str(e)}")
           
            return []

    async def get_server_certificate(self):
            try:
                if "ServerCertificate"  not in self.nodes:                 
                    if self.server_node_name not in self.nodes:
                        await self.CreateBrowser()
                        logging.debug(f"get_server_certificate: {self.server_node_name} not build , build it using CreateBrowser")
                    server_node=self.nodes[self.server_node_name]

                if "ServerCertificate"  in self.nodes:   
                         server_cert_node = self.nodes["ServerCertificate"]
                else:
                         server_cert_node = await self._find_node_(server_node, "ServerCertificate" ,max_depth = 3)



                server_cert_node = self.nodes["ServerCertificate"]
                if not server_cert_node:
                    logging.error("get_server_certificate: ServerCertificate node not found")
                    return False
                
                cert_data = await server_cert_node.read_value()
                with open(self.server_cert_path, "wb") as f:
                    f.write(cert_data)
                logging.debug(f"get_server_certificate: Retrieved server certificate and saved to {self.server_cert_path}")
                # 验证证书
                try:
                    x509.load_pem_x509_certificate(cert_data)
                    logging.debug("Server certificate is valid")
                    return True
                except Exception as e:
                    logging.error(f"Retrieved server certificate is invalid: {str(e)}")
                    server_error_status = await self. get_server_last_error()
                    logging.warning(f"get_server_certificate: Server error status: {server_error_status}")
                    return False
            except Exception as e:
                 logging.error(f"Retrieved server certificate is invalid: {str(e)}")
                 return False
    
    async def generate_server_certificate(self):
                try:
                    gen_server_cert_method=await self.find_method('generate_server_certificate')
                    if not gen_server_cert_method:
                            logging.error("generate_server_certificate Error: generate_server_certificate method not found")
                            return False

                    logging.debug("generate_server_certificate: Calling generate_server_certificate to update security policy...")

                    try:
                            result = await self.client.nodes.objects.call_method(gen_server_cert_method.nodeid)
                            
                    except ua.UaStatusCodeError as e:
                            logging.error(f"generate_server_certificate:  failed with status code: {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                            logging.error(f"generate_server_certificate:  failed - {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                            server_error_status = await self. get_server_last_error()
                            logging.error(f"generate_server_certificate: Server error status: {server_error_status}")
                            return False
                    except Exception as e:
                            logging.error(f"generate_server_certificate: Unexpected error in generate_server_certificate: {str(e)}")
                
                            server_error_status = await self. get_server_last_error()
                            logging.error(f"generate_server_certificate:Server error status: {server_error_status}")
                            return False
                    logging.info(f"generate_server_certificate:Calling generate_server_certificate ...: {result}")
                    return True
                except Exception as e:
                     logging.error(f"generate_server_certificate: Unexpected error in generate_server_certificate: {str(e)}")
                     return False
               
    async def set_server_policy(self, policy="AES256Sha256RsaPss", sign_and_encrypt=True):
            try:
                    set_server_policy_method= await self.find_method("set_server_policy") 
                    if not set_server_policy_method:
                        logging.error("set_server_policy Error: set_server_policy method not found")
                        return False
           
                    try:
                        result = await self.client.nodes.objects.call_method(
                            set_server_policy_method.nodeid,
                            ua.Variant(policy, ua.VariantType.String),
                            ua.Variant(sign_and_encrypt, ua.VariantType.Boolean)
                        )
                        logging.debug(f"set_server_policy: Set server security policy to {policy}:{sign_and_encrypt}")
                
                    except ua.UaStatusCodeError as e:
                        logging.error(f"set_server_policy:set_server_policy failed with status code: {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                        logging.error(f"set_server_policy Error: set_server_policy failed - {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"set_server_policy: set_server_policy Server error status: {server_error_status}")
                        return False
                    except Exception as e:
                        logging.error(f"set_server_policy:Unexpected error in set_server_policy: {str(e)}")
                        logging.error(f"set_server_policy: Unexpected error: {str(e)}")
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"set_server_policy: Server error status: {server_error_status}")
                        return False
                    
                                # 设置客户端的安全策略
                    policy_map = {
                        "AES256Sha256RsaPss": SecurityPolicyAes256Sha256RsaPss,
                        "Basic256Sha256": SecurityPolicyBasic256Sha256,
                        "AES128Sha256RsaOaep": SecurityPolicyAes128Sha256RsaOaep
                    }
                    selected_policy = policy_map.get(policy, SecurityPolicyBasic256Sha256)
                    selected_mode = ua.MessageSecurityMode.SignAndEncrypt if sign_and_encrypt else ua.MessageSecurityMode.Sign
                    self.security_policy = (selected_policy, selected_mode)  # 确保是二元元组
                    logging.debug(f"set_server_policy: Set client security policy: policy={selected_policy.URI}, mode={selected_mode} (Value={selected_mode.value})")

                    return True

            except Exception as e:
                        logging.error(f"set_server_policy:Unexpected error in set_server_policy: {str(e)}")
           


           
    async def restore_server_certificate(self):
        
                try:
                    restore_server_cert_method= await self.find_method("restore_initial_certificate")
                    if not restore_server_cert_method:
                        logging.error("restore_server_certificate Error: restore_server_certificate method not found")
                        return False
        
                    try:
                           result = await self.client.nodes.objects.call_method(restore_server_cert_method.nodeid)
                    except ua.UaStatusCodeError as e:
                            logging.error(f"restore_server_certificate: restore_initial_certificate failed with status code: {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                            logging.error(f"estore_server_certificate: restore_initial_certificate failed - {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                            server_error_status = await self. get_server_last_error()
                            logging.error(f"estore_server_certificate: Server error status: {server_error_status}")
                            return False
                    except Exception as e:
                            logging.error(f"estore_server_certificate: Unexpected error in restore_initial_certificate: {str(e)}")
                            logging.error(f"estore_server_certificate: Unexpected error: {str(e)}")
                            server_error_status = await self. get_server_last_error()
                            logging.error(f"estore_server_certificate: Server error status: {server_error_status}")
                            return False
                    logging.info(f"estore_server_certificate: Calling restore_initial_certificate...: {result}")
                    return True
                except Exception as e:
                    logging.error(f"estore_server_certificate: Unexpected error in restore_initial_certificate: {str(e)}")
                    return False
    
    async def get_server_last_error(self):
        """读取服务器端的 LastErrorStatus 节点"""
        if  not self.last_error_desc :
            logging.error("get_server_last_error: LastErrorStatus node not available")
            return "get_server_last_error: status node not available"
        try:
            error_desc = await self.last_error_desc.read_value()
            return f"{error_desc}"
        except Exception as e:
            logging.error(f"get_server_last_error: Failed to read LastErrorStatus: {str(e)}")
            return f"get_server_last_error: Failed to read error status: {str(e)}"

    async def add_item(self,item_name:str):
      
        try: 
            if item_name in self.nodes :
               return self.nodes[item_name]
            
            else:
                node=self.nodes[self.server_node_name]
                item_node= await self._find_node_(node,item_name,max_depth=3)
                if item_node is None:
                   logging.debug(f"Read: Node {item_name} not found,please use add_item call to create it")
                   add_item_method=await self.find_method('add_item')
                   if not add_item_method:
                        logging.error("add_item Error: add_item method not found")
                        return None
                   result = await self.client.nodes.objects.call_method(
                                        add_item_method.nodeid,
                                        ua.Variant(item_name, 3)
                                        )
                await asyncio.sleep(3)
                item_node= await self._find_node_(node,item_name,3)   

            return item_node
        except Exception as e:
                    logging.error(f"Read: Failed to read {item_name}: {e}")
                    return None

    async def read(self, item_name:str):
      
        try: 
            if item_name in self.nodes :
                node = self.nodes[item_name]
                  
            else:
                logging.debug(f"Read: Node {item_name} not found,please use add item function to add it first")
                node = await self.add_item(item_name)
            
            if node:

                if (await node.read_node_class()) == ua.NodeClass.Variable:
                    
                        value = await node.read_value()
                        logging.debug(f"Read: {item_name} = {value}")
                        return value
                else:
                    logging.debug(f"Read: {item_name} is not a opc ua varialbe")  
                    return None  
            return None
        except Exception as e:
                    logging.error(f"Read: Failed to read {item_name}: {e}")
                    return None
    async def write(self, values,items):
            try:
                nums=len(items)
                write_method=await self.find_method("write_items")
                if not write_method:
                    logging.error("write Error: write_items method not available")
                    return [False]*nums

             
                items_variant = ua.Variant(items, ua.VariantType.String)
                values_variant = ua.Variant([ua.Variant(val) for val in values], ua.VariantType.Variant)

                for attempt in range(3):
                    try:
                        logging.debug(f"write: Starting write attempt {attempt + 1} for items: {items}")
                        results = await asyncio.wait_for(
                            self.client.nodes.objects.call_method(write_method.nodeid, values_variant,items_variant),
                            timeout=120              
                        )
                        if not isinstance(results, list):
                            if isinstance(results, bool):
                                 return [results]
                            else:
                               logging.error(f"write:Invalid result type from server: {type(results)}")
                        
                               return [False]*nums  
                        if len(results) > 1 and not results[0]:
                            error_message = results[1]
                            logging.error(f"write: Server returned error: {error_message}")                  
                            server_error_status = await self. get_server_last_error()
                            logging.error(f"write: Server error status: {server_error_status}")
                            return [False]*nums
                        logging.debug(f"write:  Write attempt {attempt + 1} succeeded with results: {results}")           
                    
                        return results
                        
                    except asyncio.TimeoutError:
                        logging.warning(f"Write: attempt {attempt + 1} timed out after 120 seconds, retrying...")                    
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"write: Server error status: {server_error_status}")
                        await asyncio.sleep(5)  # 增加重试间隔到 5 秒
                    except ua.UaStatusCodeError as e:
                        logging.error(f"Write: attempt {attempt + 1} failed with UA error,write_to_opc_da failed with status code: {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                        logging.error(f"Write Error: Method call  write_to_opc_da failed - {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                        logging.error(f"Write Raw exception: {str(e)}")  # 打印原始异常信息
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"Write: Server error status: {server_error_status}")
                        return [False]*nums
                    except Exception as e:
                        logging.error(f"Write:Unexpected error in write attempt {attempt + 1}: {str(e)}")
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"Write:Server error status: {server_error_status}")
                        logging.error(f"Write: Unexpected error: {str(e)}")
                        return [False]*nums
                logging.error("Write: All write attempts failed due to timeout")
            
                return [False]*nums
            except Exception as e:
                        logging.error(f"Write:Unexpected error in write moehtod call: {str(e)}")
    

async def main():

   


    clients = [
        _OPCUAClient_(name='opcuaclient1',username="EMERSON", password="DeltaVE1"),  # admin account
        _OPCUAClient_(name='opcuaclient2'),  # default account
        _OPCUAClient_(name='opcuaclient3')   # default account, without certficate
      
    ]
    
   
    write_lock = asyncio.Lock()  # 添加锁以同步写操作
    async def run_client(client): 
        print(F'{client.name} is waiting 5 seconds for server to start first..')
        await asyncio.sleep(5)  # 延迟 10 秒
      
        
       
      
           
        if client.name=='opcuaclient1':
            print(f'{client.name} connect to the server without certficate to  get server certificate ...')
            await client.connect(use_certificate=False)
         
            await client.get_server_certificate()
            await client.disconnect()
            print(f'{client.name} disconnected and connect to the server again with certficate to  reset server certificate by call generate_server_certificate moethod...')
            await client.connect(use_certificate=True) 
         
           
            await client.generate_server_certificate()
            print(f'{client.name} reset server security policy by call set_server_policy moethod...')
            await client.set_server_policy()
            print(f'New certificate applied to the opc ua server, {client.name} disconnect to the server...')
            await client.disconnect()
      
        print(f'{client.name} is waiting 10 seconds for server to update certificate ..')
        await asyncio.sleep(10)  # 延迟 10 秒
        print(f'waiting client to init for {client.name}..')
        client.__init__(name=client.name,username=client.username,password=client.password)
        
        await client.connect(use_certificate=False)
        print(f'get server certificate for {client.name} without certficate verification...')
        await client.get_server_certificate()
        await client.disconnect()

        # 使用证书重新连接
        if client.name !='opcuaclient3':
            for attempt in range(3):  # 添加重试机制
                try:
                    print(f'connecting  {client.name} with certficate verification...')
                    await client.connect(use_certificate=True)
                    break
                except (asyncio.TimeoutError, Exception) as e:
                    logging.warning(f"Connect to  {client.name} attempt {attempt + 1} failed: {str(e)}")
                    print(f"Connect to  {client.name} attempt {attempt + 1} failed: {str(e)}")
                    await asyncio.sleep(2)
            else:
                logging.error(f"All connection attempts failed for {client.name}")
                return
        else:
            await asyncio.sleep(10)  # 延迟 30 秒
            for attempt in range(3):  # 添加重试机制
                try:
                    print(f'connecting  {client.name} without certficate verification...')
                    await client.connect(use_certificate=False)
                    break
                except (asyncio.TimeoutError, Exception) as e:
                    logging.warning(f"Connect to  {client.name} attempt {attempt + 1} failed: {str(e)}")
                    print(f"Connect to  {client.name} attempt {attempt + 1} failed: {str(e)}")
                    await asyncio.sleep(2)
            else:
                logging.error(f"All connection attempts failed for {client.name}")
                return
        
      
        print(f'read value to the server from {client.name}...')
        result=await client.read("V1-IO/AI1_SCI1.EU100")
        print(f'read value V1-IO/AI1_SCI1.EU100 from {client.name} is {result}...')
        
        if client.name=='opcuaclient1': 
            print(f"{client.name} transfer client certificate.by call transfer_client_certificate...")
            await client.transfer_client_certificate()
            print(f'write value to the server from {client.name}....')

            write_items = ["V1-IO/AI1_SCI1.EU100","V1-AI-1/FS_CTRL1/MOD_DESC.CV"] 
            write_values = [32766,"WELCOME"] 
            async with write_lock:  # 使用锁同步写操作
                result=await client.write(write_values,write_items)
                print(f'write  result from {client.name} is {result}...')
            await asyncio.sleep(1)
            for item in write_items:
                result= await client.read(item)
                print(f'read value from {client.name} is {result}...')

        elif client.name=='opcuaclient2': 
            print(f'write value to the server from {client.name}....')
            write_items = ["V1-IO/AI1_SCI1.EU100","V1-AI-1/FS_CTRL1/MOD_DESC.CV"] 
            write_values = [32787,"helloworld"]
            async with write_lock:  # 使用锁同步写操作
                result= await client.write(write_values,write_items)
                print(f'write  result from {client.name} is {result}...')
            await asyncio.sleep(1)
            for item in write_items:
                result=await client.read(item)
                print(f'read value from {client.name} is {result}...')
        else:
           print(f'read value  at {client.name}....')
           result=await client.read("V1-AI-1/FS_CTRL1/MOD_DESC.CV")
           print(f'read value from {client.name} is {result}...')
      
           
        
        policies = await client.query_security_policies()
      
        print(f"use query_security_policies method at {client.name} for  Security policies query : {policies}")
        print(f'{client.name} disconnect to the server...')
        await client.disconnect()
        
    tasks = [run_client(client) for client in clients]
    await asyncio.gather(*tasks)

    last_client = clients[0]
    
    await last_client.connect(use_certificate=True)
    print(f'{last_client.name} call restore_server_certificate to restore server certficate..')
    await last_client.restore_server_certificate()
    await last_client.disconnect()

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(base_dir,'opcuaclient.log')

    logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    logging.getLogger('asyncua').setLevel(logging.WARNING)
    asyncio.run(main())