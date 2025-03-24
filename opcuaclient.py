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
    def __init__(self, name:str='OPCUAclient',endpoint:str="opc.tcp://localhost:4840", username: Optional[str] = None, password: Optional[str] = None, cert_dir:str='clientcert'):
        self.name=name
        self.endpoint=endpoint
        self.client = Client(self.endpoint)
       # logging.info(f"server attributes: {dir(self.client)}")
        if username and password:
            self.username = username  # 添加这一行
            self.password, self.nonce = self._hash_password(username,password)
        elif username :
            self.username = username
            self.password= 'DeltaVE1'
            self.nonce = '123456789'
        else:
            self.username = 'default'  
            self.password = 'password' 
            self.nonce = '123456789' 
      
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.cert_dir = os.path.join(self.base_dir, "cert", cert_dir)
        os.makedirs(self.cert_dir, exist_ok=True)
        self.client_cert_name = f"client_cert_{self.name}"  #{uuid.uuid4().hex}
        self.client_cert_path = os.path.join(self.cert_dir, f"{self.client_cert_name}.pem")
        self.client_key_path = os.path.join(self.cert_dir, f"{self.client_cert_name}_key.pem")
        self.server_cert_path = os.path.join(self.cert_dir, "server_cert.pem")
        
        self.nodes_dict = {}
        self.write_method = None
        self.gen_server_cert_method = None
        self.set_server_policy_method = None
        self.restore_server_cert_method = None
        self.client.application_uri="urn:opcda:wrapper"
        self.last_error_code = None
        self.last_error_desc = None
        self.security_policy = (SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.SignAndEncrypt)
    def _hash_password(self,username:str, password: str) -> tuple[str, str]:
        """使用 SHA-256 和 nonce 哈希密码"""
        nonce = str(time.time())  # 使用时间戳作为 nonce
        salted_password = password + username
        hashed_password = hashlib.sha256((salted_password + nonce).encode('utf-8')).hexdigest()
        return hashed_password, nonce
    
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
            logging.info(f"Generated client certificate {self.client_cert_name} in {self.cert_dir}")
    
    async def transfer_client_certificate(self):
            """将客户端证书传输到服务器并调用 add_client_cert 方法"""
            try:
                
                # 读取客户端证书内容
                with open(self.client_cert_path, "rb") as f:
                    client_cert_data = f.read()
                    logging.info(f"Loaded client certificate from {self.client_cert_path} for transfer")

                # 动态查找 add_client_cert 方法的 NodeId
                opc_da_folder = await self._get_opc_da_folder()
                if not opc_da_folder:
                    logging.error("OPCDA.1 folder not found, cannot transfer certificate")
                    raise RuntimeError("OPCDA.1 folder not found")

                method_node = None
                children = await opc_da_folder.get_children()
                for child in children:
                    display_name = await child.read_display_name()
                    if display_name.Text == "add_client_cert":
                        method_node = child
                        break
                
                if not method_node:
                    logging.error("add_client_cert method not found in OPCDA.1 folder")
                    raise RuntimeError("add_client_cert method not found")

                # 调用服务器端的 add_client_cert 方法
                result = await self.client.nodes.objects.call_method(
                    method_node.nodeid,
                    ua.Variant(client_cert_data, ua.VariantType.ByteString)
                )
                if result:
                    logging.info("Successfully transferred client certificate to server")
                else:
                    logging.warning("Server reported failure when adding client certificate")
                
                return result

            except Exception as e:
                logging.error(f"Failed to transfer client certificate: {str(e)}")
                server_error_status = await self. get_server_last_error()
                print(f"Server error status: {server_error_status}")
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
                        logging.info(f"Client connect: Using server certificate: Subject={cert.subject}, Serial={cert.serial_number}")

                    
                       
                    self.client.set_user(self.username)
                    self.client.set_password(self.password + ":" + self.nonce)
                    if not os.path.exists(self.client_cert_path) or not os.path.exists(self.client_key_path):
                        logging.info(f"Client connect: Client certificate {self.client_cert_path} or key {self.client_key_path} not found, generating...")
                        await self.generate_client_certificate()
                        # 先生成客户端证书  

                    # 使用 self.security_policy（默认值或已更新的值）
                    selected_policy, selected_mode = self.security_policy
                    logging.info(f"Client connect: set client security policy: {selected_policy.URI}, mode={selected_mode} (Value={selected_mode.value})")
                   
                    await self.client.set_security(
                        selected_policy,
                        self.client_cert_path,
                        self.client_key_path,
                        server_certificate=server_cert,
                        mode=selected_mode
                    )
                    #self.client.uaclient.user_identity_token = None  # 清除用户身份令牌
                    logging.info("Client connect: Security policy set successfully")
                else:
                    # 即使不使用证书，也尝试加密连接
                  
                    
                    self.client.security_policy = SecurityPolicy()
                    self.client.set_user(self.username)
                    self.client.set_password(self.password + ":" + self.nonce)
                    logging.info("Client connect: use_certificate set to False,Connecting with no security policy (SecurityPolicy#None)")
                    self.client.uaclient.skip_validation = True
                logging.info("Client connect: Attempting to connect to server...")
                await self.client.connect()
                logging.info(f"Client connect: Connected to server as {self.username}" + (" with certificate" if use_certificate else " with username/password"))
            except asyncio.TimeoutError as e:
                logging.error(f"Client connect: Connection timed out: {str(e)}")
                raise
            except Exception as e:
                logging.error(f"Client connect: Connection failed: {str(e)}")
                raise




    async def disconnect(self):
            await self.client.disconnect()
            logging.info(f"Client disconnect: Disconnected from server as {self.username}")

    async def query_security_policies(self):
        try:
            endpoints = await self.client.get_endpoints()
            supported_policies = [ep.SecurityPolicyUri for ep in endpoints if ep.SecurityPolicyUri]
            logging.info(f"query_security_policies: Queried server security policies: {supported_policies}")
           
            return supported_policies
        except Exception as e:
            logging.error(f"query_security_policies: Failed to query security policies: {str(e)}")
            server_error_status = await self. get_server_last_error()
            logging.error(f"query_security_policies: QServer error status: {server_error_status}")
            return []

    async def get_server_certificate(self):
            opc_da_folder = await self._get_opc_da_folder()
            if not opc_da_folder:
                logging.error("get_server_certificate:  OPC_DA_Items folder not found")
                return False
            items = await opc_da_folder.get_children()
            for item in items:
                display_name = await item.read_display_name()
                if display_name.Text == "ServerCertificate":
                    cert_data = await item.read_value()
                    with open(self.server_cert_path, "wb") as f:
                        f.write(cert_data)
                    logging.info(f"get_server_certificate: Retrieved server certificate and saved to {self.server_cert_path}")
                    # 验证证书
                    try:
                        x509.load_pem_x509_certificate(cert_data)
                        #logging.info("Server certificate is valid")
                    except Exception as e:
                        logging.error(f"Retrieved server certificate is invalid: {str(e)}")
                        server_error_status = await self. get_server_last_error()
                        logging.info(f"get_server_certificate: Server error status: {server_error_status}")
                    return True
            logging.error("get_server_certificate: ServerCertificate node not found")
            return False
    
    async def generate_server_certificate(self):
            if not self.gen_server_cert_method:
                objects_node = self.client.nodes.objects
                children = await objects_node.get_children()
                opc_da_folder = None
                for child in children:
                    display_name = await child.read_display_name()
                    if display_name.Text == "OPCDA.1":
                        opc_da_folder = child
                        break
                if not opc_da_folder:
                    logging.error("generate_server_certificate error: OPCDA.1 folder not found")
                    return False

                items = await opc_da_folder.get_children()
                for item in items:
                    display_name = await item.read_display_name()
                    if display_name.Text == "generate_server_certificate":
                        self.gen_server_cert_method = item
                        break
                if not self.gen_server_cert_method:
                    logging.error("generate_server_certificate Error: generate_server_certificate method not found")
                    return False

            logging.info("generate_server_certificate: Calling generate_server_certificate to update security policy...")

            try:
                result = await self.client.nodes.objects.call_method(self.gen_server_cert_method.nodeid)
                
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
    async def set_server_policy(self, policy="AES256Sha256RsaPss", sign_and_encrypt=True):
            if not self.set_server_policy_method:
                objects_node = self.client.nodes.objects
                children = await objects_node.get_children()
                opc_da_folder = None
                for child in children:
                    display_name = await child.read_display_name()
                    if display_name.Text == "OPCDA.1":
                        opc_da_folder = child
                        break
                if not opc_da_folder:
                    logging.error("set_server_policy Error: OPCDA.1 folder not found")
                    return False

                items = await opc_da_folder.get_children()
                for item in items:
                    display_name = await item.read_display_name()
                    if display_name.Text == "set_server_policy":
                        self.set_server_policy_method = item
                        break
                if not self.set_server_policy_method:
                    logging.error("set_server_policy Error: set_server_policy method not found")
                    return False


           
            try:
                result = await self.client.nodes.objects.call_method(
                    self.set_server_policy_method,
                    ua.Variant(policy, ua.VariantType.String),
                    ua.Variant(sign_and_encrypt, ua.VariantType.Boolean)
                )
                logging.info(f"set_server_policy: Set server security policy to {policy}:{sign_and_encrypt}")
         
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
            logging.info(f"set_server_policy: Set client security policy: policy={selected_policy.URI}, mode={selected_mode} (Value={selected_mode.value})")

            logging.info(f"set_server_policy: Calling restore_initial_cset_server_policy ...: {result}")
            return True

            
           


           
    async def restore_server_certificate(self):
        if not self.restore_server_cert_method:
            opc_da_folder = await self._get_opc_da_folder()
            items = await opc_da_folder.get_children()
            for item in items:
                display_name = await item.read_display_name()
                if display_name.Text == "restore_initial_certificate":
                    self.restore_server_cert_method = item
                    break
            if not self.restore_server_cert_method:
                logging.error("restore_server_certificate Error: restore_initial_certificate method not found")
                return False

        
        try:
           result = await self.client.nodes.objects.call_method(self.restore_server_cert_method.nodeid)
        except ua.UaStatusCodeError as e:
                logging.error(f"restore_server_certificate: set_server_policy failed with status code: {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                logging.error(f"estore_server_certificate: set_server_policy failed - {STATUS_CODE_NAMES.get(e.code, "UnknownStatusCode")} ({hex(e.code)})")
                server_error_status = await self. get_server_last_error()
                logging.error(f"estore_server_certificate: Server error status: {server_error_status}")
                return False
        except Exception as e:
                logging.error(f"estore_server_certificate: Unexpected error in set_server_policy: {str(e)}")
                logging.error(f"estore_server_certificate: Unexpected error: {str(e)}")
                server_error_status = await self. get_server_last_error()
                logging.error(f"estore_server_certificate: Server error status: {server_error_status}")
                return False
        logging.info(f"estore_server_certificate: Calling restore_initial_certificate...: {result}")
        return True

    async def browse(self):
        opc_da_folder = await self._get_opc_da_folder()
        if not opc_da_folder:
            logging.error("browse Error: OPC_DA_Items folder not found")
            return False

        self.nodes_dict.clear()
        self.write_method = None
        items = await opc_da_folder.get_children()
        for item in items:
            node_id = item.nodeid
            display_name = await item.read_display_name()
            node_class = await item.read_node_class()
            if node_class == ua.NodeClass.Method and display_name.Text == "write_to_opc_da":
                self.write_method = item
                logging.info(f"browse: Found write_to_opc_da method with NodeId: {node_id}")
            elif node_class == ua.NodeClass.Variable and display_name.Text == "LastErrorStatus":
                self.last_error_code = item
                logging.info(f"browse: Found LastErrorStatus node with NodeId: {node_id}")
            elif node_class == ua.NodeClass.Variable and display_name.Text == "LastErrorDesc":
                self.last_error_desc = item
                logging.info(f"browse: Found LastErrorDesc node with NodeId: {node_id}")
            elif node_class == ua.NodeClass.Variable and display_name.Text != "ServerCertificate":
                value = await item.read_value()
                logging.info(f"browse: Node: {node_id}, Name: {display_name.Text}, Value: {value}")
                self.nodes_dict[display_name.Text] = item
            

        if not self.write_method:
            logging.error("browse Error: write_to_opc_da method not found")
            return False
        
        
        return True
    
    async def get_server_last_error(self):
        """读取服务器端的 LastErrorStatus 节点"""
        if  not self.last_error_desc :
            logging.error("get_server_last_error: LastErrorStatus node not available")
            return "get_server_last_error: status node not available"
        try:
            # error_code = await self.last_error_code.read_value()
           
            # error_name = STATUS_CODE_NAMES.get(error_code, "UnknownStatusCode")
            error_desc = await self.last_error_desc.read_value()
            # return f"{error_name} ({hex(error_code)}):{error_desc}"
            return f"{error_desc}"
        except Exception as e:
            logging.error(f"get_server_last_error: Failed to read LastErrorStatus: {str(e)}")
            return f"get_server_last_error: Failed to read error status: {str(e)}"



    async def read(self, item_name):
        ua_name = item_name.replace('/', '_')
        if ua_name in self.nodes_dict:
            node = self.nodes_dict[ua_name]
            try:
                value = await node.read_value()
                logging.info(f"Read: {item_name} = {value}")
                return value
            except ua.UaStatusCodeError as e:
                logging.error(f"Read: Failed to read {item_name}: {e}")
                return None
        else:
            logging.debug(f"Read: Node {ua_name} not found")
            return None

    async def write(self, items, values):
            if not self.write_method:
                logging.error("write Error: write_to_opc_da method not available")
                return False

            logging.info("write: Attempting to write values via write_to_opc_da...")
            items_variant = ua.Variant(items, ua.VariantType.String)
            values_variant = ua.Variant([ua.Variant(val) for val in values], ua.VariantType.Variant)

            for attempt in range(3):
                try:
                    logging.info(f"write: Starting write attempt {attempt + 1} for items: {items}")
                    results = await asyncio.wait_for(
                        self.client.nodes.objects.call_method(self.write_method.nodeid, items_variant, values_variant),
                        timeout=120  # 增加到 60 秒
                        
                    )
                   # results = await self.client.nodes.objects.call_method(self.write_method.nodeid, items_variant, values_variant)
                    if not isinstance(results, list):
                        logging.error(f"write:Invalid result type from server: {type(results)}")
                       
                        return False  
                    if len(results) > 1 and not results[0]:
                        error_message = results[1]
                        logging.error(f"write: Server returned error: {error_message}")
                  
                        server_error_status = await self. get_server_last_error()
                        logging.error(f"write: Server error status: {server_error_status}")
                        return False
                    logging.info(f"write:  Write attempt {attempt + 1} succeeded with results: {results}")
                    logging.info(f"write: Write results: {results}")
                   
                
                    return results[0]
                    
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
                    return False
                except Exception as e:
                    logging.error(f"Write:Unexpected error in write attempt {attempt + 1}: {str(e)}")
                    server_error_status = await self. get_server_last_error()
                    logging.error(f"Write:Server error status: {server_error_status}")
                    logging.error(f"Write: Unexpected error: {str(e)}")
                    return False
            logging.error("Write: All write attempts failed due to timeout")
        
            return False

    async def _get_opc_da_folder(self):
        root = self.client.get_root_node()
        objects = self.client.get_objects_node()
        children = await objects.get_children()
        for child in children:
            display_name = await child.read_display_name()
            if display_name.Text == "OPCDA.1":
                return child
        return None

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
        client.__init__(client.name,client.endpoint,client.username,client.password)
        
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
        print(f'print the server from {client.name}...')
        await client.browse()
        print(f'read value to the server from {client.name}...')
        await client.read("V1-IO/AI1_SCI1.EU100")
       
        
        if client.name=='opcuaclient1': 
            print(f"{client.name} transfer client certificate.by call transfer_client_certificate...")
            await client.transfer_client_certificate()
            print(f'write value to the server from {client.name}....')

            write_items = ["V1-IO/AI1_SCI1.EU100","V1-AI-1/FS_CTRL1/MOD_DESC.CV"] 
            write_values = [32764,"welcome"] 
            async with write_lock:  # 使用锁同步写操作
                await client.write(write_items, write_values)
            await asyncio.sleep(1)
            for item in write_items:
                await client.read(item)

        elif client.name=='opcuaclient2': 
            print(f'write value to the server from {client.name}....')
            write_items = ["V1-IO/AI1_SCI1.EU100","V1-AI-1/FS_CTRL1/MOD_DESC.CV"] 
            write_values = [32787,"helloworld"]
            async with write_lock:  # 使用锁同步写操作
                await client.write(write_items, write_values)
            await asyncio.sleep(1)
            for item in write_items:
                await client.read(item)
        else:
           print(f'read value  at {client.name}....')
           await client.read("V1-AI-1/FS_CTRL1/MOD_DESC.CV")
      
           
        
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
    asyncio.run(main())