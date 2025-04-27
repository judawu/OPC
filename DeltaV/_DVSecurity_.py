import os
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
from asyncua.server.users import  UserRole  # Correct import for v1.1.5
import socket
import datetime
import logging
from asyncua import ua
class _OPCUASecurity_:
        def __init__(self,wrapper):
            self._wrapper = wrapper
           
            self._cert_dir = os.path.join(wrapper._base_dir, "cert")
            self._initial_cert_path = os.path.join(self._cert_dir, "server_init_cert.pem")
            self._initial_key_path = os.path.join(self._cert_dir, "server_init_key.pem")
            self._cert_path = os.path.join(self._cert_dir, "server_cert.pem")
            self._key_path = os.path.join(self._cert_dir, "server_key.pem")
            self._trustedcert_dir=os.path.join(self._cert_dir, "trusted")
           
            self.security_policies = None # 运行时动态填充


        async def generate_self_signed_cert(self,cert_path:str=None, key_path:str=None):
                if cert_path is None or key_path is None:
                    cert_path= self._cert_path
                    key_path=self._key_path
                name =  self._wrapper._name
                application_uri=self._wrapper.application_uri
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
                    if  self._wrapper.node.last_error_desc is not None:
                        await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.generate_self_signed_cert: Failed to generate certificate: {str(e)}")
                        raise
        async def restore_initial_certificate(self,parent=None):
                userrole = await self._get_current_userrole()
                if not  self._wrapper.user_manager.check_method_permission(12, userrole):
                    logging.warning(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate by")
                    if  self._wrapper.node.last_error_code is not None and self._wrapper.node.last_error_desc is not None:
                        await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                        await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Unauthorized attempt to call restore_initial_certificate ")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
                try:
                    await  self._wrapper.server.load_certificate(self._initial_cert_path)
                    await  self._wrapper.server.load_private_key(self._initial_key_path)
                    self._wrapper.server.set_security_policy(self.security_policies)
                    with open(self._initial_cert_path, "rb") as f:
                        
                        await  self._wrapper.node.cert_node.write_value(f.read())
                    logging.info("_OPCDAWrapper_.restore_initial_certificate:Restored initial certificate and security policies")
                    return [ua.Variant(True, ua.VariantType.Boolean)]
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate: {str(e)}")
                    if  self._wrapper.node.last_error_desc is not None: 
                        await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.restore_initial_certificate:Failed to restore initial certificate:,Error Occured: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]     
        async def add_client_certificate(self,parent,client_cert_variant):
            """动态添加客户端证书到信任列表"""
            userrole = await self._get_current_userrole()
            if not  self._wrapper.user_manager.check_method_permission(50, userrole):
                    logging.warning(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate")
                    await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Unauthorized attempt to call add_client_certificate ")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
            client_cert_data = client_cert_variant.Value
            
            # 解析证书以确认有效性
            try:
                cert = x509.load_pem_x509_certificate(client_cert_data)
                logging.debug(f"_OPCDAWrapper_.add_client_certificate:Received client certificate: Subject={cert.subject}, Serial={cert.serial_number}")
            except Exception as e:
                logging.error(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate: {e}")
                await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.add_client_certificate:Invalid client certificate,Error Occured: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]

            # 定义信任证书路径
            trust_dir = self.trustedcert_dir # 替换为你的信任目录
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
            
                if not  self._wrapper.user_manager.check_method_permission(4, userrole):
                    logging.warning(f"CustomSecurity.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                    await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await  self._wrapper.node.last_error_desc.write_value(f"CustomSecurity.generate_server_certificate:Unauthorized attempt to call generate_server_certificate ")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
                
                try:
                
                    await self.generate_self_signed_cert()
                
                    return [ua.Variant(True, ua.VariantType.Boolean)]  # 正确返回 OPC UA Variant 列表
                
                except Exception as e:
                    logging.error(f"CustomSecurity.generate_server_certificate:Failed to generate certificate: {str(e)}")
                    await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.generate_server_certificate:FFailed to generate certificate,Error Occured: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表
        async def set_server_policy(self, parent, security_policy_variant, sign_and_encrypt_variant):
                userrole = await self._get_current_userrole()
            
                if not  self._wrapper.user_manager.check_method_permission(12, userrole):
                    logging.warning("_OPCDAWrapper_.set_server_policy:Unauthorized attempt to call set_server_policy")
                    await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await  self._wrapper.node.last_error_desc.write_value(f"_OPCDAWrapper_.set_server_policy:nauthorized attempt to call set_server_policy ")
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
                    
                    logging.debug(f"_OPCDAWrapper_.set_server_policy:Updated security policy to {security_policy}:{'SignAndEncrypt' if sign_and_encrypt else 'Sign'}")
                
                    self._wrapper.server.set_security_policy(self.security_policies)
                    logging.debug(f"_OPCDAWrapper_.set_server_policy:Security policies set: {[policy.URI for policy in self.security_policies]}")
                    return [ua.Variant(True, ua.VariantType.Boolean)]  # 失败时也返回列表
                
            
                
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_:Failed to update Security policies: {str(e)}")
                    await  self._wrapper.node.last_error_desc.write_value(f"Failed to update Security policies: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]  # 失败时也返回列表
        async def _get_current_userrole(self):
            # 默认用户角色，假设未识别时为最低权限（如 Anonymous）
                userrole = 100  # 或根据需求改为其他默认值，例如 12 表示 Anonymous

                # 步骤 1：尝试获取外部客户端的 userrole
                client_addr = None
                if hasattr( self._wrapper.server.iserver, 'asyncio_transports') and  self._wrapper.server.iserver.asyncio_transports:
                    transport =  self._wrapper.server.iserver.asyncio_transports[-1]
                    client_addr = transport.get_extra_info('peername') or ('unknown', 0)
                    for session_id, session_info in  self._wrapper.user_manager.connected_clients["sessions"].items():
                        if session_info["client_addr"] == client_addr:
                            userrole = session_info["userrole"]
                            logging.debug(f"CustomSecurity._get_current_userrole: Found external client session, userrole={userrole}, client_addr={client_addr}")
                            return userrole

                # 步骤 2：如果没有外部客户端连接，检查服务器内部会话
                if hasattr( self._wrapper.server.iserver, 'isession') and  self._wrapper.server.iserver.isession:
                    session_user =  self._wrapper.server.iserver.isession.user
                    if session_user:
                        # 根据 UserRole 映射到你的自定义 userrole
                        role_map = {
                            UserRole.Admin: 0,    # 假设 Admin 映射到 deltavadmin (最高权限)
                            UserRole.User: 15,    
                            UserRole.Anonymous: 50  
                        }
                        userrole = role_map.get(session_user.role, 100)  # 默认匿名用户
                        logging.debug(f"CustomSecurity._get_current_userrole: No external client, using internal session user, role={session_user.role}, mapped userrole={userrole}")
                        return userrole

                # 步骤 3：如果仍然没有找到用户角色，返回默认值
                logging.debug(f"CustomSecurity._get_current_userrole: No client or session found, returning default userrole={userrole}")
                return userrole
        async def get_connected_clients(self, parent) -> list:
                """
                OPC UA 方法：返回当前连接的客户端信息。
                返回值：[String] - JSON 格式的 connected_clients 数据
                """
                userrole = await self._get_current_userrole()
                if not  self._wrapper.user_manager.check_method_permission(50, userrole):  # 限制为 OPERATE 或更高权限
                    logging.warning(f"CustomSecurity_.get_connected_clients: Unauthorized attempt to query clients")
                    await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await  self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to query clients")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)
                clients_json = await  self._wrapper.user_manager.query_connected_clients()
                return [ua.Variant(clients_json, ua.VariantType.String)]
        async def disconnect_client(self, parent, session_id_variant) -> list:
            """
            OPC UA 方法：根据 session_id 断开客户端连接。
            输入参数：session_id (String)
            返回值：[Boolean] - True 表示成功，False 表示失败
            """
            userrole = await self._get_current_userrole()
            if not  self._wrapper.user_manager.check_method_permission(12, userrole):  # 限制为 Admin 权限 (userrole <= 0)
                logging.warning(f"CustomSecurity.disconnect_client: Unauthorized attempt to disconnect client")
                await  self._wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                await  self._wrapper.node.last_error_desc.write_value("Unauthorized attempt to disconnect client")
                raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

            session_id = session_id_variant.Value
            try:
                success = await  self._wrapper.user_manager.disconnect_session(self._wrapper.server.iserver, session_id)
                if success:
                    logging.debug(f"CustomSecurity.disconnect_client: Successfully disconnected session {session_id}")
                    return [ua.Variant(True, ua.VariantType.Boolean)]
                else:
                    logging.warning(f"CustomSecurity.disconnect_client: Failed to disconnect session {session_id}")
                    await  self._wrapper.node.last_error_desc.write_value(f"Failed to disconnect session {session_id}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]
            except Exception as e:
                logging.error(f"CustomSecurity.disconnect_client: Error disconnecting session {session_id}: {str(e)}")
                await  self._wrapper.node.last_error_desc.write_value(f"Error disconnecting session {session_id}: {str(e)}")
                return [ua.Variant(False, ua.VariantType.Boolean)]
