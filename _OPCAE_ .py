import win32com.client
import pythoncom
import logging

class _OPCAE_:
    def __init__(self, server_name: str = "DeltaV.OPCEventServer.1",node_name='127.0.0.1', client_name: str = "DefaultOPCAEClient"):
        self.server_name = server_name
        self.node_name = node_name
        self.opc_ae = None
        self.connected = False
        self.client_name = client_name
        self.subscription = None

    def connect(self) -> bool:
        """连接到 OPC AE 服务器"""
        logging.debug(f"_OPCAE_: Attempting to connect to {self.server_name}")
        try:
            pythoncom.CoInitialize()
            print(f"Connecting to {self.server_name}...")
            #smust regsiter from C:\Program Files (x86)\Common Files\OPC Foundation\Bin ,find  opc_aeps.dll adn run regsvr32 opc_aeps.dll
            self.opc_ae = win32com.client.Dispatch("Opc_auto_ae.OpcEventServer") #Opc_auto_ae.OpcEventServer
            print(dir(self.opc_ae))
          
            #self.server_name = self.opc_ae.GetOpcEventServers()[0]   #DvOPCAE.exe
        
            print(f"Server name: {self.server_name}")
      
            self.opc_ae.Connect(self.server_name, self.node_name)
         
          
            print(self.opc_ae.ServerName)
            print(f"Server {self.server_name} connected")
            self.connected = True
            logging.info(f"_OPCAE_: Successfully connected to {self.server_name}")
            return True
        except Exception as e:
            logging.error(f"_OPCAE_: Failed to connect to {self.server_name}: {str(e)}")
            return False

    def disconnect(self):
        """断开与 OPC AE 服务器的连接"""
        if self.opc_ae and self.connected:
            try:
                if self.subscription:
                    self.stop_subscription()
                self.opc_ae.Disconnect()
                self.connected = False
                logging.info(f"_OPCAE_: Successfully disconnected from {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCAE_: Failed to disconnect from {self.server_name}: {str(e)}")
            finally:
                self.opc_ae = None
                pythoncom.CoUninitialize()
    def event_callback(events):
        for source, severity, message, timestamp in events:
            print(f"Event: Source={source}, Severity={severity}, Message={message}, Time={timestamp}")

    def subscribe_events(self, callback=event_callback):
        """订阅报警和事件"""
        if not self.connected or not self.opc_ae:
            raise ConnectionError(f"_OPCAE_: Not connected to {self.server_name}")
        
        try:
            self.subscription = self.opc_ae.CreateSubscription()
            self.subscription.IsActive = True
            handler = win32com.client.WithEvents(self.subscription, OPCAEEventHandler)
            handler.callback = callback
            logging.info(f"_OPCAE_: Subscribed to events on {self.server_name}")
        except Exception as e:
            logging.error(f"_OPCAE_: Failed to subscribe to events: {str(e)}")

    def stop_subscription(self):
        """停止事件订阅"""
        if self.subscription:
            try:
                self.subscription.Cancel()
                self.subscription = None
                logging.info(f"_OPCAE_: Event subscription stopped on {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCAE_: Failed to stop subscription: {str(e)}")

class OPCAEEventHandler:
    def __init__(self, callback=None):
        self.callback = callback

    def OnEvent(self, TransactionID, NumEvents, EventData):
        """处理 OPC AE 事件"""
        events = [(data.Source, data.Severity, data.Message, data.EventTime) for data in EventData]
        if self.callback:
            self.callback(events)

def test_opc_ae():
   

    opc_ae = _OPCAE_()  # 替换为实际的 OPC AE 服务器 ProgID
    if opc_ae.connect():
        print("Waiting for events... (Press Ctrl+C to stop)")
      
        # print("Waiting for events... (Press Ctrl+C to stop)")
        # try:
        #     while True:
        #         pythoncom.PumpWaitingMessages()
        # except KeyboardInterrupt:
        opc_ae.disconnect()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_opc_ae()