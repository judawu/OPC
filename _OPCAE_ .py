import win32com.client
import pythoncom
import logging

class _OPCAE_:
    def __init__(self, server_name="DeltaV.OPCEventServer.1", node_name="127.0.0.1", client_name="DefaultOPCAEClient"):
        self.server_name = server_name
        self.node_name = node_name
        self.opc_ae = None
        self.connected = False
        self.client_name = client_name
        self.subscription = None
        self.handler = None

    def connect(self) -> bool:
        """Connect to the OPC AE server."""
        logging.debug(f"_OPCAE_: Attempting to connect to {self.server_name}")
        try:
            pythoncom.CoInitialize()
            self.opc_ae = win32com.client.Dispatch("Opc_auto_ae.OpcEventServer")
            servers = self.opc_ae.GetOpcEventServers()
            if servers:
                self.server_name = servers[0]
            print(f"Server name: {self.server_name}")
            self.opc_ae.Connect(self.server_name, self.node_name)
            print(f"Connected to {self.server_name} v{self.opc_ae.MajorVersion}.{self.opc_ae.MinorVersion} by {self.opc_ae.VendorInfo}")
            print(f"Server State: {self.opc_ae.ServerState}")
            self.connected = True
            logging.info(f"_OPCAE_: Successfully connected to {self.server_name}")
            return True
        except Exception as e:
            logging.error(f"_OPCAE_: Failed to connect to {self.server_name}: {str(e)}")
            return False

    def disconnect(self):
        """Disconnect from the OPC AE server and release resources."""
        if self.connected and self.opc_ae:
            try:
                if self.subscription:
                    self.stop_subscription()
                self.opc_ae.Disconnect()
                self.connected = False
                logging.info(f"_OPCAE_: Successfully disconnected from {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCAE_: Failed to disconnect from {self.server_name}: {str(e)}")
            finally:
                # Forcefully release COM object
                if self.opc_ae:
                    self.opc_ae = None
                pythoncom.CoUninitialize()
                logging.debug(f"_OPCAE_: COM resources released")

    def event_callback(self, events):
        """Default callback for events."""
        for source, severity, message, timestamp in events:
            print(f"Event: Source={source}, Severity={severity}, Message={message}, Time={timestamp}")

    def subscribe_events(self, callback=None, areas=None, severity_min=1, severity_max=1000):
        """Subscribe to alarms and events."""
        if not self.connected or not self.opc_ae:
            raise ConnectionError(f"_OPCAE_: Not connected to {self.server_name}")

        try:
            subscriptions = self.opc_ae.OpcEventSubscriptions
            print(f"OpcEventSubscriptions methods: {dir(subscriptions)}")
            print(f"Default BufferTime: {subscriptions.DefaultBufferTime}, Default MaxSize: {subscriptions.DefaultMaxSize}")
            print(f"Existing subscription count: {subscriptions.Count}")

            if subscriptions.Count > 0:
                print("Using existing subscription...")
                self.subscription = subscriptions.Item(1)  # 1-based index
            else:
                print("No existing subscriptions. Attempting to create a new one...")
                try:
                    self.subscription = subscriptions.Add(subscriptions.DefaultBufferTime)
                    print(f"Subscription created with BufferTime={subscriptions.DefaultBufferTime}")
                except Exception as e:
                    logging.warning(f"Add({subscriptions.DefaultBufferTime}) failed: {str(e)}. Trying Add()...")
                    self.subscription = subscriptions.Add()
                    print("Subscription created with default settings")

            print(f"Subscription object: {dir(self.subscription)}")
            print(f"IsActive before: {self.subscription.IsActive}")
            self.subscription.IsActive = True
            print(f"IsActive after: {self.subscription.IsActive}")

            if areas:
                try:
                    self.subscription.FiltersByArea = areas
                    print(f"Applied area filter: {areas}")
                except Exception as e:
                    logging.warning(f"Failed to set area filter: {str(e)}")
            if severity_min or severity_max:
                try:
                    self.subscription.FiltersBySeverity = (severity_min, severity_max)
                    print(f"Applied severity filter: {severity_min}-{severity_max}")
                except Exception as e:
                    logging.warning(f"Failed to set severity filter: {str(e)}")

            self.handler = win32com.client.WithEvents(self.subscription, OPCAEEventHandler)
            self.handler.callback = callback if callback else self.event_callback
            logging.info(f"_OPCAE_: Subscribed to events on {self.server_name}")
        except Exception as e:
            logging.error(f"_OPCAE_: Failed to subscribe to events: {str(e)}")
            raise

    def stop_subscription(self):
        """Stop the event subscription."""
        if self.subscription:
            try:
                self.subscription.Cancel()
                self.subscription = None
                self.handler = None
                logging.info(f"_OPCAE_: Event subscription stopped on {self.server_name}")
            except Exception as e:
                logging.error(f"_OPCAE_: Failed to stop subscription: {str(e)}")

class OPCAEEventHandler:
    def __init__(self, callback=None):
        self.callback = callback

    def OnEvent(self, TransactionID, NumEvents, EventData):
        """Handle OPC AE events."""
        events = [(data.Source, data.Severity, data.Message, data.EventTime) for data in EventData]
        if self.callback:
            self.callback(events)

def test_opc_ae():
    opc_ae = _OPCAE_()
    try:
        if opc_ae.connect():
            print("Connected successfully.")
            print("Subscribing to events... (Press Ctrl+C to stop)")
            test_areas = ["PlantArea1"]  # Replace with a valid area
            opc_ae.subscribe_events(areas=test_areas, severity_min=500)
            while True:
                pythoncom.PumpWaitingMessages()
    except KeyboardInterrupt:
        print("Disconnecting...")
    finally:
        opc_ae.disconnect()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_opc_ae()