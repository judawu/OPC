import json
import socket
import datetime
import asyncio
import io
import logging
import struct
from typing import List, Dict, Any, Tuple

import logging
import json
from typing import Dict, List
from asyncua import ua
from asyncua.ua import UaStatusCodeError

class _OPCUAPubSub_:
    def __init__(self, wrapper):
        """Initialize the Pub/Sub manager for the OPC UA server."""
        self.wrapper = wrapper
       
       
        self.pubsub_enabled = False
        self.published_datasets = {}
        self.writer_groups = {}
        self.dataset_writers = {}
        self.publishing_interval = 1000  # Default: 1 second (in milliseconds)
        self.multicast_address = "239.0.0.1"  # Default multicast address
        self.multicast_port = 4840  # Default port
        self.pubsub_node = None  # PublishSubscribe object
        self.published_datasets_folder=None
        self.running = False  # Flag to control publishing loop
        self.sock = None  # UDP socket for publishing
        self.publisher_id = ua.Variant(1, ua.VariantType.UInt16) # Store as UA Variant
        self.published_datasets: Dict[str, Dict[str, Any]] = {}
        self.writer_groups: Dict[str, Any] = {} # Assuming Any is Node or similar
        self.dataset_writers: Dict[str, Any] = {} # Assuming Any is Node or similar
          # Add state for sequence numbers per DataSetWriterId
        self.sequence_numbers: Dict[int, int] = {} # Key: DataSetWriterId, Value: Sequence Number
        logging.info("_OPCUAPubSub_.__init__: Initialized Pub/Sub manager")

    async def setup_pubsub(self):
        """Set up Pub/Sub configuration in the OPC UA server."""
        if self.pubsub_enabled:
            logging.info("_DVUAPubSub_.setup_pubsub: Pub/Sub already enabled")
            return

        try:
             # Access the PublishSubscribe object
            self.pubsub_node = self.wrapper.server.get_node(ua.ObjectIds.PublishSubscribe)
               # Check if the node exists by attempting to read its DisplayName
            try:
                await self.pubsub_node.read_display_name()
            except UaStatusCodeError as e:
                if e.code == ua.StatusCodes.BadNodeIdUnknown:
                    logging.error("_OPCUAPubSub_.setup_pubsub: PublishSubscribe object not found in server address space")
                    raise RuntimeError("PublishSubscribe object not found. Server does not support Pub/Sub.")
                raise  # Re-raise other errors
            self.pubsub_enabled = True
            logging.info("_DVUAPubSub_.setup_pubsub: Pub/Sub enabled with UADP profile")
            self.published_datasets_folder = await self.pubsub_node.get_child("0:PublishedDataSets")
           
            if not self.wrapper.node.pubsub_folder:
                pubsub_folder = await self.wrapper.da_manager.create_folder("Publisher Subscriber")
                self.wrapper.node.pubsub_folder = pubsub_folder
          
            # Add configuration variables
            self.wrapper.node.pubsub_nodes = {
                "Enabled": await pubsub_folder.add_variable(
                    self.wrapper.node.idx, "PubSubEnabled", self.pubsub_enabled, ua.VariantType.Boolean
                ),
                "PublishingInterval": await pubsub_folder.add_variable(
                    self.wrapper.node.idx, "PublishingInterval_ms", self.publishing_interval, ua.VariantType.Float
                ),
                "MulticastAddress": await pubsub_folder.add_variable(
                    self.wrapper.node.idx, "MulticastAddress", self.multicast_address, ua.VariantType.String
                ),
                "MulticastPort": await pubsub_folder.add_variable(
                    self.wrapper.node.idx, "MulticastPort", self.multicast_port, ua.VariantType.UInt16
                )
            }
            for node in self.wrapper.node.pubsub_nodes.values():
                await node.set_writable()

            self.wrapper.node.methods_nodes["configure_pubsub"]=await pubsub_folder.add_method(
                    self.wrapper.node.idx,
                    "configure_pubsub",
                    self.configure_pubsub_moethod,
                   [ua.VariantType.ByteString], [ua.VariantType.Boolean]
                )
            self.wrapper.node.methods_nodes["add_published_dataset"] = await pubsub_folder.add_method(
                self.wrapper.node.idx,
                "add_published_dataset",
                self.add_published_dataset_method,
                [ua.VariantType.ByteString], [ua.VariantType.Boolean]
            )
            self.wrapper.node.methods_nodes["start_pub"] = await pubsub_folder.add_method(
                self.wrapper.node.idx,
                "start_pub",
                self.start_pub_method,
                [], [ua.VariantType.Boolean]
            )
            self.wrapper.node.methods_nodes["stop_pub"] = await pubsub_folder.add_method(
                self.wrapper.node.idx,
                "stop_pub",
                self.stop_pub_method,
                [], [ua.VariantType.Boolean]
            )


            
            logging.debug("_DVUAPubSub_.setup_pubsub: Pub/Sub configuration nodes created")
        except Exception as e:
            logging.error(f"_DVUAPubSub_.setup_pubsub: Failed to enable Pub/Sub: {str(e)}")
            raise

    async def configure_pubsub(self, config: Dict):
        """Configure Pub/Sub settings from a JSON dictionary."""
        try:
            # Update basic settings
            if "publishing_interval" in config:
                self.publishing_interval = float(config["publishing_interval"])
                await self.wrapper.node.pubsub_nodes["PublishingInterval"].write_value(
                    ua.Variant(self.publishing_interval, ua.VariantType.Float)
                )
                logging.info(f"_DVUAPubSub_.configure_pubsub: Updated publishing interval to {self.publishing_interval} ms")

            if "multicast_address" in config:
                self.multicast_address = config["multicast_address"]
                await self.wrapper.node.pubsub_nodes["MulticastAddress"].write_value(self.multicast_address)
                logging.info(f"_DVUAPubSub_.configure_pubsub: Updated multicast address to {self.multicast_address}")

            if "multicast_port" in config:
                self.multicast_port = int(config["multicast_port"])
                await self.wrapper.node.pubsub_nodes["MulticastPort"].write_value(ua.Variant(self.multicast_port, ua.VariantType.UInt16))
                logging.info(f"_DVUAPubSub_.configure_pubsub: Updated multicast port to {self.multicast_port}")

            # Configure published nodes
            if "published_items" in config:
                for dataset_name, items in config["published_items"].items():
                    await self.add_published_dataset(dataset_name, items)

            logging.info("_DVUAPubSub_.configure_pubsub: Configuration applied successfully")
            return True
        except Exception as e:
            logging.error(f"_DVUAPubSub_.configure_pubsub: Error applying configuration: {str(e)}")
            return False

    async def add_published_dataset(self, dataset_name: str, items: List[str]):
        """Add a PublishedDataSet, WriterGroup, and DataSetWriter for publishing."""
        if not self.pubsub_enabled:
            await self.setup_pubsub()

        try:
            # Ensure published_datasets_folder is set
            if self.published_datasets_folder is None:
                logging.error("_OPCUAPubSub_.add_published_dataset: published_datasets_folder not initialized")
                raise RuntimeError("PublishedDataSets folder not initialized. Ensure setup_pubsub completed successfully.")

            # Create PublishedDataSet if it doesn't exist
            if dataset_name not in self.published_datasets:
                # Check for existing PublishedDataSet and clean up if necessary
                existing_datasets = await self.published_datasets_folder.get_children()
                for ds_node in existing_datasets:
                    ds_name = (await ds_node.read_browse_name()).Name
                    if ds_name == dataset_name:
                        await self.published_datasets_folder.delete_nodes([ds_node])
                        logging.debug(f"_OPCUAPubSub_.add_published_dataset: Removed existing PublishedDataSet {ds_name}")

                # Create a folder for the PublishedDataSet
                pds_node = await self.published_datasets_folder.add_object(
                    self.wrapper.node.idx, dataset_name, ua.ObjectIds.PublishedDataItemsType
                )

                # Define DataSetMetaData
                data_set_fields = []
                published_vars = []
                await self.wrapper.da_manager.add_items(items, "Publisher Subscriber")
                for item in items:
                    if item not in self.wrapper.node.nodes:
                        logging.warning(f"_OPCUAPubSub_.add_published_dataset: Node {item} not found in wrapper.nodes")
                        continue
                    current_node = self.wrapper.node.nodes[item]
                    # Add a PublishedVariable to the dataset
                    published_var = ua.PublishedVariableDataType()
                    published_var.PublishedVariable = current_node.nodeid
                    published_var.AttributeId = ua.AttributeIds.Value
                    var_node = await pds_node.add_variable(
                        self.wrapper.node.idx,
                        item,
                        ua.Variant(published_var, ua.VariantType.ExtensionObject),
                        varianttype=ua.VariantType.ExtensionObject
                    )

                    # Define the field metadata
                   
                    field_meta = ua.FieldMetaData()
                    field_meta.Name = item
                    field_meta.DataType = (await current_node.read_data_type()).Identifier  # Get the node's data type
                    field_meta.ValueRank = await current_node.read_value_rank()
                    field_meta.FieldFlags = ua.DataSetFieldFlags(0)  # Adjust flags as needed
                    field_meta.ValueRank = -1
                    data_set_fields.append(field_meta)
                    published_vars.append((item, current_node))
                    logging.debug(f"_OPCUAPubSub_.add_published_dataset: Added field {item} to {dataset_name}")
             
                # Add DataSetMetaData to the PublishedDataSet
                data_set_meta_data = ua.DataSetMetaDataType()
                data_set_meta_data.Name = dataset_name
                data_set_meta_data.Fields = data_set_fields
                data_set_meta_data.ConfigurationVersion.MajorVersion = 1
                data_set_meta_data.ConfigurationVersion.MinorVersion = 1
                await pds_node.add_variable(
                    self.wrapper.node.idx,
                    f"DataSetMetaData_{dataset_name}",
                    ua.Variant(data_set_meta_data, ua.VariantType.ExtensionObject),
                    varianttype=ua.VariantType.ExtensionObject
                )

                self.published_datasets[dataset_name] = {
                    "node": pds_node,
                    "variables": published_vars  # Store node references for publishing
                }
                logging.debug(f"_OPCUAPubSub_.add_published_dataset: Created PublishedDataSet {dataset_name}")

                # Check for existing WriterGroup and clean up if necessary
                existing_writer_groups = await self.pubsub_node.get_children()
                for wg_node in existing_writer_groups:
                    wg_name = (await wg_node.read_browse_name()).Name
                    if wg_name.startswith(f"WriterGroup_{dataset_name}"):
                        await self.pubsub_node.delete_nodes([wg_node])
                        logging.debug(f"_OPCUAPubSub_.add_published_dataset: Removed existing WriterGroup {wg_name}")

                # Create a WriterGroup for this PublishedDataSet
                writer_group_name = f"WriterGroup_{dataset_name}"
                writer_group_node = await self.pubsub_node.add_object(
                    self.wrapper.node.idx, writer_group_name, ua.ObjectIds.WriterGroupType
                )
                # Use a unique BrowseName for PublishingInterval by appending dataset_name
                pub_interval_browse_name = f"PublishingInterval_{dataset_name}"
                pub_interval_node = await writer_group_node.add_variable(
                    self.wrapper.node.idx, pub_interval_browse_name, self.publishing_interval, ua.VariantType.Float
                )
                await pub_interval_node.set_writable()

                # Enable the WriterGroup
                await writer_group_node.add_property(
                    self.wrapper.node.idx, "Enabled", True, ua.VariantType.Boolean
                )
                  # Set the PublisherId for the WriterGroup
                await writer_group_node.add_property(
                    self.wrapper.node.idx, "PublisherId", self.publisher_id, ua.VariantType.UInt16
                )
                # Set the MessageSettings for UADP
                message_settings_node = await writer_group_node.add_object(
                    self.wrapper.node.idx, "MessageSettings", ua.ObjectIds.UadpWriterGroupMessageType
                )
                await message_settings_node.add_variable(
                    self.wrapper.node.idx, f"PublishingOffset_{dataset_name}", 0.0, ua.VariantType.Double
                )
                 # Add TransportSettings to specify UDP multicast
                transport_settings_node = await writer_group_node.add_object(
                    self.wrapper.node.idx, "TransportSettings", ua.ObjectIds.DatagramConnectionTransportDataType  
                )
             
                await transport_settings_node.add_variable(
                    self.wrapper.node.idx, "Address", f"udp://{self.multicast_address}:{self.multicast_port}", ua.VariantType.String
                )
                self.writer_groups[dataset_name] = writer_group_node
                logging.debug(f"_OPCUAPubSub_.add_published_dataset: Created WriterGroup {writer_group_name}")

                # Check for existing DataSetWriter and clean up if necessary
                existing_writers = await writer_group_node.get_children()
                for writer_node in existing_writers:
                    writer_name = (await writer_node.read_browse_name()).Name
                    if writer_name.startswith(f"DataSetWriter_{dataset_name}"):
                        await writer_group_node.delete_nodes([writer_node])
                        logging.debug(f"_OPCUAPubSub_.add_published_dataset: Removed existing DataSetWriter {writer_name}")

                # Create a DataSetWriter under the WriterGroup
                writer_name = f"DataSetWriter_{dataset_name}"
                dataset_writer_node = await writer_group_node.add_object(
                    self.wrapper.node.idx, writer_name, ua.ObjectIds.DataSetWriterType
                )
                # Use a unique BrowseName for DataSetWriterId by appending dataset_name
                writer_id_browse_name = f"DataSetWriterId_{dataset_name}"
                writer_id_node = await dataset_writer_node.add_variable(
                    self.wrapper.node.idx, writer_id_browse_name, 1, ua.VariantType.UInt16
                )
                await writer_id_node.set_writable()

                # Link the DataSetWriter to the PublishedDataSet
                await dataset_writer_node.add_property(
                    self.wrapper.node.idx, "DataSetName", dataset_name, ua.VariantType.String
                )

                # Set the DataSetWriter properties
                await dataset_writer_node.add_property(
                    self.wrapper.node.idx, "Enabled", True, ua.VariantType.Boolean
                )

                # Add MessageSettings for the DataSetWriter
                writer_message_settings = await dataset_writer_node.add_object(
                    self.wrapper.node.idx, "MessageSettings", ua.ObjectIds.UadpDataSetWriterMessageType
                )
                await writer_message_settings.add_variable(
                    self.wrapper.node.idx, f"DataSetOffset_{dataset_name}", 0, ua.VariantType.UInt32
                )

                self.dataset_writers[dataset_name] = dataset_writer_node
                logging.debug(f"_OPCUAPubSub_.add_published_dataset: Created DataSetWriter {writer_name}")

            logging.info(f"_OPCUAPubSub_.add_published_dataset: Prepared PublishedDataSet {dataset_name} for publishing")
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.add_published_dataset: Error creating PublishedDataSet {dataset_name}: {str(e)}")
            raise

    async def start(self):
        """Start publishing for all WriterGroups."""
        if not self.pubsub_enabled:
            await self.setup_pubsub()

        if self.running:
            logging.info("_OPCUAPubSub_.start: Publishing already running")
            return

        try:
            # Set up UDP socket for multicast
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            self.running = True

            # Start the publishing loop
            pubsub_task=asyncio.create_task(self._publish_loop())
            self.wrapper.tasks.append(pubsub_task)
            logging.info("_OPCUAPubSub_.start: Started publishing")
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.start: Error starting publishing: {str(e)}")
            self.running = False
            if self.sock:
                self.sock.close()
                self.sock = None
            raise

    # async def _publish_loop(self):
    #         """Periodically publish data via UDP multicast with a simplified binary format."""
    #         while self.running:
    #             try:
    #                 for dataset_name, dataset_info in self.published_datasets.items():
    #                     # Collect data from all variables in the dataset
    #                     values = []
    #                     for var_name, node in dataset_info["variables"]:
    #                         try:
    #                             value = await node.read_value()
    #                             values.append((var_name, value))
    #                         except Exception as e:
    #                             logging.warning(f"_OPCUAPubSub_._publish_loop: Error reading {var_name}: {str(e)}")
    #                             continue

    #                     # Create a simplified binary message
    #                     message = bytearray()
                        
    #                     # Header: PublisherId (UInt16), DataSetWriterId (UInt16), Number of fields (UInt16)
    #                     message.extend(struct.pack('!H', self.publisher_id))  # PublisherId
    #                     message.extend(struct.pack('!H', 1))  # DataSetWriterId (hardcoded to 1, adjust if needed)
    #                     message.extend(struct.pack('!H', len(values)))  # Number of fields

    #                     # Serialize values (simplified: assume values are basic types like int, float, string)
    #                     for var_name, value in values:
    #                         # Encode variable name (null-terminated string)
    #                         message.extend(var_name.encode('utf-8'))
    #                         message.extend(b'\x00')
                            
    #                         # Encode value (simplified: handle int, float, string)
    #                         if isinstance(value, int):
    #                             message.extend(struct.pack('!B', 1))  # Type: 1 = Int32
    #                             message.extend(struct.pack('!i', value))
    #                         elif isinstance(value, float):
    #                             message.extend(struct.pack('!B', 2))  # Type: 2 = Float
    #                             message.extend(struct.pack('!f', value))
    #                         elif isinstance(value, str):
    #                             message.extend(struct.pack('!B', 3))  # Type: 3 = String
    #                             message.extend(value.encode('utf-8'))
    #                             message.extend(b'\x00')
    #                         else:
    #                             logging.warning(f"_OPCUAPubSub_._publish_loop: Unsupported value type for {var_name}")
    #                             continue

    #                     # Prepend message length
    #                     full_message = struct.pack('!I', len(message)) + message

    #                     # Send the message via UDP multicast
    #                     self.sock.sendto(full_message, (self.multicast_address, self.multicast_port))
    #                     logging.debug(f"_OPCUAPubSub_._publish_loop: Published message {full_message} for {dataset_name}")

    #                 # Wait for the publishing interval
    #                 await asyncio.sleep(self.publishing_interval / 1000.0)

    #             except Exception as e:
    #                 logging.error(f"_OPCUAPubSub_._publish_loop: Error in publishing loop: {str(e)}")
    #                 break

    #         # Cleanup if loop exits
    #         self.running = False
    #         if self.sock:
    #             self.sock.close()
    #             self.sock = None
    #         logging.info("_OPCUAPubSub_._publish_loop: Publishing loop stopped")

    async def _publish_loop(self):
        """Periodically publish data via UDP multicast using UADP encoding."""
        while self.running:
            current_time = asyncio.get_event_loop().time()
            try:
                for dataset_name, dataset_info in self.published_datasets.items():
                    if dataset_name not in self.dataset_writers:
                        logging.warning(f"_OPCUAPubSub_._publish_loop: No DataSetWriter info found for {dataset_name}, skipping.")
                        continue

                    # --- Get DataSetWriter ID ---
                    # Option 1: Retrieve from stored info (RECOMMENDED if you stored it)
                    # writer_info = self.dataset_writers.get(dataset_name)
                    # if not writer_info or "id" not in writer_info:
                    #      logging.warning(f"DataSetWriter ID not found for {dataset_name}")
                    #      continue
                    # dataset_writer_id = writer_info["id"]

                    # Option 2: Read from the node (Slower, but reflects current server state)
                    # try:
                    #     writer_node = self.dataset_writers[dataset_name]["node"] # Assuming node stored
                    #     # Find the 'DataSetWriterId' variable node (adjust Browse path if needed)
                    #     id_node = await writer_node.get_child(f"{self.wrapper.node.idx}:DataSetWriterId_{dataset_name}") # Check exact browse name
                    #     if id_node:
                    #        dataset_writer_id = await id_node.read_value()
                    #     else:
                    #         logging.warning(f"DataSetWriterId node not found for {dataset_name}")
                    #         dataset_writer_id = 1 # Fallback or error
                    # except Exception as e:
                    #     logging.error(f"Error reading DataSetWriterId for {dataset_name}: {e}")
                    #     continue # Skip this dataset for this cycle

                    # Option 3: Use a hardcoded/known ID (Simpler for example, but less robust)
                    dataset_writer_id = 1 # <<< Make sure this matches the configuration in add_published_dataset

                    # --- Collect Data ---
                    values_to_publish = []
                    ordered_vars = dataset_info.get("variables", [])
                    if not ordered_vars:
                         logging.warning(f"No variables configured for dataset {dataset_name}")
                         continue

                    for var_name, node in ordered_vars:
                        try:
                            # Read DataValue to potentially get timestamp and status from source
                            data_value = await node.read_data_value()
                            # We need the value itself for the UADP payload Variant
                            values_to_publish.append(data_value.Value)
                        except Exception as read_err:
                            logging.warning(f"_OPCUAPubSub_._publish_loop: Error reading {var_name}: {read_err}")
                            # Handle error: Maybe publish a null/default value or skip?
                            # For simplicity, let's try to publish None if read fails
                            values_to_publish.append(None) # Or skip the message entirely

                    # --- Serialize to UADP ---
                    try:
                        # Pass the raw values; serialization wraps them in Variants
                        uadp_message = self._serialize_uadp_message(
                            self.publisher_id.Value, # Pass the raw uint16 value
                            dataset_writer_id,
                            values_to_publish
                        )
                    except Exception as ser_err:
                        logging.error(f"_OPCUAPubSub_._publish_loop: Error serializing UADP for {dataset_name}: {ser_err}")
                        continue # Skip sending if serialization fails

                    # --- Send the message via UDP multicast ---
                    if self.sock and uadp_message:
                        try:
                            self.sock.sendto(uadp_message, (self.multicast_address, self.multicast_port))
                            logging.debug(f"_OPCUAPubSub_._publish_loop: Published UADP message for {dataset_name} (WriterID: {dataset_writer_id}), size: {len(uadp_message)}")
                        except Exception as send_err:
                             logging.error(f"_OPCUAPubSub_._publish_loop: Error sending UDP packet: {send_err}")
                             # Consider re-initializing socket or handling network issues

                # --- Wait for the next interval ---
                # Calculate sleep time based on actual processing time
                elapsed_time = asyncio.get_event_loop().time() - current_time
                sleep_duration = max(0, (self.publishing_interval / 1000.0) - elapsed_time)
                await asyncio.sleep(sleep_duration)

            except asyncio.CancelledError:
                logging.info("_OPCUAPubSub_._publish_loop: Publishing loop cancelled.")
                break
            except Exception as e:
                logging.error(f"_OPCUAPubSub_._publish_loop: Error in publishing loop: {e}", exc_info=True)
                # Decide whether to break or continue after errors
                await asyncio.sleep(self.publishing_interval / 1000.0) # Wait before retrying

        # Cleanup if loop exits
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception as sock_err:
                 logging.error(f"Error closing socket: {sock_err}")
            finally:
                self.sock = None
        logging.info("_OPCUAPubSub_._publish_loop: Publishing loop stopped")


    # --- REVISED _serialize_uadp_message ---
    def _serialize_uadp_message(self, publisher_id: int, dataset_writer_id: int, values: List[Any]) -> bytes:
        """
        Serialize data into a simplified UADP NetworkMessage containing one DataSetMessage.

        Args:
            publisher_id: The publisher ID (UInt16).
            dataset_writer_id: The DataSetWriter ID (UInt16).
            values: A list of raw Python values to be published, in the order defined
                    by the DataSetMetaData.

        Returns:
            The UADP message as bytes, or None on error.
        """
        try:
            # Use BytesIO for efficient byte manipulation
            buf = io.BytesIO()

            # --- NetworkMessage Header ---
            # Flags (Byte): Bit 0=PayloadIsDataSetMessageArray=1, Bit 7=PublisherIdEnabled=1 => 0x81
            # Other flags (Security, Group, Timestamps etc.) are 0 for this simple case.
            uadp_flags = 0x81
            buf.write(struct.pack('!B', uadp_flags))

            # PublisherId (UInt16) - Already ensured it's UInt16 Variant's value
            buf.write(struct.pack('!H', publisher_id))

            # ExtendedFlags1/2, GroupHeader, SecurityHeader etc. - Skipped for simplicity

            # --- Payload Header ---
            # Number of DataSetMessages in Payload (Byte) - We send one per call
            buf.write(struct.pack('!B', 1))

            # --- DataSetMessage 1 ---
            # DataSetFlags1 (Byte): Bit 0=Valid=1, Bit 1=Timestamp=1, Bit 5=SequenceNumber=1 => 0x23 ?
            # Let's double check Part 14:
            # Bit 0: Valid Message (1)
            # Bit 1: Timestamp (1)
            # Bit 2: PicoSeconds (0)
            # Bit 3: Status (0)
            # Bit 4: ConfigurationVersion (0)
            # Bit 5: SequenceNumber (1)
            # Result: 0b00100011 = 0x23
            ds_flags1 = 0x23
            buf.write(struct.pack('!B', ds_flags1))

            # DataSetFlags2 (Byte): No KeyFrame or specific flags here.
            ds_flags2 = 0x00
            buf.write(struct.pack('!B', ds_flags2))

            # DataSetWriterId (UInt16)
            buf.write(struct.pack('!H', dataset_writer_id))

            # SequenceNumber (UInt16) - Manage state per writer ID
            # Initialize if not present
            if dataset_writer_id not in self.sequence_numbers:
                self.sequence_numbers[dataset_writer_id] = 0
            # Increment sequence number (handle wrap around)
            self.sequence_numbers[dataset_writer_id] = (self.sequence_numbers[dataset_writer_id] + 1) & 0xFFFF
            seq_num = self.sequence_numbers[dataset_writer_id]
            buf.write(struct.pack('!H', seq_num))

            # Timestamp (DateTime - UADateTime UInt64) - Little Endian!
            now_utc = datetime.datetime.now(datetime.timezone.utc).timestamp()
            buf.write(struct.pack('!d', now_utc))
            # --- DataSet Payload ---
            # Number of Fields (UInt16) - This seems optional in some contexts if metadata known,
            # but often included for clarity or if DataSetFlags1 doesn't guarantee structure.
            # Let's include it. Check if this is standard practice for UADP *data* messages.
            # Part 14, 7.2.2.3.3: "The number of Fields is defined by the DataSetMetaData..."
            # It implies the count isn't explicitly needed here if metadata is fixed.
            # However, some examples show it. Let's *omit* it for now based on the spec quote.
            # If issues arise, add: buf.write(struct.pack('!H', len(values)))

            # Field Values (Encoded Variants)
            for value in values:
                try:
                    # Create a ua.Variant. The library should handle type mapping.
                    # Handle potential None values from read errors if necessary
                    if value is None:
                        # Encode ua.Variant with Null status or skip?
                        # Let's create a Variant with no value (should encode as Null)
                        variant_to_encode = ua.Variant(None)
             
                    else:
                        # The library's Variant constructor often guesses the type,
                        # but explicitly setting it can be safer if the source type is ambiguous.
                        # For simplicity here, we let it guess unless it's a datetime.
                        variant_to_encode = ua.Variant(value)

                    buf.write(ua.ua_binary.variant_to_binary(variant_to_encode))
                 
                except Exception as enc_err:
                    logging.error(f"Failed to encode value '{value}' (Type: {type(value)}) as Variant: {enc_err}", exc_info=True)
                    # How to handle partial message? Best to abort serialization.
                    return None # Indicate serialization failure

            # --- Finalize ---
            return buf.getvalue()

        except Exception as e:
            logging.error(f"Error during UADP message serialization: {e}", exc_info=True)
            return None


    async def stop(self):
        """Stop all Pub/Sub activities."""
        try:
            # Stop the publishing loop
            self.running = False
            await asyncio.sleep(0.1)  # Give the loop a chance to exit

            # Clean up UDP socket
            if self.sock:
                self.sock.close()
                self.sock = None

            # Delete WriterGroups and DataSetWriters
            for dataset_name in list(self.writer_groups.keys()):
                writer_group = self.writer_groups.pop(dataset_name)
                dataset_writer = self.dataset_writers.pop(dataset_name, None)
                # Delete DataSetWriter and its children first
                if dataset_writer:
                    children = await dataset_writer.get_children()
                    if children:
                        await dataset_writer.delete_nodes(children)
                    await writer_group.delete_nodes([dataset_writer])
                    logging.debug(f"_OPCUAPubSub_.stop: Deleted DataSetWriter for {dataset_name}")
                # Delete WriterGroup and its children
                children = await writer_group.get_children()
                if children:
                    await writer_group.delete_nodes(children)
                await self.pubsub_node.delete_nodes([writer_group])
                logging.debug(f"_OPCUAPubSub_.stop: Deleted WriterGroup for {dataset_name}")

            # Delete PublishedDataSets
            for dataset_name, dataset_info in list(self.published_datasets.items()):
                if self.published_datasets_folder:
                    # Delete children of the PublishedDataSet first
                    children = await dataset_info["node"].get_children()
                    if children:
                        await dataset_info["node"].delete_nodes(children)
                    await self.published_datasets_folder.delete_nodes([dataset_info["node"]])
                    logging.debug(f"_OPCUAPubSub_.stop: Deleted PublishedDataSet {dataset_name}")
                else:
                    logging.warning(f"_OPCUAPubSub_.stop: published_datasets_folder not available, skipping deletion of {dataset_name}")

            self.published_datasets.clear()
            self.pubsub_enabled = False
            await self.wrapper.node.pubsub_nodes["Enabled"].write_value(False)
            logging.info("_OPCUAPubSub_.stop: Pub/Sub stopped")
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.stop: Error stopping Pub/Sub: {str(e)}")

    
    async def configure_pubsub_moethod(self, parent, json_data_variant) -> list:
                """
                OPC UA Method: Configure Pub/Sub settings from a JSON string.
                Inputs:
                    json_data (ByteString): JSON string, e.g.,
                                        {
                                            "publishing_interval": 1000,
                                            "multicast_address": "239.0.0.1",
                                            "multicast_port": 4840,
                                            "published_nodes": {
                                                "Dataset1": ["Parameter1", "Parameter2"]
                                            }
                                        }
                Returns:
                    [Boolean]: True if successful, False otherwise.
                """
                userrole = await self.wrapper.security._get_current_userrole()
                if not self.wrapper.user_manager.check_method_permission(50, userrole):
                    logging.warning(f"_DVUAPubSub_.configure_pubsub: Unauthorized attempt to configure Pub/Sub")
                    await self.wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
                    await self.wrapper.node.last_error_desc.write_value("Unauthorized attempt to configure Pub/Sub")
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

                try:
                    json_data = json_data_variant.Value.decode('utf-8')
                    config = json.loads(json_data)
                    logging.debug(f"_OPCDAWrapper_.configure_pubsub: Received config: {json.dumps(config, indent=2)}")
                    if not isinstance(config, dict):
                        logging.error("_OPCDAWrapper_.configure_pubsub: Invalid config format, expected a dictionary")
                        await self.wrapper.node.last_error_desc.write_value("Invalid config format, expected a dictionary")
                        return [ua.Variant(False, ua.VariantType.Boolean)]
                    
                    success = await self.configure_pubsub(config)
                    if success:
                        logging.info("_OPCDAWrapper_.configure_pubsub: Successfully configured Pub/Sub")
                        return [ua.Variant(True, ua.VariantType.Boolean)]
                    else:
                        logging.error("_OPCDAWrapper_.configure_pubsub: Failed to configure Pub/Sub")
                        await self.wrapper.node.last_error_desc.write_value("Failed to configure Pub/Sub")
                        return [ua.Variant(False, ua.VariantType.Boolean)]
                except json.JSONDecodeError as e:
                    logging.error(f"_OPCDAWrapper_.configure_pubsub: Invalid JSON format: {str(e)}")
                    await self.wrapper.node.last_error_desc.write_value(f"Invalid JSON format: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]
                except Exception as e:
                    logging.error(f"_OPCDAWrapper_.configure_pubsub: Error processing JSON: {str(e)}")
                    await self.wrapper.node.last_error_desc.write_value(f"Error processing JSON: {str(e)}")
                    return [ua.Variant(False, ua.VariantType.Boolean)]
    
    async def add_published_dataset_method(self, parent, json_data_variant) -> list:
        """
        OPC UA Method: Add a PublishedDataSet with specified nodes.
        Inputs:
            json_data (ByteString): JSON string containing a dictionary with dataset_name (string) and items (list of strings),
                                    e.g., '{"dataset_name": "PlantMetrics", "items": ["Temperature", "Pressure"]}'.
        Returns:
            [Boolean]: True if successful, False otherwise.
        """
        userrole = await self.wrapper.security._get_current_userrole()
        if not self.wrapper.user_manager.check_method_permission(50, userrole):
            logging.warning(f"_OPCUAPubSub_.add_published_dataset_method: Unauthorized attempt to add PublishedDataSet")
            await self.wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.wrapper.node.last_error_desc.write_value("Unauthorized attempt to add PublishedDataSet")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

        try:
            json_data = json_data_variant.Value.decode('utf-8')
            config = json.loads(json_data)
            logging.debug(f"_OPCUAPubSub_.add_published_dataset_method: Received config: {json.dumps(config, indent=2)}")

            # Validate JSON structure
            if not isinstance(config, dict):
                logging.error("_OPCUAPubSub_.add_published_dataset_method: Invalid config format, expected a dictionary")
                await self.wrapper.node.last_error_desc.write_value("Invalid config format, expected a dictionary")
                return [ua.Variant(False, ua.VariantType.Boolean)]
            
            if "dataset_name" not in config or "items" not in config:
                logging.error("_OPCUAPubSub_.add_published_dataset_method: Missing required keys: dataset_name or items")
                await self.wrapper.node.last_error_desc.write_value("Missing required keys: dataset_name or items")
                return [ua.Variant(False, ua.VariantType.Boolean)]
            
            dataset_name = config["dataset_name"]
            items = config["items"]
            
            if not isinstance(dataset_name, str):
                logging.error("_OPCUAPubSub_.add_published_dataset_method: dataset_name must be a string")
                await self.wrapper.node.last_error_desc.write_value("dataset_name must be a string")
                return [ua.Variant(False, ua.VariantType.Boolean)]
            
            if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
                logging.error("_OPCUAPubSub_.add_published_dataset_method: items must be a list of strings")
                await self.wrapper.node.last_error_desc.write_value("items must be a list of strings")
                return [ua.Variant(False, ua.VariantType.Boolean)]

            await self.add_published_dataset(dataset_name, items)
            logging.info(f"_OPCUAPubSub_.add_published_dataset_method: Successfully added PublishedDataSet {dataset_name}")
            return [ua.Variant(True, ua.VariantType.Boolean)]
        except json.JSONDecodeError as e:
            logging.error(f"_OPCUAPubSub_.add_published_dataset_method: Invalid JSON format: {str(e)}")
            await self.wrapper.node.last_error_desc.write_value(f"Invalid JSON format: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.add_published_dataset_method: Error adding PublishedDataSet: {str(e)}")
            await self.wrapper.node.last_error_desc.write_value(f"Error adding PublishedDataSet: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]

    async def start_pub_method(self, parent) -> list:
        """
        OPC UA Method: Start Pub/Sub functionality.
        Returns:
            [Boolean]: True if successful, False otherwise.
        """
        userrole = await self.wrapper.security._get_current_userrole()
        if not self.wrapper.user_manager.check_method_permission(50, userrole):
            logging.warning(f"_OPCUAPubSub_.start_pub_method: Unauthorized attempt to start Pub/Sub")
            await self.wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.wrapper.node.last_error_desc.write_value("Unauthorized attempt to start Pub/Sub")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

        try:
            if not self.pubsub_enabled:
                await self.setup_pubsub()
            await self.start()
            logging.info("_OPCUAPubSub_.start_pub_method: Successfully started Pub/Sub")
            return [ua.Variant(True, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.start_pub_method: Error starting Pub/Sub: {str(e)}")
            await self.wrapper.node.last_error_desc.write_value(f"Error starting Pub/Sub: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]

    async def stop_pub_method(self, parent) -> list:
        """
        OPC UA Method: Stop Pub/Sub functionality.
        Returns:
            [Boolean]: True if successful, False otherwise.
        """
        userrole = await self.wrapper.security._get_current_userrole()
        if not self.wrapper.user_manager.check_method_permission(50, userrole):
            logging.warning(f"_OPCUAPubSub_.stop_pub_method: Unauthorized attempt to stop Pub/Sub")
            await self.wrapper.node.last_error_code.write_value(ua.StatusCodes.BadUserAccessDenied)
            await self.wrapper.node.last_error_desc.write_value("Unauthorized attempt to stop Pub/Sub")
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUserAccessDenied)

        try:
            await self.stop()
            logging.info("_OPCUAPubSub_.stop_pub_method: Successfully stopped Pub/Sub")
            return [ua.Variant(True, ua.VariantType.Boolean)]
        except Exception as e:
            logging.error(f"_OPCUAPubSub_.stop_pub_method: Error stopping Pub/Sub: {str(e)}")
            await self.wrapper.node.last_error_desc.write_value(f"Error stopping Pub/Sub: {str(e)}")
            return [ua.Variant(False, ua.VariantType.Boolean)]
