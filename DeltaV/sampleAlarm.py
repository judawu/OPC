import asyncio
import logging
from datetime import datetime, timezone

from asyncua import Server, ua
from asyncua.ua.uaerrors import BadTypeMismatch

# Configuración de logging
logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger('asyncua')

async def main():
    # 1. Inicializar Servidor
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4841")
    server.set_server_name("My Alarm Server")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    # 2. Registrar Namespace
    uri = "http://example.org/alarmdemo"
    idx = await server.register_namespace(uri)
    _logger.info(f"Namespace registered with index {idx} and URI '{uri}'")

    # Habilitar notificación de eventos también en el objeto Server (i=85)
    try:
        await server.nodes.server.write_attribute(
            ua.AttributeIds.EventNotifier,
            ua.DataValue(ua.Variant(ua.EventNotifierType.SubscribeToEvents, ua.VariantType.Byte))
        )
        _logger.info(f"Set EventNotifier for Server Node ({server.nodes.server.nodeid})")
    except Exception as e:
        _logger.warning(f"Could not set EventNotifier for Server node: {e}")

    # 3. Crear Device Node
    device_node = await server.nodes.objects.add_object(idx, "MyDevice")
    _logger.info(f"Device Node created: {device_node.nodeid}")

    # 4. Habilitar EventNotifier en Device Node
    await device_node.write_attribute(
        ua.AttributeIds.EventNotifier,
        ua.DataValue(ua.Variant(ua.EventNotifierType.SubscribeToEvents, ua.VariantType.Byte))
    )
    _logger.info(f"Set EventNotifier for {device_node.nodeid}")

    # 5. Obtener AlarmConditionType
    try:
        alarm_type_node = await server.nodes.root.get_child([
            "0:Types", "0:EventTypes", "0:BaseEventType",
            "0:ConditionType", "0:AcknowledgeableConditionType", "0:AlarmConditionType"
        ])
        _logger.info(f"Found AlarmConditionType Node: {alarm_type_node.nodeid}")
    except Exception as e:
        _logger.error(f"Could not find standard AlarmConditionType node: {e}")
        return

    # 6. Crear Instancia de Alarma
    alarm_node = await device_node.add_object(idx, "MyOverheatAlarm", alarm_type_node.nodeid)
    _logger.info(f"Alarm instance created: {alarm_node.nodeid} (Name: MyOverheatAlarm)")

    # 7. Obtener Sub-nodos de Alarma
    try:
        enabled_state_node = await alarm_node.get_child("EnabledState")
        enabled_state_id_node = await enabled_state_node.get_child("Id")
        active_state_node = await alarm_node.get_child("ActiveState")
        active_state_id_node = await active_state_node.get_child("Id")
        acked_state_node = await alarm_node.get_child("AckedState")
        acked_state_id_node = await acked_state_node.get_child("Id")
        confirmed_state_node = await alarm_node.get_child("ConfirmedState")
        confirmed_state_id_node = await confirmed_state_node.get_child("Id")
        retain_node = await alarm_node.get_child("Retain")
        severity_node = await alarm_node.get_child("Severity")
        message_node = await alarm_node.get_child("Message")
        condition_name_node = await alarm_node.get_child("ConditionName")
        _logger.info("Successfully retrieved essential alarm sub-nodes.")
    except Exception as e:
        _logger.error(f"Failed to get essential sub-nodes for alarm {alarm_node.nodeid}: {e}")
        return

    # 8. Inicializar Propiedades de Alarma
    try:
        await enabled_state_id_node.write_value(True)
        await active_state_id_node.write_value(False)
        await acked_state_id_node.write_value(True)
        await confirmed_state_id_node.write_value(True)
        await retain_node.write_value(False)
        await severity_node.write_value(ua.Variant(0, ua.VariantType.UInt16))
        await message_node.write_value(ua.LocalizedText("Alarm Initialized"))
        alarm_browse_name_obj = await alarm_node.read_browse_name()
        alarm_browse_name = alarm_browse_name_obj.Name
        await condition_name_node.write_value(alarm_browse_name)
        _logger.info(f"Initialized properties for alarm '{alarm_browse_name}' ({alarm_node.nodeid})")
    except BadTypeMismatch as e:
        _logger.error(f"Type mismatch error during initialization for {alarm_node.nodeid}: {e}. Check node data types.", exc_info=True)
        return
    except Exception as e:
        _logger.error(f"Error initializing properties for alarm {alarm_node.nodeid}: {e}", exc_info=True)
        return

    # 9. Crear Generador de Eventos
    generator = await server.get_event_generator(alarm_type_node, emitting_node=device_node)
    _logger.info("Event generator created.")

    # 10. Iniciar Servidor y Bucle Principal
    async with server:
        print(f"🚀 Server started at endpoint: {server.endpoint.geturl()}")
      
        print(f"   Device NodeId: {device_node.nodeid}")
        print(f"   Alarm NodeId: {alarm_node.nodeid} (Name: {alarm_browse_name})")
        print(f"   Namespace Index: {idx}, URI: {uri}")
        print("\n📢 Simulating alarm state change every 10 seconds (Active <-> Inactive)...")

        is_active = False

        while True:
            await asyncio.sleep(10)

            try:
                now = datetime.now(timezone.utc)
                is_active = not is_active

                # --- Actualizar estado del objeto de alarma ---
                if is_active:
                    _logger.info(f"{now} - Setting Alarm State to ACTIVE")
                    await active_state_id_node.write_value(True)
                    await acked_state_id_node.write_value(False)
                    await confirmed_state_id_node.write_value(False)
                    await retain_node.write_value(True) # <<< Retain = True
                    await severity_node.write_value(ua.Variant(800, ua.VariantType.UInt16))
                    await message_node.write_value(ua.LocalizedText("🔥 Overheat Alarm is ACTIVE"))
                    await active_state_node.write_value(ua.LocalizedText("Active"))
                    await acked_state_node.write_value(ua.LocalizedText("Unacknowledged"))
                    await confirmed_state_node.write_value(ua.LocalizedText("Unconfirmed"))
                else:
                    _logger.info(f"{now} - Setting Alarm State to INACTIVE (ReturnToNormal)")
                    await active_state_id_node.write_value(False)
                    await retain_node.write_value(False) # <<< Retain = False
                    await severity_node.write_value(ua.Variant(0, ua.VariantType.UInt16))
                    await message_node.write_value(ua.LocalizedText("✅ Overheat Alarm is Inactive (Cleared)"))
                    await active_state_node.write_value(ua.LocalizedText("Inactive"))
                    acked_status = await acked_state_id_node.read_value()
                    await acked_state_node.write_value(ua.LocalizedText("Acknowledged" if acked_status else "Unacknowledged"))
                    confirmed_status = await confirmed_state_id_node.read_value()
                    await confirmed_state_node.write_value(ua.LocalizedText("Confirmed" if confirmed_status else "Unconfirmed"))

                # --- Configurar y disparar evento ---
                _logger.info(f"Triggering event for state: {'Active' if is_active else 'Inactive'}")
                event = generator.event

                event.EventType = alarm_type_node.nodeid
                event.SourceNode = alarm_node.nodeid
                event.SourceName = alarm_browse_name
                event.ConditionId = alarm_node.nodeid
                event.ConditionName = alarm_browse_name

                # ***** NUEVO: Añadir ConditionClassId y ConditionClassName *****
                base_condition_class_id = ua.NodeId(ua.ObjectIds.BaseConditionClassType) # i=11173
                event.ConditionClassId = base_condition_class_id
                event.ConditionClassName = ua.LocalizedText("BaseConditionClass")
                # *************************************************************

                event.BranchId = ua.NodeId(ua.ObjectIds.Null)
                event.Time = now
                event.ReceiveTime = now
                event.LocalTime = ua.TimeZoneDataType(Offset=0, DaylightSavingInOffset=False)
                event.Retain = is_active

                event.Severity = await severity_node.read_value()
                event.Message = await message_node.read_value()
                event.EnabledState = ua.LocalizedText("Enabled")
                event.ActiveState = await active_state_node.read_value()
                event.AckedState = await acked_state_node.read_value()
                event.ConfirmedState = await confirmed_state_node.read_value()

                await generator.trigger()
                print(f"🔔 Event triggered for '{alarm_browse_name}' -> State: {'Active' if is_active else 'Inactive'}")

            except BadTypeMismatch as e:
                _logger.error(f"Type mismatch error during alarm loop for {alarm_node.nodeid}: {e}. Check node data types.", exc_info=True)
                await asyncio.sleep(5)
            except Exception as e:
                _logger.error(f"Unexpected error during alarm loop: {e}", exc_info=True)
                import traceback
                traceback.print_exc()
                await asyncio.sleep(5)

# --- Punto de Entrada Principal ---
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user.")
    except Exception as main_err:
        print(f"\nAn error occurred running the main application: {main_err}")