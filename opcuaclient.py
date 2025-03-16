from asyncua import Client
from asyncua import ua
import asyncio

async def browse_and_write(client):
    try:
        await client.connect()
        print("Connected to server")

        root = client.get_root_node()
        print("Root node:", root)
        objects = client.get_objects_node()
        print("Objects node:", objects)

        children = await objects.get_children()
        opc_da_folder = None
        for child in children:
            display_name = await child.read_display_name()
            if display_name.Text == "OPC_DA_Items":
                opc_da_folder = child
                break

        if not opc_da_folder:
            print("Error: OPC_DA_Items folder not found")
            return

        print("Found OPC_DA_Items folder:", opc_da_folder)

        items = await opc_da_folder.get_children()
        write_method = None
        nodes_dict = {}
        for item in items:
            node_id = item.nodeid
            display_name = await item.read_display_name()
            node_class = await item.read_node_class()
            if node_class == ua.NodeClass.Method and display_name.Text == "write_to_opc_da":
                write_method = item
            elif node_class == ua.NodeClass.Variable:
                value = await item.read_value()
                print(f"Node: {node_id}, Name: {display_name.Text}, Value: {value}")
                nodes_dict[display_name.Text] = item

        if not write_method:
            print("Error: write_to_opc_da method not found")
            return

        print(f"Found write_to_opc_da method: {write_method.nodeid}")
        print(f"Found {len(nodes_dict)} variables in OPC_DA_Items folder")

        await asyncio.sleep(5)  # 模拟等待服务器准备
        write_items = [
            "V1-IO/AI1_SCI1.EU100",
            "V1-AI-1/FS_CTRL1/MOD_DESC.CV",
            "V1-TIC-JKT/HEAT_OUT_D.CV"
        ]
        write_values = [32764, "helloworld", 3.14]

        print("Attempting to write values via write_to_opc_da...")
        items_variant = ua.Variant(write_items, ua.VariantType.String)
        values_variant = ua.Variant([ua.Variant(val) for val in write_values], ua.VariantType.Variant)
        try:
            results = await client.nodes.objects.call_method(write_method.nodeid, items_variant, values_variant)
            print(f"Write results: {results}")
        except ua.UaStatusCodeError as e:
            print(f"Method call failed: {e}")
            print(f"Status code: {e.status}")

        await asyncio.sleep(2)
        print("Reading values to verify write...")
        for item_name in write_items:
            ua_name = item_name.replace('/', '_')
            if ua_name in nodes_dict:
                node = nodes_dict[ua_name]
                try:
                    value = await node.read_value()
                    print(f"Verified: {item_name} = {value}")
                except ua.UaStatusCodeError as e:
                    print(f"Failed to read {item_name}: {e}")
            else:
                print(f"Node {ua_name} not found for verification")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()
        print("Disconnected from server")

async def test_client():
    client = Client("opc.tcp://localhost:4840")
    try:
        await browse_and_write(client)
    except asyncio.CancelledError:
        print("Client task cancelled")
    
       
        await client.disconnect()
        print("Client fully disconnected")

if __name__ == "__main__":
    asyncio.run(test_client())