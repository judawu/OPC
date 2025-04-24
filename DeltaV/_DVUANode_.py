from typing import Dict
import logging
from asyncua import ua
class _OPCUANode_:
        def __init__(self,name:str= 'OPCUA Server', nodename:str ='localhost',endpoint: str = 'opc.tcp://0.0.0.0:4840',application_uri:str='OPC.DELTAV.1'):
            self.endpoint = endpoint   
            self.name = name
            self.nodename = nodename
            self.application_uri = application_uri
            self.idx = None
            self.da_folder = None
            self.cert_node = None
            self.nodes = {}  # Dict[str, ua.Node]
            self.parameters_folder=None
            self.methods_nodes={}
            self.parameters_nodes = {}  # Dict[str, ua.Node]
            self.folders = {}  # 新增: 用于存储文件夹节点
          
            self.events_node = None           
            self.event_nodes = {}
            self.alarm_type = None
            self.event_type = None
            self.historian_node = None
          

            self.last_error_code = None  # 用于存储错误状态的节点
            self.last_error_desc = None  # 用于存储错误状态的节点
      
    
        async def _get_node_path(self, node) -> str:
            """Helper to get the full path of a node based on self.node.folders."""
            for path, n in self.folders.items():
                if n.nodeid == node.nodeid:
                    return path
            # If not found in folders, use the browse name at the root level
            browse_name = await node.read_browse_name()
            return browse_name.Name if browse_name.NamespaceIndex == self.idx else ""
        
        def _get_folder_path_for_item(self, item_path: str, current_node_path: str) -> str:
            """Determine the intended folder path for an item based on self.node.folders."""
            # Find the longest matching folder path that this item belongs to
            item_parts = item_path.split('.')
            for folder_path in sorted(self.folders.keys(), key=len, reverse=True):
                if item_path.startswith(folder_path) and folder_path != item_path:
                    return folder_path
            # If no folder matches, it belongs at the current level or root
            return current_node_path
        
        async def _build_node_structure(self, node) -> Dict:
                structure = {}
                items_list = []  # To collect variables at this level
                children = await node.get_children()
                logging.debug(f"_OPCUANode_._build_node_structure: Node={await node.read_browse_name()}, Children={[await child.read_browse_name() for child in children]}")

                # Get the current node's path for comparison
                current_node_path = await self._get_node_path(node)

                for child in children:
                    child_name = await child.read_browse_name()
                    name = child_name.Name
                    node_class = await child.read_node_class()
                    logging.debug(f"_build_node_structure: Child={name}, NodeClass={node_class}")

                    if node_class == ua.NodeClass.Object:
                        # Recursively build sub-structure for folders
                        sub_structure = await self._build_node_structure(child)
                        if sub_structure:  # Only add non-empty sub-structures
                            structure[name] = sub_structure
                    elif node_class == ua.NodeClass.Variable:
                        # Find the full path from self.node.nodes
                        item_path = next((path for path, n in self.nodes.items() if n.nodeid == child.nodeid), name)
                        # Determine the intended folder path for this item
                        item_folder_path = self._get_folder_path_for_item(item_path, current_node_path)
                        
                        if item_folder_path == current_node_path or not item_folder_path:
                            # This item belongs directly at this level
                            if item_path not in items_list:
                                items_list.append(item_path)
                        else:
                            # Navigate to the correct sub-folder
                            relative_path = item_folder_path[len(current_node_path) + 1:] if current_node_path else item_folder_path
                            path_parts = relative_path.split('.')
                            current = structure
                            for part in path_parts:
                                if part not in current:
                                    current[part] = {}
                                current = current[part]
                            if "ITEMS" not in current:
                                current["ITEMS"] = []
                            if item_path not in current["ITEMS"]:
                                current["ITEMS"].append(item_path)

                if items_list:
                    structure["ITEMS"] = items_list

                logging.debug(f"_OPCUANode_._build_node_structure: Built structure={structure}")
                return structure