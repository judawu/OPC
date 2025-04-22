import pyodbc
import logging
import asyncio
from datetime import datetime, timedelta



class EventChronicleClient:
    def __init__(self, server="PROPLUS", instance="DELTAV_CHRONICLE", trusted_connection=True):
        self.server = f"{server}\\{instance}" if instance else server
   
        self.trusted_connection = trusted_connection
        self.conn = None
        self.cursor = None

    def connect(self):
        try:
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={self.server};"
           
                f"Trusted_Connection=yes;"
            )
            self.conn = pyodbc.connect(conn_str)
            self.cursor = self.conn.cursor()
            logging.debug(f"EventChronicleClient:Connected to SQL Server: {self.server}")
        except Exception as e:
            logging.error(f"EventChronicleClient:Failed to connect to SQL Server: {str(e)}")
            raise

    def disconnect(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
            logging.debug("EventChronicleClient:Disconnected from SQL Server")

    
    def fetch_events(self, seconds_back=60, filters=None):
        """
        带过滤条件的事件查询函数，仅查询主数据库
        参数:
            seconds_back: 查询多少秒之前的事件
            filters: 字典形式的过滤条件，例如 {"Category": "Alarm", "Level": 5}
        """
        events = []
        filters = filters or {}
        
        try:
            # 基础查询语句，仅查询主数据库
            base_query = """
                SELECT [Date_Time] AS EventTime, [Event_Type] AS Event_Type, [Category] AS Category,
                    [Area] AS Area, [Node] AS Node, [Module] AS Module, 
                    [Module_Description] AS ModuleDescription, [Attribute] AS Attribute, 
                    [State] AS State, [Event_Level] AS Level, [Desc1] AS Parameter, 
                    [Desc2] AS Description, [Ord] AS Ord
                FROM [EJournal].[dbo].[Journal]
                WHERE [Date_Time] >= DATEADD(second, ?, GETUTCDATE())
            """
            
            # 添加过滤条件
            params = [-seconds_back]
            where_clauses = []
            
            # 可过滤的字段映射
            field_mapping = {
                "EventTime": "Date_Time",
                "Event_Type": "Event_Type",
                "Category": "Category",
                "Area": "Area",
                "Node": "Node",
                "Module": "Module",
                "ModuleDescription": "Module_Description",
                "Attribute": "Attribute",
                "State": "State",
                "Level": "Event_Level",
                "Parameter": "Desc1",
                "Description": "Desc2"
            }
            
            # 构建WHERE子句
            for filter_key, filter_value in filters.items():
                if filter_key in field_mapping:
                    db_field = field_mapping[filter_key]
                    if isinstance(filter_value, list):
                        placeholders = ",".join(["?" for _ in filter_value])
                        where_clauses.append(f"[{db_field}] IN ({placeholders})")
                        params.extend(filter_value)
                    elif isinstance(filter_value, (int, float)):
                        where_clauses.append(f"[{db_field}] = ?")
                        params.append(filter_value)
                    elif filter_key in ['Area', 'Module', 'Node']:
                        where_clauses.append(f"[{db_field}] = ?")
                        params.append(filter_value)
                    else:
                        where_clauses.append(f"[{db_field}] LIKE ?")
                        params.append(f"%{filter_value}%")
            
            # 组合完整的查询语句
            query = base_query
            if where_clauses:
                query += " AND " + " AND ".join(where_clauses)
            query += " ORDER BY [Date_Time] DESC"
            
            # 执行查询
            self.cursor.execute(query, params)
            events.extend([
                {
                    "EventTime": row.EventTime,
                    "Event_Type": row.Event_Type,
                    "Category": row.Category,
                    "Area": row.Area,
                    "Node": row.Node,
                    "Module": row.Module,
                    "ModuleDescription": row.ModuleDescription,
                    "Attribute": row.Attribute,
                    "State": row.State,
                    "Level": row.Level,
                    "Parameter": row.Parameter,
                    "Description": row.Description,
                    "Ord": row.Ord
                }
                for row in self.cursor.fetchall()
            ])
            
            logging.debug(f"EventChronicleClient:Fetched {len(events)} events with filters: {filters}")
            return sorted(events, key=lambda x: x["EventTime"], reverse=True)
            
        except Exception as e:
            logging.error(f"EventChronicleClient:Failed to fetch events: {str(e)}")
            return []

    def filter_events(self, filters=None):
        """
        带过滤条件的事件查询函数，支持时间范围和溢出数据库（仅在主数据库无数据时查询）
        参数:
            filters: 字典形式的过滤条件，例如 {"Category": "Alarm", "Level": 5, "start_time": "2023-01-01 10:00:00", "end_time": "2023-01-01 12:00:00"}
            include_overflow: 是否在主数据库无数据时查询溢出数据库
        """
        events = []
        filters = filters or {}
        
        # 设置默认时间范围
        default_end_time = datetime.now()
        default_start_time = default_end_time - timedelta(days=1)
        
        # 获取时间过滤条件
        start_time = filters.get("start_time", default_start_time)
        end_time = filters.get("end_time", default_end_time)
        
        # 如果传入的是字符串，转换为datetime对象
        if isinstance(start_time, str):
            start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        if isinstance(end_time, str):
            end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        
        try:
            # 基础查询语句
            base_query = """
                SELECT [Date_Time] AS EventTime, [Event_Type] AS Event_Type, [Category] AS Category,
                    [Area] AS Area, [Node] AS Node, [Module] AS Module, 
                    [Module_Description] AS ModuleDescription, [Attribute] AS Attribute, 
                    [State] AS State, [Event_Level] AS Level, [Desc1] AS Parameter, 
                    [Desc2] AS Description, [Ord] AS Ord
                FROM [EJournal].[dbo].[Journal]
                WHERE [Date_Time] BETWEEN ? AND ?
            """
            
            # 参数列表，时间范围始终作为前两个参数
            params = [start_time, end_time]
            
            # 可过滤的字段映射（移除时间相关的，因为已单独处理）
            field_mapping = {
                "Event_Type": "Event_Type",
                "Category": "Category",
                "Area": "Area",
                "Node": "Node",
                "Module": "Module",
                "ModuleDescription": "Module_Description",
                "Attribute": "Attribute",
                "State": "State",
                "Level": "Event_Level",
                "Parameter": "Desc1",
                "Description": "Desc2"
            }
            
            # 构建额外的WHERE子句
            where_clauses = []
            for filter_key, filter_value in filters.items():
                if filter_key in field_mapping:
                    db_field = field_mapping[filter_key]
                    if isinstance(filter_value, list):
                        placeholders = ",".join(["?" for _ in filter_value])
                        where_clauses.append(f"[{db_field}] IN ({placeholders})")
                        params.extend(filter_value)
                    elif isinstance(filter_value, (int, float)):
                        where_clauses.append(f"[{db_field}] = ?")
                        params.append(filter_value)
                    elif filter_key in ['Area', 'Module', 'Node']:
                        where_clauses.append(f"[{db_field}] = ?")
                        params.append(filter_value)
                    else:
                        where_clauses.append(f"[{db_field}] LIKE ?")
                        params.append(f"%{filter_value}%")
            
            # 组合完整的查询语句
            query = base_query
            if where_clauses:
                query += " AND " + " AND ".join(where_clauses)
            query += " ORDER BY [Date_Time] DESC"
            
            # 执行主数据库查询
            self.cursor.execute(query, params)
            events.extend([
                {
                    "EventTime": row.EventTime,
                    "Event_Type": row.Event_Type,
                    "Category": row.Category,
                    "Area": row.Area,
                    "Node": row.Node,
                    "Module": row.Module,
                    "ModuleDescription": row.ModuleDescription,
                    "Attribute": row.Attribute,
                    "State": row.State,
                    "Level": row.Level,
                    "Parameter": row.Parameter,
                    "Description": row.Description,
                    "Ord": row.Ord
                }
                for row in self.cursor.fetchall()
            ])
            
            # 如果主数据库没有数据且include_overflow为True，则查询溢出数据库
            if not events :
                overflow_query = query.replace("[EJournal].[dbo].[Journal]", "[EJOverflow].[dbo].[Journal]")
                self.cursor.execute(overflow_query, params)
                events.extend([
                    {
                        "EventTime": row.EventTime,
                        "Event_Type": row.Event_Type,
                        "Category":  row.Category,
                        "Area": row.Area,
                        "Node": row.Node,
                        "Module": row.Module,
                        "ModuleDescription": row.ModuleDescription,
                        "Attribute": row.Attribute,
                        "State": row.State,
                        "Level": row.Level,
                        "Parameter": row.Parameter,
                        "Description": row.Description,
                        "Ord": row.Ord
                    }
                    for row in self.cursor.fetchall()
                ])
                logging.debug("EventChronicleClient:No events found in main database, queried overflow database")
            
            logging.debug(f"EventChronicleClient:Fetched {len(events)} events with filters: {filters}")
            return sorted(events, key=lambda x: x["EventTime"], reverse=True)
            
        except Exception as e:
            logging.error(f"EventChronicleClient:Failed to fetch filtered events: {str(e)}")
            return []

async def main():
    #sql_client = EventChronicleClient(server="localhost", instance="DELTAV_CHRONICLE")
    sql_client = EventChronicleClient(server="10.8.0.6,55114", instance="DELTAV_CHRONICLE")
    try:
        sql_client.connect()
        # filters = {
        #                         "Category": "PROCESS",
        #                         "Area": "AREA_V1",
        #                         "Event_Type": "ALARM",
        #                         "Attribute": ["LO_ALM","LO_LO_ALM","HI_ALM","HI_HI_ALM","PVBAD_ALM"]
                                                                      
        #                     }
        # events = sql_client.fetch_events(seconds_back=5,filters=filters)
        # for event in events:
        #     print(event)


        filters = {
            "Category": "USER", #PROCESS
            "Event_Type": "CHANGE", #ALARM
            "Area": ["AREA_V1", "AREA_V2"]  # 查询 AREA_V1 和 AREA_V2    
            # "start_time": "2025-04-09 10:00:00",
            # "end_time": "2025-04-10 12:00:00"
        }
        events = sql_client.filter_events(filters=filters)
        for event in events:
            print(event)
    

       
    except Exception as e:
        ptint(f"Error in main: {str(e)}")
        raise
    finally:
        sql_client.disconnect()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())