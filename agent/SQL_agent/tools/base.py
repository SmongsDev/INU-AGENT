from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import ToolNode
from agent.SQL_agent.config import Config

allow_tables_env = Config.ALLOW_TABLES
include_tables = (
    [t.strip() for t in allow_tables_env.split(",")] if allow_tables_env else None
)

db = SQLDatabase.from_uri(
    Config.DATABASE_URL,
    include_tables=include_tables
)

llm = ChatOpenAI(model="gpt-4.1", openai_api_key=Config.OPENAI_API_KEY)
toolkit = SQLDatabaseToolkit(db=db, llm=llm)
tools = toolkit.get_tools()

get_schema_tool = next(tool for tool in tools if tool.name == "sql_db_schema")
get_schema_node = ToolNode([get_schema_tool], name="get_schema")

run_query_tool = next(tool for tool in tools if tool.name == "sql_db_query")
run_query_node = ToolNode([run_query_tool], name="run_query")