from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from langchain.chat_models import init_chat_model
from langchain.tools.retriever import create_retriever_tool

from ..config import Config

# Database setup
engine = create_engine(Config.DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Vector store setup
embeddings = OpenAIEmbeddings(api_key=Config.OPENAI_API_KEY)
connection = engine.url.render_as_string(hide_password=False)

vector_store = PGVector(
    connection=connection,
    embeddings=embeddings,
    collection_name=Config.COLLECTION_NAME,
    relevance_score_fn="cosine",
)

retriever = vector_store.as_retriever(search_kwargs={"k": 5})

# Tool setup
retriever_tool = create_retriever_tool(
    retriever,
    "retrieve_document",
    "Search and return information about MITRE ATT&CK technique posts.",
)

# Model setup
response_model = init_chat_model(
    f"openai:{Config.MODEL_NAME}",
    temperature=0,
    openai_api_key=Config.OPENAI_API_KEY
)

grader_model = init_chat_model(
    f"openai:{Config.MODEL_NAME}",
    temperature=0,
    openai_api_key=Config.OPENAI_API_KEY
)
