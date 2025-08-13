import os
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores.pgvector import PGVector
from app.db.session import engine

def get_vector_store() -> PGVector:
    """PostgreSQL Vector Store 인스턴스를 반환합니다."""
    embeddings = OpenAIEmbeddings(
        model="text-embedding-3-small",
        api_key=os.environ.get("OPENAI_API_KEY")
    )

    connection_string = str(engine.url)
    
    return PGVector(
        connection_string=connection_string,
        embedding_function=embeddings,
        collection_name="document",
        distance_strategy="cosine"  # or "euclidean" or "max_inner_product"
    )