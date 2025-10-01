import os
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from app.db.session import engine

def get_vector_store() -> PGVector:
    embeddings = OpenAIEmbeddings(
        model="text-embedding-3-small",
        api_key=os.environ.get("OPENAI_API_KEY")
    )

    connection = engine.url.render_as_string(hide_password=False)

    return PGVector(
        connection=connection,
        embeddings=embeddings,
        collection_name="document",
        distance_strategy="cosine"
    )