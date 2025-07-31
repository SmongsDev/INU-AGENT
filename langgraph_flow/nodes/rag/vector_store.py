import os
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import SupabaseVectorStore
from .supabase_client import get_supabase_client

def get_vector_store() -> SupabaseVectorStore:
    """Supabase Vector Store 인스턴스를 반환합니다."""
    supabase = get_supabase_client()
    embeddings = OpenAIEmbeddings(
        model="text-embedding-3-small",
        api_key=os.environ.get("OPENAI_API_KEY")
    )

    return SupabaseVectorStore(
        embedding=embeddings,
        client=supabase,
        table_name="document",
        query_name="match_documents",
    ) 