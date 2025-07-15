from .supabase_client import get_supabase_client
from .retriever import RAGRetriever
from langchain_core.documents import Document
import os

'''
RAGPipeline은 RAG 파이프라인을 구성하는 클래스입니다.

Args:
    None

Returns:
    RAGPipeline: RAG 파이프라인 인스턴스
'''
class RAGPipeline:
    def __init__(self):
        self.supabase_client = get_supabase_client()
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.retriever = RAGRetriever(self.supabase_client, self.openai_api_key)

    def add_sample_document(self):
        document1 = Document(
            page_content="test is simple in Smongs",
            metadata={"source": "https://example.com"},
        )
        self.retriever.add_documents([document1])

    def search(self, query):
        return self.retriever.similarity_search(query)
