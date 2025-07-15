from langchain_community.vectorstores import SupabaseVectorStore
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
import uuid

"""
RAGRetriever는 SupabaseVectorStore를 사용하여 문서를 벡터 저장소에 추가하고 유사도 검색을 수행합니다.

Args:
    supabase_client: Supabase 클라이언트 인스턴스
    openai_api_key: OpenAI API 키
    table_name: 문서를 저장할 Supabase 테이블 이름
    query_name: 유사도 검색을 위한 쿼리 이름
"""
class RAGRetriever:
    def __init__(self, supabase_client, openai_api_key, table_name="document", query_name="match_documents"):
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)
        self.vector_store = SupabaseVectorStore(
            embedding=self.embeddings,
            client=supabase_client,
            table_name=table_name,
            query_name=query_name,
        )

    def add_documents(self, documents):
        ids = [str(uuid.uuid4()) for _ in documents]
        self.vector_store.add_documents(documents, ids=ids)

    def similarity_search(self, query, top_k=4):
        return self.vector_store.similarity_search_with_relevance_scores(query, k=top_k)
