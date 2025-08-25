from langchain_core.documents import Document
from .vector_store import get_vector_store

class RAGRetriever:

    def __init__(self):
        self.vector_store = get_vector_store()

    def add_documents(self, documents: list[Document]):
        """문서를 벡터 스토어에 추가합니다."""
        self.vector_store.add_documents(documents)

    def similarity_search(self, query: str, k: int = 5):
        """쿼리와 유사한 문서를 검색합니다."""
        return self.vector_store.similarity_search(query, k=k)
