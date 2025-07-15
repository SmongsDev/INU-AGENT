import pytest
from agents.rag.retriever import RAGRetriever
from langchain_core.documents import Document
from unittest.mock import MagicMock

class DummyVectorStore:
    def add_documents(self, documents, ids=None):
        self.added = (documents, ids)
    def similarity_search_with_relevance_scores(self, query, k=4):
        return [(Document(page_content="mock result", metadata={}), 0.99)]

class DummyEmbeddings:
    pass

def test_add_documents_and_search(monkeypatch):
    # RAGRetriever 내부 vector_store를 더미로 교체
    retriever = RAGRetriever(supabase_client=None, openai_api_key="dummy")
    retriever.vector_store = DummyVectorStore()
    doc = Document(page_content="test", metadata={})
    retriever.add_documents([doc])
    assert hasattr(retriever.vector_store, "added")
    results = retriever.similarity_search("test")
    assert results[0][0].page_content == "mock result"
    assert results[0][1] == 0.99
