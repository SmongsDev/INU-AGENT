from agents.rag.rag_pipeline import RAGPipeline
from langchain_core.documents import Document
from unittest.mock import patch, MagicMock

def test_rag_pipeline_add_and_search():
    with patch("agents.rag.rag_pipeline.get_supabase_client") as mock_get_client, \
         patch("agents.rag.rag_pipeline.RAGRetriever") as mock_retriever_class:
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_retriever = MagicMock()
        mock_retriever.similarity_search.return_value = [(Document(page_content="mock", metadata={}), 0.9)]
        mock_retriever_class.return_value = mock_retriever

        pipeline = RAGPipeline()
        pipeline.add_sample_document()
        results = pipeline.search("test")
        assert results[0][0].page_content == "mock"
        assert results[0][1] == 0.9
