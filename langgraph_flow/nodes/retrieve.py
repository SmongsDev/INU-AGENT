from typing import TypedDict
from langchain_core.documents import Document
from agents.rag.retriever import RAGRetriever

class State(TypedDict):
    event_summary: str
    similar_events: list[Document]

def retrieve_similar_events(state: State) -> State:
    """유사한 이벤트들을 검색합니다."""
    retriever = RAGRetriever()
    similar_events = retriever.similarity_search(state['event_summary'])
    return {
        'similar_events': similar_events,
    } 