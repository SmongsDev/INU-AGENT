from typing import Literal
from pydantic import BaseModel, Field
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from ..config import Config
from .base import get_grader_model


class State(TypedDict):
    messages: Annotated[list, add_messages]
    rag_model: str

class GradeDocuments(BaseModel):
    """Grade documents using a binary score for relevance check."""
    binary_score: str = Field(
        description="Relevance score: 'yes' if relevant, or 'no' if not relevant"
    )

def grade_documents(
    state: State,
) -> Literal["generate_answer", "rewrite_question"]:
    """Determine whether the retrieved documents are relevant to the question."""
    question = state["messages"][0].content
    context = state["messages"][-1].content

    prompt = Config.load_prompt("grade").format(
        question=question,
        context=context
    )
    
    response = (
        get_grader_model(state["rag_model"])
        .with_structured_output(GradeDocuments)
        .invoke([{"role": "user", "content": prompt}])
    )
    score = response.binary_score

    if score == "yes":
        return "generate_answer"
    else:
        return "rewrite_question"

