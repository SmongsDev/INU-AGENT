from langchain_openai import ChatOpenAI
from langchain_core.tools import tool, InjectedToolCallId
from langgraph.prebuilt import InjectedState
from langgraph.types import Command
from typing import Annotated
from agent.Supervisor_agent.config import Config

def get_supervisor_llm(model_name: str):
    """지정된 모델명으로 LLM 인스턴스를 반환합니다."""
    model = model_name or Config.MODEL_NAME
    return ChatOpenAI(model=model, openai_api_key=Config.OPENAI_API_KEY)

def create_handoff_tool(*, agent_name: str, description: str | None = None):
    """다른 에이전트로 작업을 전달하는 도구를 생성합니다."""
    name = f"transfer_to_{agent_name}"
    description = description or f"Ask {agent_name} for help."

    @tool(name, description=description)
    def handoff_tool(
        state: Annotated[dict, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId],
    ) -> Command:
        tool_message = {
            "role": "tool",
            "content": f"Successfully transferred to {agent_name}",
            "name": name,
            "tool_call_id": tool_call_id,
        }
        return Command(
            goto=agent_name,  
            update={"messages": state["messages"] + [tool_message]},  
            graph=Command.PARENT,  
        )

    return handoff_tool
