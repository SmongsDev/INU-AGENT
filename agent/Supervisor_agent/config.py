import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
PROMPTS_DIR = BASE_DIR / "prompts"

class Config:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
    # Supervisor specific configurations
    DEFAULT_SUP_MODEL = "openai:gpt-4.1"
    DEFAULT_SQL_MODEL = "openai:gpt-4.1"
    DEFAULT_RAG_MODEL = "openai:gpt-4.1"
    DEFAULT_RETRIVE_CNT = 5
    
    @classmethod
    def load_prompt(cls, name: str) -> str:
        prompt_path = PROMPTS_DIR / f"{name}_system_prompt.txt"
        return prompt_path.read_text()
