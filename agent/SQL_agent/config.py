import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
PROMPTS_DIR = BASE_DIR / "prompts"

class Config:
    DATABASE_URL = os.getenv("TEST_DATABASE_URL")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    MODEL_NAME = "gpt-4"
    ALLOW_TABLES = os.getenv("ALLOW_TABLES")
    
    @classmethod
    def load_prompt(cls, name: str) -> str:
        prompt_path = PROMPTS_DIR / f"{name}_system_prompt.txt"
        return prompt_path.read_text()
