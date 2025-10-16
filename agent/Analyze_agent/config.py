import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
PROMPTS_DIR = BASE_DIR / "prompts"

class Config:
    DATABASE_URL = os.getenv("TEST_DATABASE_URL")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    MODEL_NAME = "gpt-4o"
    COLLECTION_NAME = "is_false_positive"
    RETRIEVE_CNT = 5
    EMBED_DIM = 1536
    
    @classmethod
    def load_prompt(cls, name: str) -> str:
        prompt_path = PROMPTS_DIR / f"{name}_prompt.txt"
        return prompt_path.read_text()

