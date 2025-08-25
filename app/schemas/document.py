from typing import Any, Dict, List
from uuid import UUID
from pydantic import BaseModel, Field

class Document(BaseModel):
    id: UUID = Field(description="문서 ID")
    content: str = Field(description="문서 내용")
    metadata: Dict[str, Any] = Field(description="문서 메타데이터")
    embedding: List[float] = Field(description="임베딩 벡터")

class DocumentCreate(BaseModel):
    content: str = Field(description="문서 내용")
    metadata: Dict[str, Any] = Field(description="문서 메타데이터")
    embedding: List[float] = Field(description="임베딩 벡터")