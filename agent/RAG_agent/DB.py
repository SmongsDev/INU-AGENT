from sqlalchemy import Column, Text, Integer
from sqlalchemy.orm import declarative_base

Base = declarative_base()

EMBED_DIM = 1536  

class CloudMatrixUrl(Base):
    __tablename__ = "cloud_matrix_url"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    url           = Column(Text, nullable=False)