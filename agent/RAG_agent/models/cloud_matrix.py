from sqlalchemy import Column, Text, Integer
from sqlalchemy.orm import declarative_base
from ..config import Config

Base = declarative_base()

class CloudMatrixUrl(Base):
    __tablename__ = "cloud_matrix_url"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False)
