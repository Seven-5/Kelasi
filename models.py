# models.py
from sqlalchemy import Column, Integer, String, Text
from database import Base

class Ecole(Base):
    __tablename__ = "ecole"
    id          = Column(Integer, primary_key=True, index=True)
    nom_ecole   = Column(String, unique=True, nullable=False)
    code_ecole  = Column(String, nullable=False)
    telephone   = Column(String, nullable=False)
    mdp_ecole   = Column(String, nullable=False)
    login_admin = Column(String, unique=True, nullable=False)
    mdp_admin   = Column(String, nullable=False)

class Notification(Base):
    __tablename__ = "notifications"
    id         = Column(Integer, primary_key=True, index=True)
    code_ecole = Column(String, nullable=False)
    message    = Column(Text, nullable=False)
    date_envoi = Column(String, nullable=False)
