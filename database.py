# database.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Récupérer la variable d'environnement sur Render
DATABASE_URL = os.getenv("DATABASE_URL")  
# (sur Render, tu as déjà mis "DATABASE_URL" = "postgresql://kelasi_db_user:...@...)."

# Crée l'engine SQLAlchemy pour PostgreSQL
engine = create_engine(DATABASE_URL)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base (pour déclarer les modèles)
Base = declarative_base()
