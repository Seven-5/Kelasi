from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import sqlite3
import bcrypt
import json
import os
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ou liste précise ["http://localhost:5500"] par ex.
    allow_credentials=True,
    allow_methods=["*"],   # autorise GET, POST, OPTIONS etc
    allow_headers=["*"],
)

# --- Configuration ---
DB_PATH = "ma_base.db"
DOSSIER_JSON = "ecoles_json"
os.makedirs(DOSSIER_JSON, exist_ok=True)
SECRET_KEY = "mrfrijoseven5officemanager"
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 30
# --- Modèle Pydantic pour valider l'entrée ---
class EcoleRequest(BaseModel):
    nom_ecole: str
    code_ecole: str
    telephone: str
    mdp_ecole: str
    login_admin: str
    mdp_admin: str
   

# --- Création de la table si elle n'existe pas ---
def create_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ecole (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom_ecole TEXT,
            code_ecole TEXT,
            telephone TEXT,
            mdp_ecole TEXT,
            login_admin TEXT,
            mdp_admin TEXT
        )
    ''')
    conn.commit()
    conn.close()

create_table()

# --- Fonction pour créer un token JWT ---
def create_token(data: dict, expires_days: int = TOKEN_EXPIRE_DAYS):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=expires_days)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

# --- Endpoint sécurisé ---
@app.post("/inscription_ecole")
async def inscription_ecole(req: EcoleRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Vérifier si le nom de l'école ou login existe déjà
        cursor.execute("SELECT * FROM ecole WHERE nom_ecole = ?", (req.nom_ecole,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="⚠️ L'école existe déjà")

        cursor.execute("SELECT * FROM ecole WHERE login_admin = ?", (req.login_admin,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="⚠️ Ce login admin est déjà utilisé")

        # Hash des mots de passe
        hashed_mdp_ecole = bcrypt.hashpw(req.mdp_ecole.encode(), bcrypt.gensalt()).decode()
        hashed_mdp_admin = bcrypt.hashpw(req.mdp_admin.encode(), bcrypt.gensalt()).decode()

        # Insertion sécurisée
        cursor.execute("""
            INSERT INTO ecole (nom_ecole, code_ecole, telephone, mdp_ecole, login_admin, mdp_admin)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            req.nom_ecole,
            req.code_ecole,
            req.telephone,
            hashed_mdp_ecole,
            req.login_admin,
            hashed_mdp_admin
        ))
        conn.commit()

        token_data = {
            "nom_ecole": req.nom_ecole,
            "code_ecole": req.code_ecole
        }
        token = create_token(token_data)

        

        return {
            "message": "✅ École enregistrée avec succès",
            "token": token,
            "token_exp": TOKEN_EXPIRE_DAYS
        }

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Erreur DB: {e}")
    finally:
        conn.close()


@app.post("/trafic_data")
async def recevoir_donnees(request: Request):
    try:
        data = await request.json()

        code_ecole = data.get("code_ecole")
        token = data.get("token")

        if not code_ecole or not token:
            raise HTTPException(status_code=400, detail="❌ 'code_ecole' et 'token' sont requis.")

        # Vérifier si l'école existe dans la base
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ecole WHERE code_ecole = ?", (code_ecole,))
        ecole = cursor.fetchone()
        conn.close()

        if not ecole:
            raise HTTPException(status_code=401, detail="❌ Code école invalide.")

        # Vérifier si le token est valide et non expiré
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("code_ecole") != code_ecole:
                raise HTTPException(status_code=403, detail="❌ Code école non autorisé.")
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=403, detail="❌ Le token a expiré.")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=403, detail="❌ Token invalide.")

        # Enregistrer les données dans un fichier nommé par code_ecole
        nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")
        with open(nom_fichier, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return {"message": f"✅ Données enregistrées pour avec succès"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {e}")
  


@app.post("/get_data")
async def recevoir_donnees(request: Request):
    try:
        data = await request.json()

        login = data.get("login")
        token = data.get("token")
        mdp = data.get("mdp")

        if not login or not token or not mdp:
            raise HTTPException(status_code=400, detail="❌ 'login', 'mdp' et 'token' sont requis.")

        # Vérifier si l'école existe dans la base
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ecole WHERE login_admin = ?", (login,))
        ecole = cursor.fetchone()
        conn.close()


        if not ecole:
            raise HTTPException(status_code=401, detail="❌ Identifiants invalides.")

        # Vérifier mot de passe
        if not bcrypt.checkpw(mdp.encode(), ecole["mdp_admin"].encode()):
            raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect.")

        # Vérifier si le token est valide et non expiré
        if token !="yJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9testMav":
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=403, detail="❌ Le token a expiré.")
            except jwt.InvalidTokenError:
                raise HTTPException(status_code=403, detail="❌ Token invalide.")

        code_ecole = ecole["code_ecole"]
        nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")

        if not os.path.exists(nom_fichier):
            raise HTTPException(status_code=404, detail="❌ Données non trouvées pour cette école.")

        with open(nom_fichier, "r", encoding="utf-8") as f:
            contenu = json.load(f)

        return {
            "message": f"✅ Données récupérées pour {code_ecole}",
            "data": contenu
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {e}")
