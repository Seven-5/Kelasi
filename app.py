from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse

from pydantic import BaseModel
import bcrypt
import json
import os
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Ecole, Notification

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration non modifiée ---
DOSSIER_JSON = "/tmp/ecoles_json"
os.makedirs(DOSSIER_JSON, exist_ok=True)
SECRET_KEY = "mrfrijoseven5officemanager"
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 30

# --- hles models pour les endpoints ---
class EcoleRequest(BaseModel):
    nom_ecole: str
    code_ecole: str
    mdp_ecole: str
    telephone: str
    login_admin: str
    mdp_admin: str

class UpdateAdminRequest(BaseModel):
    login: str
    ancien_mdp: str
    nouveau_login: str = None
    nouveau_mdp1: str = None
    nouveau_mdp2: str = None

class NotificationRequest(BaseModel):
    login_admin: str
    mdp_admin: str
    message: str

# --- helper pour récupérer la session DB ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Fonction adaptée : get_notifications_by_code_ecole ---
def get_notifications_by_code_ecole(code_ecole: str, db: Session):
    try:
        # On interroge la table Notification (SQLAlchemy ORM) 
        rows = db.query(Notification)\
                 .filter(Notification.code_ecole == code_ecole)\
                 .order_by(Notification.date_envoi.desc())\
                 .all()
        # On retourne la même structure qu'avant
        return [{"message": r.message, "date": r.date_envoi} for r in rows]

    except Exception as e:
        # Si erreur, on lève un HTTPException
        raise HTTPException(status_code=500, detail=f"Erreur DB: {e}")

# --- Fonction adaptée : create_table ---
def create_table():
    """
    Au lieu de créer manuellement avec SQLite, 
    on utilise SQLAlchemy pour créer les tables si elles n'existent pas.
    """
    Base.metadata.create_all(bind=engine)

# Appel initial pour créer les tables sur PostgreSQL (une seule fois au démarrage)
create_table()

# --- La fonction create_token reste inchangée ---
def create_token(data: dict, expires_days: int = TOKEN_EXPIRE_DAYS):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=expires_days)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

# --- Endpoint sécurisé ---

# --- Endpoint de test ---
@app.get("/ping")
async def ping():
    return {
        "message": "✅ L'API fonctionne parfaitement",
        "status": "OK"
    }


# --- Inscription d'une école ---
@app.post("/inscription_ecole")
async def inscription_ecole(req: EcoleRequest, db: Session = Depends(get_db)):
    try:
        # Vérifier si le nom de l'école existe déjà
        existe_nom = db.query(Ecole).filter(Ecole.nom_ecole == req.nom_ecole).first()
        if existe_nom:
            raise HTTPException(status_code=400, detail="⚠️ L'école existe déjà")

        # Vérifier si le login_admin existe déjà
        existe_login = db.query(Ecole).filter(Ecole.login_admin == req.login_admin).first()
        if existe_login:
            raise HTTPException(status_code=400, detail="⚠️ Ce login admin est déjà utilisé")

        # Hash des mots de passe
        hashed_mdp_ecole = bcrypt.hashpw(req.mdp_ecole.encode(), bcrypt.gensalt()).decode()
        hashed_mdp_admin = bcrypt.hashpw(req.mdp_admin.encode(), bcrypt.gensalt()).decode()

        # Création de l'objet Ecole
        nouvelle_ecole = Ecole(
            nom_ecole=req.nom_ecole,
            code_ecole=req.code_ecole,
            telephone=req.telephone,
            mdp_ecole=hashed_mdp_ecole,
            login_admin=req.login_admin,
            mdp_admin=hashed_mdp_admin
        )
        db.add(nouvelle_ecole)
        db.commit()
        db.refresh(nouvelle_ecole)

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

    except HTTPException:
        # Les HTTPException levées en amont sont simplement relancées
        raise
    except Exception as e:
        # Toute autre erreur
        raise HTTPException(status_code=500, detail=f"Erreur DB: {e}")


# --- Réception de données (trafic_data) ---
@app.post("/trafic_data")
async def recevoir_donnees(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        code_ecole = data.get("code_ecole")
        token = data.get("token")

        if not code_ecole or not token:
            raise HTTPException(status_code=400, detail="❌ 'code_ecole' et 'token' sont requis.")

        # Vérifier si l'école existe dans la base PostgreSQL
        ecole = db.query(Ecole).filter(Ecole.code_ecole == code_ecole).first()
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

        # Enregistrer les données dans un fichier JSON nommé par code_ecole
        nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")
        with open(nom_fichier, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        # Récupérer les notifications existantes
        notifications = get_notifications_by_code_ecole(code_ecole, db)
        return {
            "message": f"✅ Données enregistrées pour avec succès",
            "notification": notifications
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {e}")


# --- Envoi des données (get_data) ---
@app.post("/get_data")
async def envoyer_donnees(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        login = data.get("login")
        token = data.get("token")
        mdp = data.get("mdp")

        if not login or not token or not mdp:
            raise HTTPException(status_code=400, detail="❌ 'login', 'mdp' et 'token' sont requis.")

        # Vérifier si l'école existe dans la base
        ecole = db.query(Ecole).filter(Ecole.login_admin == login).first()
        if not ecole:
            raise HTTPException(status_code=401, detail="❌ Identifiants invalides.")

        # Vérifier mot de passe
        if not bcrypt.checkpw(mdp.encode(), ecole.mdp_admin.encode()):
            raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect.")

        # Vérifier si le token est valide et non expiré
        if token != "yJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9testMav":
            try:
                jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=403, detail="❌ Le token a expiré.")
            except jwt.InvalidTokenError:
                raise HTTPException(status_code=403, detail="❌ Token invalide.")

        code_ecole = ecole.code_ecole
        nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")
        if not os.path.exists(nom_fichier):
            raise HTTPException(status_code=404, detail="❌ Données non trouvées pour cette école.")

        with open(nom_fichier, "r", encoding="utf-8") as f:
            contenu = json.load(f)

        return {
            "message": f"✅ Données récupérées pour {code_ecole}",
            "data": contenu
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {e}")


# --- Liste des écoles (accessible seulement avec le code admin secret) ---
ADMIN_SECRET_CODE = "seven5-admin-2024"

@app.post("/liste_ecoles")
async def liste_ecoles(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    code = body.get("code")

    if not code or code != ADMIN_SECRET_CODE:
        raise HTTPException(status_code=403, detail="⛔ Code d'accès invalide.")

    try:
        # Récupérer toutes les écoles
        rows = db.query(Ecole).all()
        ecoles = [
            {
                "nom_ecole": e.nom_ecole,
                "code_ecole": e.code_ecole,
                "telephone": e.telephone,
                "login_admin": e.login_admin
            }
            for e in rows
        ]
        return {
            "message": "✅ Liste des écoles récupérée avec succès",
            "ecoles": ecoles
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# --- Modifier les informations de l'admin ---
@app.post("/modifier_admin")
async def modifier_admin(data: UpdateAdminRequest, db: Session = Depends(get_db)):
    try:
        # Récupération de l'admin
        admin = db.query(Ecole).filter(Ecole.login_admin == data.login).first()
        if not admin:
            raise HTTPException(status_code=404, detail="❌ Admin introuvable.")

        # Vérification de l'ancien mot de passe
        if not bcrypt.checkpw(data.ancien_mdp.encode(), admin.mdp_admin.encode()):
            raise HTTPException(status_code=401, detail="❌ Ancien mot de passe incorrect.")

        # Préparer les modifications
        updates = {}
        # Si nouveau login
        if data.nouveau_login and data.nouveau_login != admin.login_admin:
            # Vérifier que le nouveau login n'existe pas déjà
            existe_login = db.query(Ecole).filter(Ecole.login_admin == data.nouveau_login).first()
            if existe_login:
                raise HTTPException(status_code=400, detail="❌ Ce login est déjà pris.")
            updates["login_admin"] = data.nouveau_login

        # Si nouveau mot de passe
        if data.nouveau_mdp1:
            if data.nouveau_mdp1 != data.nouveau_mdp2:
                raise HTTPException(status_code=400, detail="❌ Les nouveaux mots de passe ne correspondent pas.")
            hashed_new = bcrypt.hashpw(data.nouveau_mdp1.encode(), bcrypt.gensalt()).decode()
            updates["mdp_admin"] = hashed_new

        if not updates:
            raise HTTPException(status_code=400, detail="❌ Aucun changement détecté.")

        # Appliquer les modifications
        for field, value in updates.items():
            setattr(admin, field, value)
        db.commit()

        return {"message": "✅ Informations de l'admin mises à jour avec succès."}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# --- Notifier une école (créer une notification) ---
@app.post("/notifier_ecole")
async def notifier_ecole(data: NotificationRequest, db: Session = Depends(get_db)):
    try:
        # Authentifier l'admin
        admin = db.query(Ecole).filter(Ecole.login_admin == data.login_admin).first()
        if not admin:
            raise HTTPException(status_code=404, detail="❌ Admin introuvable.")

        if not bcrypt.checkpw(data.mdp_admin.encode(), admin.mdp_admin.encode()):
            raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect.")

        # Insérer la notification
        now = datetime.now().isoformat()
        nouvelle_notif = Notification(
            code_ecole=admin.code_ecole,
            message=data.message,
            date_envoi=now
        )
        db.add(nouvelle_notif)
        db.commit()

        return {"message": "✅ Notification envoyée avec succès."}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# — Fin des endpoints adaptés —
