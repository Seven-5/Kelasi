# main_app.py
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
from sqlalchemy import text
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

# --- Configuration non modifiée (avec dossier JSON pour fallback) ---
DOSSIER_JSON = "/tmp/ecoles_json"
os.makedirs(DOSSIER_JSON, exist_ok=True)
NOTIF_DIR = os.path.join(DOSSIER_JSON, "notifications")
os.makedirs(NOTIF_DIR, exist_ok=True)

SECRET_KEY = "mrfrijoseven5officemanager"
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 30

# --- pydantic models pour les endpoints ---
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

# --- Helper: vérifier la disponibilité de la DB ---
def is_db_available() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

# --- Helper: chemins JSON / opérations JSON fallback ---
def school_json_path(code_ecole: str) -> str:
    safe_code = str(code_ecole)
    return os.path.join(DOSSIER_JSON, f"{safe_code}.json")

def save_school_json(data: dict) -> str:
    """
    Sauvegarde/écrase le fichier JSON correspondant au code_ecole.
    Retourne le chemin du fichier.
    """
    code = data.get("code_ecole") or data.get("code") or data.get("codeEcole")
    if not code:
        # fallback: filename by timestamp
        filename = f"ecole_{int(datetime.utcnow().timestamp())}.json"
        path = os.path.join(DOSSIER_JSON, filename)
    else:
        path = school_json_path(code)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return path

def load_school_json_by_login(login: str):
    """
    Parcourt les fichiers JSON et retourne le premier fichier dont login_admin == login.
    """
    for fname in os.listdir(DOSSIER_JSON):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(DOSSIER_JSON, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("login_admin") == login:
                return data, path
        except Exception:
            continue
    return None, None

def load_school_json_by_code(code_ecole: str):
    path = school_json_path(code_ecole)
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data, path
    except Exception:
        return None, None

def list_schools_from_json():
    out = []
    for fname in os.listdir(DOSSIER_JSON):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(DOSSIER_JSON, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            out.append({
                "nom_ecole": data.get("nom_ecole"),
                "code_ecole": data.get("code_ecole"),
                "telephone": data.get("telephone"),
                "login_admin": data.get("login_admin"),
                "json_path": path
            })
        except Exception:
            continue
    return out

def save_notification_json(code_ecole: str, message: str):
    fname = os.path.join(NOTIF_DIR, f"{code_ecole}_notifications.json")
    now = datetime.now().isoformat()
    existing = []
    if os.path.exists(fname):
        try:
            with open(fname, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.insert(0, {"message": message, "date_envoi": now})
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)
    return fname

def load_notifications_json(code_ecole: str):
    fname = os.path.join(NOTIF_DIR, f"{code_ecole}_notifications.json")
    if not os.path.exists(fname):
        return []
    try:
        with open(fname, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return []

# --- Fonction adaptée : get_notifications_by_code_ecole ---
def get_notifications_by_code_ecole(code_ecole: str, db: Session):
    try:
        if is_db_available():
            # On interroge la table Notification (SQLAlchemy ORM) 
            rows = db.query(Notification)\
                     .filter(Notification.code_ecole == code_ecole)\
                     .order_by(Notification.date_envoi.desc())\
                     .all()
            return [{"message": r.message, "date": r.date_envoi} for r in rows]
        else:
            # Fallback: lire fichier JSON des notifications
            notifs = load_notifications_json(code_ecole)
            # adapter structure
            return [{"message": n.get("message"), "date": n.get("date_envoi")} for n in notifs]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur DB/JSON: {e}")

# --- Fonction adaptée : create_table (inchangée) ---
def create_table():
    """
    Utilise SQLAlchemy pour créer les tables si elles n'existent pas.
    """
    try:
        Base.metadata.create_all(bind=engine)
    except Exception:
        # si la création échoue on laisse faire la bascule JSON au runtime
        pass

# Appel initial pour créer les tables sur le démarrage (tentative)
create_table()

# --- La fonction create_token reste inchangée ---
def create_token(data: dict, expires_days: int = TOKEN_EXPIRE_DAYS):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=expires_days)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

# --- Endpoint de test ---
@app.get("/ping")
async def ping():
    return {
        "message": "✅ L'API fonctionne parfaitement",
        "status": "OK",
        "db_available": is_db_available()
    }


# --- Inscription d'une école (avec fallback JSON si DB indisponible) ---
@app.post("/inscription_ecole")
async def inscription_ecole(req: EcoleRequest, db: Session = Depends(get_db)):
    try:
        # Hash des mots de passe (toujours fait)
        hashed_mdp_ecole = bcrypt.hashpw(req.mdp_ecole.encode(), bcrypt.gensalt()).decode()
        hashed_mdp_admin = bcrypt.hashpw(req.mdp_admin.encode(), bcrypt.gensalt()).decode()

        token_data = {
            "nom_ecole": req.nom_ecole,
            "code_ecole": req.code_ecole
        }
        token = create_token(token_data)

        if not is_db_available():
            # DB indisponible -> sauvegarde en JSON
            payload = {
                "nom_ecole": req.nom_ecole,
                "code_ecole": req.code_ecole,
                "telephone": req.telephone,
                "mdp_ecole": hashed_mdp_ecole,
                "login_admin": req.login_admin,
                "mdp_admin": hashed_mdp_admin,
                "created_at": datetime.utcnow().isoformat(),
                "pending_db": True
            }

            # vérifier doublon local (fichiers JSON) sur nom ou login ou code
            # éviter d'écraser sans contrôle
            # si fichier code existe -> considérer comme existant
            path_code = school_json_path(req.code_ecole)
            if os.path.exists(path_code):
                raise HTTPException(status_code=400, detail="⚠️ L'école existe déjà dans les sauvegardes JSON (même code).")

            # vérifier login existant dans JSON
            existing_data, _ = load_school_json_by_login(req.login_admin)
            if existing_data:
                raise HTTPException(status_code=400, detail="⚠️ Ce login admin est déjà utilisé dans les sauvegardes JSON.")

            saved_path = save_school_json(payload)
            return {
                "message": "✅ DB inaccessible — école sauvegardée temporairement en JSON",
                "token": token,
                "token_exp": TOKEN_EXPIRE_DAYS,
                "json_path": saved_path
            }

        # Si DB disponible -> logique d'origine (vérifications DB)
        existe_nom = db.query(Ecole).filter(Ecole.nom_ecole == req.nom_ecole).first()
        if existe_nom:
            raise HTTPException(status_code=400, detail="⚠️ L'école existe déjà")

        existe_login = db.query(Ecole).filter(Ecole.login_admin == req.login_admin).first()
        if existe_login:
            raise HTTPException(status_code=400, detail="⚠️ Ce login admin est déjà utilisé")

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

        return {
            "message": "✅ École enregistrée avec succès",
            "token": token,
            "token_exp": TOKEN_EXPIRE_DAYS
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur DB/JSON: {e}")


# --- Réception de données (trafic_data) ---
@app.post("/trafic_data")
async def recevoir_donnees(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        code_ecole = data.get("code_ecole")
        token = data.get("token")

        if not code_ecole or not token:
            raise HTTPException(status_code=400, detail="❌ 'code_ecole' et 'token' sont requis.")

        if is_db_available():
            # Vérifier si l'école existe dans la base PostgreSQL
            ecole = db.query(Ecole).filter(Ecole.code_ecole == code_ecole).first()
            if not ecole:
                # si DB disponible mais école inconnue -> erreur comme auparavant
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

            # Enregistrer les données dans un fichier JSON nommé par code_ecole (log local)
            nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")
            with open(nom_fichier, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            notifications = get_notifications_by_code_ecole(code_ecole, db)
            return {
                "message": f"✅ Données enregistrées avec succès (DB disponible)",
                "notification": notifications,
                "json_path": nom_fichier
            }

        else:
            # DB indisponible -> on sauvegarde la payload directement (sans vérification DB)
            nom_fichier = os.path.join(DOSSIER_JSON, f"{code_ecole}.json")
            with open(nom_fichier, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            # On peut aussi écrire une notification JSON vide si nécessaire
            notifications = load_notifications_json(code_ecole)
            return {
                "message": "✅ DB inaccessible — données sauvegardées en JSON",
                "notification": notifications,
                "json_path": nom_fichier
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

        if is_db_available():
            ecole = db.query(Ecole).filter(Ecole.login_admin == login).first()
            if not ecole:
                raise HTTPException(status_code=401, detail="❌ Identifiants invalides.")

            if not bcrypt.checkpw(mdp.encode(), ecole.mdp_admin.encode()):
                raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect.")

            # Vérifier token
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

        else:
            # DB indisponible -> chercher fichier JSON par login
            found, path = load_school_json_by_login(login)
            if not found:
                raise HTTPException(status_code=404, detail="❌ Données non trouvées (DB inaccessible et aucun JSON pour ce login).")

            # Vérifier mot de passe (stocké hashed dans le JSON si provient d'inscription)
            stored_hashed = found.get("mdp_admin")
            if not stored_hashed or not bcrypt.checkpw(mdp.encode(), stored_hashed.encode()):
                raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect (JSON fallback).")

            # Vérifier token
            try:
                jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=403, detail="❌ Le token a expiré.")
            except jwt.InvalidTokenError:
                raise HTTPException(status_code=403, detail="❌ Token invalide.")

            return {
                "message": f"✅ Données récupérées (JSON fallback) pour {found.get('code_ecole')}",
                "data": found,
                "json_path": path
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
        if is_db_available():
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
        else:
            # Fallback: lister les fichiers JSON
            ecoles = list_schools_from_json()
            return {
                "message": "✅ DB inaccessible — liste récupérée depuis JSON",
                "ecoles": ecoles
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# --- Modifier les informations de l'admin ---
@app.post("/modifier_admin")
async def modifier_admin(data: UpdateAdminRequest, db: Session = Depends(get_db)):
    try:
        if is_db_available():
            admin = db.query(Ecole).filter(Ecole.login_admin == data.login).first()
            if not admin:
                raise HTTPException(status_code=404, detail="❌ Admin introuvable.")

            if not bcrypt.checkpw(data.ancien_mdp.encode(), admin.mdp_admin.encode()):
                raise HTTPException(status_code=401, detail="❌ Ancien mot de passe incorrect.")

            updates = {}
            if data.nouveau_login and data.nouveau_login != admin.login_admin:
                existe_login = db.query(Ecole).filter(Ecole.login_admin == data.nouveau_login).first()
                if existe_login:
                    raise HTTPException(status_code=400, detail="❌ Ce login est déjà pris.")
                updates["login_admin"] = data.nouveau_login

            if data.nouveau_mdp1:
                if data.nouveau_mdp1 != data.nouveau_mdp2:
                    raise HTTPException(status_code=400, detail="❌ Les nouveaux mots de passe ne correspondent pas.")
                hashed_new = bcrypt.hashpw(data.nouveau_mdp1.encode(), bcrypt.gensalt()).decode()
                updates["mdp_admin"] = hashed_new

            if not updates:
                raise HTTPException(status_code=400, detail="❌ Aucun changement détecté.")

            for field, value in updates.items():
                setattr(admin, field, value)
            db.commit()

            return {"message": "✅ Informations de l'admin mises à jour avec succès."}
        else:
            # Fallback JSON: chercher par login dans JSON files
            found, path = load_school_json_by_login(data.login)
            if not found:
                raise HTTPException(status_code=404, detail="❌ Admin introuvable (JSON fallback).")

            if not bcrypt.checkpw(data.ancien_mdp.encode(), found.get("mdp_admin", "").encode()):
                raise HTTPException(status_code=401, detail="❌ Ancien mot de passe incorrect (JSON fallback).")

            updates_made = False
            if data.nouveau_login and data.nouveau_login != found.get("login_admin"):
                # vérifier doublon dans JSON
                exists, _ = load_school_json_by_login(data.nouveau_login)
                if exists:
                    raise HTTPException(status_code=400, detail="❌ Ce login est déjà pris (JSON fallback).")
                found["login_admin"] = data.nouveau_login
                updates_made = True

            if data.nouveau_mdp1:
                if data.nouveau_mdp1 != data.nouveau_mdp2:
                    raise HTTPException(status_code=400, detail="❌ Les nouveaux mots de passe ne correspondent pas.")
                hashed_new = bcrypt.hashpw(data.nouveau_mdp1.encode(), bcrypt.gensalt()).decode()
                found["mdp_admin"] = hashed_new
                updates_made = True

            if not updates_made:
                raise HTTPException(status_code=400, detail="❌ Aucun changement détecté (JSON fallback).")

            # sauvegarder fichier JSON mis à jour
            save_school_json(found)
            return {"message": "✅ Informations de l'admin mises à jour (JSON fallback).", "json_path": path}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# --- Notifier une école (créer une notification) ---
@app.post("/notifier_ecole")
async def notifier_ecole(data: NotificationRequest, db: Session = Depends(get_db)):
    try:
        if is_db_available():
            admin = db.query(Ecole).filter(Ecole.login_admin == data.login_admin).first()
            if not admin:
                raise HTTPException(status_code=404, detail="❌ Admin introuvable.")

            if not bcrypt.checkpw(data.mdp_admin.encode(), admin.mdp_admin.encode()):
                raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect.")

            now = datetime.now().isoformat()
            nouvelle_notif = Notification(
                code_ecole=admin.code_ecole,
                message=data.message,
                date_envoi=now
            )
            db.add(nouvelle_notif)
            db.commit()

            return {"message": "✅ Notification envoyée avec succès."}
        else:
            # fallback: verifier login dans fichiers JSON
            found, path = load_school_json_by_login(data.login_admin)
            if not found:
                raise HTTPException(status_code=404, detail="❌ Admin introuvable (JSON fallback).")

            if not bcrypt.checkpw(data.mdp_admin.encode(), found.get("mdp_admin", "").encode()):
                raise HTTPException(status_code=401, detail="❌ Mot de passe incorrect (JSON fallback).")

            code_ecole = found.get("code_ecole") or found.get("code")
            notif_path = save_notification_json(code_ecole, data.message)
            return {"message": "✅ Notification sauvegardée (JSON fallback).", "notif_path": notif_path}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur serveur : {e}")


# — Fin des endpoints adaptés —
