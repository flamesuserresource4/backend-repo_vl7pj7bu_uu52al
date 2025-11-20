import os
import hashlib
import secrets
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from database import db, create_document, get_documents
from schemas import User, TutorProfile, Booking, Report, ChatMessage, Emergency, ShopItem, Notification
from bson import ObjectId

app = FastAPI(title="LeierXpert API", version="0.1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helpers ---
SALT = os.getenv("AUTH_SALT", "leierxpert_salt")

def hash_password(pw: str) -> str:
    return hashlib.sha256((SALT + pw).encode()).hexdigest()

class Token(BaseModel):
    token: str
    user_id: str
    role: str


def oid(val: Any) -> ObjectId:
    if isinstance(val, ObjectId):
        return val
    try:
        return ObjectId(str(val))
    except Exception:
        raise HTTPException(400, detail="Invalid id format")


def get_user_by_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.replace("Bearer ", "").strip()
    session = db["token"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    user["id"] = str(user["_id"])
    return user

# --- Health ---
@app.get("/")
def root():
    return {"name": "LeierXpert API", "status": "ok"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Error {str(e)[:60]}"
    return response

# --- Auth ---
class RegisterPayload(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str  # parent | tutorA | tutorB | tutorC | admin
    language: str = "de"
    documents: Optional[Dict[str, Any]] = None  # for tutors

@app.post("/auth/register")
def register(payload: RegisterPayload):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(400, detail="E-Mail bereits registriert")
    is_admin = payload.role == "admin"
    is_tutor = payload.role.startswith("tutor")
    user_doc = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        name=payload.name,
        language=payload.language,
        is_verified=not is_tutor,  # simple default
        is_approved=is_admin or (not is_tutor)
    ).model_dump()
    user_id = create_document("user", user_doc)

    if is_tutor:
        category = payload.role[-1].upper()  # A/B/C
        tp = TutorProfile(
            user_id=user_id,
            category=category,
            documents=payload.documents or {},
        ).model_dump()
        create_document("tutorprofile", tp)

    # Auto-create a default coin shop items once if empty
    if db["shopitem"].count_documents({}) == 0:
        items = [
            ShopItem(title="Boost 24h", description="Sichtbarkeit +50% für 24 Stunden", price_coins=50).model_dump(),
            ShopItem(title="Profil-Rahmen Gold", description="Hebe dich visuell ab", price_coins=120, kind="item").model_dump(),
        ]
        for it in items:
            create_document("shopitem", it)

    return {"message": "Registrierung erfolgreich", "user_id": user_id}

class LoginPayload(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/login")
def login(payload: LoginPayload):
    user = db["user"].find_one({"email": payload.email})
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(401, detail="Ungültige Anmeldedaten")
    if user["role"] != "admin" and not user.get("is_approved"):
        raise HTTPException(403, detail="Warten auf Admin-Freigabe")
    token = secrets.token_hex(24)
    db["token"].insert_one({"token": token, "user_id": user["_id"], "role": user["role"]})
    return {"token": token, "role": user["role"], "name": user.get("name"), "language": user.get("language", "de")}

@app.get("/me")
def me(user=Depends(get_user_by_token)):
    user.pop("password_hash", None)
    return user

# --- Public tutor listing with filters ---
@app.get("/tutors")
def list_tutors(filter: Optional[str] = None, limit: int = 30):
    query: Dict[str, Any] = {"role": {"$regex": "^tutor"}, "is_approved": True}
    sort = [("bookings_count", -1)] if filter == "most_booked" else [("likes", -1)] if filter == "most_liked" else [("boosts", -1), ("likes", -1)] if filter == "ai" else [("likes", -1)]
    cur = db["user"].find(query).sort(sort).limit(limit)
    results = []
    for u in cur:
        prof = db["tutorprofile"].find_one({"user_id": str(u["_id"])})
        results.append({
            "id": str(u["_id"]),
            "name": u.get("name"),
            "likes": u.get("likes", 0),
            "bookings_count": u.get("bookings_count", 0),
            "rating": (prof or {}).get("rating", 0),
            "subjects": (prof or {}).get("subjects", []),
            "hourly_price": (prof or {}).get("hourly_price", 25.0),
            "category": (prof or {}).get("category", "A")
        })
    return results

# --- Bookings ---
class CreateBookingPayload(BaseModel):
    tutor_id: str
    subject: str
    start_time: str
    end_time: str
    notes: Optional[str] = None

@app.post("/bookings")
def create_booking(payload: CreateBookingPayload, user=Depends(get_user_by_token)):
    if user["role"] != "parent":
        raise HTTPException(403, detail="Nur Eltern können buchen")
    b = Booking(parent_id=str(user["_id"]), tutor_id=payload.tutor_id, subject=payload.subject, start_time=payload.start_time, end_time=payload.end_time, notes=payload.notes).model_dump()
    bid = create_document("booking", b)
    # increment tutor stat
    db["user"].update_one({"_id": oid(payload.tutor_id)}, {"$inc": {"bookings_count": 1}})
    return {"booking_id": bid}

@app.get("/bookings")
def my_bookings(user=Depends(get_user_by_token)):
    role = user["role"]
    query = {"parent_id": str(user["_id"]) } if role == "parent" else {"tutor_id": str(user["_id"]) } if role.startswith("tutor") else {}
    docs = get_documents("booking", query, limit=200)
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

# --- Reports ---
class ReportPayload(BaseModel):
    booking_id: str
    title: str
    content: Optional[str] = None
    attachments: Optional[List[Dict[str, Any]]] = None

@app.post("/reports")
def create_report(payload: ReportPayload, user=Depends(get_user_by_token)):
    if not user["role"].startswith("tutor"):
        raise HTTPException(403, detail="Nur Tutor")
    booking = db["booking"].find_one({"_id": oid(payload.booking_id)})
    if not booking:
        raise HTTPException(404, detail="Buchung nicht gefunden")
    r = Report(
        booking_id=payload.booking_id,
        tutor_id=str(user["_id"]),
        parent_id=booking["parent_id"],
        title=payload.title,
        content=payload.content,
        attachments=payload.attachments or [],
    ).model_dump()
    rid = create_document("report", r)
    return {"report_id": rid}

@app.get("/reports")
def list_reports(user=Depends(get_user_by_token)):
    role = user["role"]
    query = {"parent_id": str(user["_id"]) } if role == "parent" else {"tutor_id": str(user["_id"]) } if role.startswith("tutor") else {}
    docs = get_documents("report", query, limit=200)
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

# --- Notifications ---
@app.get("/notifications")
def my_notifications(user=Depends(get_user_by_token)):
    docs = get_documents("notification", {"user_id": str(user["_id"])}, limit=200)
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

# --- Emergency ---
class EmergencyPayload(BaseModel):
    message: str
    priority: Optional[str] = "high"

@app.post("/emergency")
def trigger_emergency(payload: EmergencyPayload, user=Depends(get_user_by_token)):
    e = Emergency(user_id=str(user["_id"]), context="parent" if user["role"] == "parent" else "tutor", message=payload.message, priority=payload.priority or "high").model_dump()
    eid = create_document("emergency", e)
    # simple notify admins
    admins = db["user"].find({"role": "admin"})
    for a in admins:
        create_document("notification", Notification(user_id=str(a["_id"]), kind="emergency", title="Notfall", body=e["message"]).model_dump())
    return {"emergency_id": eid}

# --- Shop ---
@app.get("/shop")
def shop_items():
    docs = get_documents("shopitem", {}, limit=200)
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

class BuyPayload(BaseModel):
    item_id: str

@app.post("/shop/buy")
def buy_item(payload: BuyPayload, user=Depends(get_user_by_token)):
    item = db["shopitem"].find_one({"_id": oid(payload.item_id)})
    if not item:
        raise HTTPException(404, detail="Item nicht gefunden")
    if user.get("coins", 0) < item.get("price_coins", 0):
        raise HTTPException(400, detail="Nicht genug Coins")
    db["user"].update_one({"_id": user["_id"]}, {"$inc": {"coins": -item["price_coins"]}})
    if item.get("kind") == "boost":
        db["tutorprofile"].update_one({"user_id": str(user["_id"])}, {"$inc": {"boosts": 1}})
    return {"status": "ok"}

# --- Admin endpoints ---
@app.get("/admin/pending")
def admin_pending(user=Depends(get_user_by_token)):
    if user["role"] != "admin":
        raise HTTPException(403, detail="Nur Admin")
    docs = list(db["user"].find({"is_approved": False}))
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

class ApprovePayload(BaseModel):
    user_id: str
    approve: bool = True

@app.post("/admin/approve")
def admin_approve(payload: ApprovePayload, user=Depends(get_user_by_token)):
    if user["role"] != "admin":
        raise HTTPException(403, detail="Nur Admin")
    db["user"].update_one({"_id": oid(payload.user_id)}, {"$set": {"is_approved": payload.approve}})
    return {"status": "ok"}

# Simple schemas endpoint
@app.get("/schema")
def get_schema():
    return {
        "User": User.model_json_schema(),
        "TutorProfile": TutorProfile.model_json_schema(),
        "Booking": Booking.model_json_schema(),
        "Report": Report.model_json_schema(),
        "ChatMessage": ChatMessage.model_json_schema(),
        "Emergency": Emergency.model_json_schema(),
        "ShopItem": ShopItem.model_json_schema(),
        "Notification": Notification.model_json_schema(),
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
