"""
Database Schemas for LeierXpert

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
These are used for validation before inserting via database helpers.
"""
from __future__ import annotations
from typing import Optional, List, Literal, Dict, Any
from pydantic import BaseModel, Field, EmailStr

# Core users and auth
class User(BaseModel):
    email: EmailStr
    password_hash: str
    role: Literal["parent", "tutorA", "tutorB", "tutorC", "admin"]
    name: str = Field(..., description="Full name")
    language: Literal["de", "fr", "en"] = "de"
    avatar_url: Optional[str] = None
    is_verified: bool = False
    is_approved: bool = False  # Admin approval
    coins: int = 0
    level: int = 1
    badges: List[str] = []
    likes: int = 0
    bookings_count: int = 0

class TutorProfile(BaseModel):
    user_id: str
    category: Literal["A", "B", "C"]
    subjects: List[str] = []
    hourly_price: float = 25.0
    price_min: float = 15.0
    price_max: float = 80.0
    documents: Dict[str, Any] = {}  # stores file meta or URLs per type
    bio: Optional[str] = None
    boosts: int = 0
    rating: float = 0.0
    likes: int = 0

class Booking(BaseModel):
    parent_id: str
    tutor_id: str
    subject: str
    start_time: str  # ISO string
    end_time: str    # ISO string
    status: Literal["pending", "confirmed", "completed", "canceled"] = "pending"
    notes: Optional[str] = None

class Report(BaseModel):
    booking_id: str
    tutor_id: str
    parent_id: str
    title: str
    content: Optional[str] = None
    attachments: List[Dict[str, Any]] = []  # {name, type, size, data?(base64 truncated)}

class ChatMessage(BaseModel):
    room_id: str  # e.g., parentId_tutorId
    sender_id: str
    receiver_id: str
    text: Optional[str] = None
    attachments: List[Dict[str, Any]] = []
    read: bool = False

class Emergency(BaseModel):
    user_id: str
    context: Literal["parent", "tutor"]
    message: str
    priority: Literal["low", "medium", "high", "critical"] = "high"
    status: Literal["open", "acknowledged", "resolved"] = "open"

class ShopItem(BaseModel):
    title: str
    description: Optional[str] = None
    price_coins: int
    kind: Literal["boost", "item"] = "boost"
    active: bool = True

class Notification(BaseModel):
    user_id: str
    kind: str
    title: str
    body: str
    read: bool = False

# Simple stats logs
class KILog(BaseModel):
    user_id: Optional[str] = None
    action: str
    payload: Dict[str, Any] = {}
