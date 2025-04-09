from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pydantic import BaseModel
import redis.asyncio as redis
import base64
import uuid
import os


load_dotenv()

app = FastAPI()
origins = [
    # "http://localhost:5174",
    os.environ.get("CORS_URL")
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

r = redis.Redis(
    host=os.environ.get("REDISHOST"),
    port=int(os.environ.get("REDISPORT")),
    # user=os.environ.get("REDISUSER"),
    password=os.environ.get("REDISPASSWORD"),
    db=0
)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


class NoteCreate(BaseModel):
    content: str
    password: str | None = None 
    ttl: int | None = None  # In seconds

@app.post("/create_note/")
async def create_note(note: NoteCreate):
    # Generate a random salt for each note
    salt = os.urandom(16)
    
    if note.password:
        encryption_key = derive_key(note.password, salt)  # Use password-based key
    else:
        encryption_key = Fernet.generate_key()  # Generate a random encryption key
    
    cipher = Fernet(encryption_key)
    encrypted_note = cipher.encrypt(note.content.encode())
    
    note_id = str(uuid.uuid4())
    
    # Store the encrypted note and salt in Redis with a TTL
    await r.hset(note_id, mapping={
        "encrypted_note": encrypted_note.decode(),
        "salt": base64.b64encode(salt).decode()
    })
    await r.expire(note_id, note.ttl)
    
    return {"note_id": note_id, "message": "Note created successfully"}



@app.get("/check_note/{note_id}")
async def check_note(note_id: str):
    """Checks if a note requires a password."""
    note_data = await r.hgetall(note_id)

    if not note_data:
        raise HTTPException(status_code=404, detail="Note not found or expired")

    # If an encryption key is stored, that means no password was required
    requires_password = not bool(note_data.get(b"encryption_key"))

    return {"requires_password": requires_password}


class NoteDecrypt(BaseModel):
    note_id: str
    password: str | None = None

@app.post("/get_note/")
async def get_note(note: NoteDecrypt):
    note_data = await r.hgetall(note.note_id)
    
    if not note_data:
        raise HTTPException(status_code=404, detail="Note not found or expired")

    salt = base64.b64decode(note_data.get(b"salt"))
    stored_encryption_key = note_data.get(b"encryption_key")

    if note.password:
        encryption_key = derive_key(note.password, salt)  # Derive key from password
    elif stored_encryption_key:
        encryption_key = stored_encryption_key.decode().encode()  # Use stored key
    else:
        raise HTTPException(status_code=400, detail="Invalid password or missing encryption key")

    # Decrypt note
    cipher = Fernet(encryption_key)
    try:
        decrypted_note = cipher.decrypt(note_data.get(b"encrypted_note")).decode()
        await r.delete(note.note_id)  # Delete note from Redis after reading
        return {"note_content": decrypted_note}
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")

