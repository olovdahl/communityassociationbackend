# main.py
from fastapi import FastAPI, HTTPException, Depends, Form
from passlib.context import CryptContext
import redis
import uuid

app = FastAPI()
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Register endpoint
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...)):
    if r.hexists("users", username):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(password)
    r.hset("users", username, hashed_password)
    return {"msg": "User registered successfully"}

# Login endpoint
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    hashed_password = r.hget("users", username)
    if not hashed_password or not verify_password(password, hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = str(uuid.uuid4())
    r.set(f"session:{token}", username, ex=3600)  # 1 hour expiry
    return {"token": token}
