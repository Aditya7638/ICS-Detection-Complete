from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, UserRole
from app.auth.security import hash_password, verify_password, create_access_token, get_current_user
from app.schemas.schemas import RegisterRequest, TokenResponse, UserResponse
import uuid

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username already exists")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email already exists")
    user = User(id=str(uuid.uuid4()), username=req.username, email=req.email,
                password_hash=hash_password(req.password), role=UserRole.OPERATOR)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account inactive")
    token = create_access_token({"sub": user.id})
    return TokenResponse(access_token=token, token_type="bearer", role=user.role, username=user.username)

@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    return user
