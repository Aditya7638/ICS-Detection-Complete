from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import AuditLog, User, UserRole
from app.auth.security import admin_only, hash_password, verify_password, create_access_token, get_current_user
from app.schemas.schemas import RegisterRequest, TokenResponse, UserResponse, UserRoleUpdateRequest
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

@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(admin_only)):
    return db.query(User).order_by(User.created_at.asc()).all()

@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: str,
    req: UserRoleUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_only),
):
    active_admins = db.query(User).filter(
        User.role == UserRole.ADMIN,
        User.is_active.is_(True),
    ).order_by(User.id).with_for_update().all()
    target = db.query(User).filter(User.id == user_id).with_for_update().first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id and target.role != req.role:
        raise HTTPException(400, "You cannot change your own role.")
    if target.role == req.role:
        return target

    if target.role == UserRole.ADMIN and target.is_active:
        if len(active_admins) <= 1:
            raise HTTPException(400, "The last active administrator cannot be demoted.")

    previous_role = target.role
    target.role = req.role
    db.add(AuditLog(
        user_id=admin.id,
        action="user_role_updated",
        resource=target.id,
        detail={
            "target_username": target.username,
            "previous_role": previous_role.value if isinstance(previous_role, UserRole) else previous_role,
            "new_role": req.role.value,
        },
    ))
    db.commit()
    db.refresh(target)
    return target
