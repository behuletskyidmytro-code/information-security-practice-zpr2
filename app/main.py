import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import User, AuditLog, Role
from app.crypto.key_manager import get_fernet, get_blind_index_key
from app.crypto.encryption import blind_index
from app.security import verify_password, hash_password, create_access_token, create_refresh_token, decode_access_token
from app.audit.logger import log_event
from app.audit.detector import check_brute_force, get_security_stats

get_fernet(); get_blind_index_key()
app=FastAPI(title='Електронний деканат',description='ЗПР-2: захист даних, аудит, hardening',version='2.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:3000','https://localhost'],allow_credentials=False,allow_methods=['GET','POST'],allow_headers=['Authorization','Content-Type'])

@app.middleware('http')
async def security_and_audit(request:Request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:"
    code=response.status_code
    if code in (401,403,429) or code>=500 or (request.method in ('POST','PUT','DELETE') and request.url.path!='/auth/login'):
        action={401:'unauthorized',403:'access_denied',429:'rate_limited'}.get(code,'server_error' if code>=500 else 'http_'+request.method.lower())
        db=SessionLocal()
        try:
            log_event(db,action,'failure' if code>=400 else 'success',request.client.host if request.client else 'unknown',http_method=request.method,endpoint=request.url.path,status_code=code)
        finally: db.close()
    return response

login_attempts=defaultdict(deque)
def limit_login(ip):
    now=time.monotonic();q=login_attempts[ip]
    while q and now-q[0]>=60:q.popleft()
    if len(q)>=5:raise HTTPException(429,'Too many login requests',headers={'Retry-After':'60'})
    q.append(now)
def get_db():
    db=SessionLocal()
    try:yield db
    finally:db.close()
oauth2=OAuth2PasswordBearer(tokenUrl='/auth/token')
def get_current_user(token:str=Depends(oauth2),db:Session=Depends(get_db)):
    try:username=decode_access_token(token)['sub']
    except Exception:raise HTTPException(401,'Invalid or expired access token')
    user=db.query(User).filter(User.username==username).first()
    if not user:raise HTTPException(401,'User not found')
    return user
def require_role(role):
    def checker(user:User=Depends(get_current_user)):
        if role not in [r.name for r in user.roles]:raise HTTPException(403,'Access forbidden')
        return user
    return checker
class LoginRequest(BaseModel):
    username:str
    password:str
class RefreshRequest(BaseModel):
    refresh_token:str
class RegisterRequest(BaseModel):
    username:str=Field(min_length=3,max_length=50)
    password:str=Field(min_length=8)
    email:EmailStr
    full_name:str=Field(min_length=1,max_length=150)
    phone:str|None=None
@app.get('/health',tags=['System'])
def health():return {'status':'ok'}
@app.post('/auth/login',tags=['Authentication'])
def login(request:Request,credentials:LoginRequest,db:Session=Depends(get_db)):
    ip=request.client.host if request.client else 'unknown'
    if check_brute_force(db,ip,credentials.username):raise HTTPException(429,'Brute force detected; wait 5 minutes')
    limit_login(ip)
    user=db.query(User).filter(User.username==credentials.username).first()
    if not user or not verify_password(credentials.password,user.password_hash):
        log_event(db,'login_failed','failure',ip,username=credentials.username,endpoint='/auth/login',status_code=401)
        raise HTTPException(401,'Incorrect username or password')
    log_event(db,'login_success','success',ip,user_id=user.id,username=user.username,endpoint='/auth/login',status_code=200)
    if 0<=datetime.now(timezone(timedelta(hours=3))).hour<6:
        log_event(db,'off_hours_login','warning',ip,user_id=user.id,username=user.username)
    return {'access_token':create_access_token(user.username),'refresh_token':create_refresh_token(user.username),'token_type':'bearer'}
@app.post('/auth/refresh',tags=['Authentication'])
def refresh(data:RefreshRequest,db:Session=Depends(get_db)):
    try:username=decode_access_token(data.refresh_token,'refresh')['sub']
    except Exception:raise HTTPException(401,'Invalid refresh token')
    if not db.query(User).filter(User.username==username).first():raise HTTPException(401,'Unknown user')
    return {'access_token':create_access_token(username),'token_type':'bearer'}
@app.post('/auth/register',status_code=201,tags=['Authentication'])
def register(request:Request,data:RegisterRequest,db:Session=Depends(get_db)):
    if db.query(User).filter(User.username==data.username).first():raise HTTPException(409,'Username already exists')
    if db.query(User).filter(User.email_index==blind_index(str(data.email))).first():raise HTTPException(409,'Email already exists')
    user=User(username=data.username,password_hash=hash_password(data.password),full_name=data.full_name)
    user.email=str(data.email);user.phone=data.phone
    role=db.query(Role).filter_by(name='student').first()
    if role:user.roles.append(role)
    db.add(user);db.commit();db.refresh(user)
    log_event(db,'user_registered','success',request.client.host if request.client else 'unknown',user_id=user.id,username=user.username)
    return {'username':user.username,'email':user.email}
@app.get('/auth/me',tags=['Authentication'])
def me(user:User=Depends(get_current_user)):
    return {'username':user.username,'email':user.email,'phone':user.phone,'roles':[r.name for r in user.roles]}
@app.get('/students',tags=['Students'])
def students(user:User=Depends(get_current_user)):return {'message':'Students endpoint'}
@app.get('/teachers',tags=['Teachers'])
def teachers(user:User=Depends(get_current_user)):return {'message':'Teachers endpoint'}
@app.get('/admin/users',tags=['Admin'])
def admin_users(db:Session=Depends(get_db),admin:User=Depends(require_role('admin'))):
    return {'users':[{'username':u.username,'email':u.email} for u in db.query(User).all()]}
@app.get('/admin/audit-log',tags=['Audit'])
def audit_log(request:Request,action:str|None=None,hours:int=Query(24,ge=1,le=720),limit:int=Query(50,ge=1,le=200),db:Session=Depends(get_db),admin:User=Depends(require_role('admin'))):
    since=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(hours=hours)
    q=db.query(AuditLog).filter(AuditLog.timestamp>=since)
    if action:q=q.filter(AuditLog.action==action)
    total=q.count();rows=q.order_by(AuditLog.id.desc()).limit(limit).all()
    log_event(db,'audit_log_viewed','success',request.client.host if request.client else 'unknown',user_id=admin.id,username=admin.username)
    return {'total':total,'logs':[{'id':r.id,'action':r.action,'status':r.status,'username':r.username,'ip_address':r.ip_address,'timestamp':r.timestamp.isoformat(),'status_code':r.status_code,'details':r.details} for r in rows]}
@app.get('/admin/security-stats',tags=['Audit'])
def security_stats(hours:int=Query(24,ge=1,le=720),db:Session=Depends(get_db),admin:User=Depends(require_role('admin'))):return get_security_stats(db,hours)

@app.post('/auth/token',tags=['Authentication'])
def login_swagger(request:Request,form:OAuth2PasswordRequestForm=Depends(),db:Session=Depends(get_db)):
    return login(request,LoginRequest(username=form.username,password=form.password),db)
