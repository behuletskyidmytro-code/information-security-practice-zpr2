import os
from app.database import SessionLocal
from app.models import User, Role, Permission
from app.security import hash_password

def seed():
    db=SessionLocal()
    try:
        roles={}
        for name in ('admin','teacher','student'):
            role=db.query(Role).filter_by(name=name).first()
            if role is None:role=Role(name=name);db.add(role);db.flush()
            roles[name]=role
        for username,role_name in (('admin','admin'),('teacher','teacher'),('student','student')):
            if not db.query(User).filter_by(username=username).first():
                password=os.environ.get('SEED_'+role_name.upper()+'_PASSWORD')
                if not password:raise RuntimeError('Set SEED_'+role_name.upper()+'_PASSWORD in .env')
                user=User(username=username,password_hash=hash_password(password),full_name='Test '+role_name)
                user.email=username+'@example.test';user.roles.append(roles[role_name]);db.add(user)
        db.commit();print('Seed complete')
    except Exception:db.rollback();raise
    finally:db.close()
if __name__=='__main__':seed()
