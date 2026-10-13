import json
import logging
from app.models import AuditLog
logger=logging.getLogger('security_audit')
SENSITIVE={'password','token','access_token','refresh_token','secret','key','email','phone'}
def log_event(db, action, status, ip_address, *, user_id=None, username=None, http_method=None, endpoint=None, status_code=None, resource=None, details=None):
    clean={k:('***' if k.lower() in SENSITIVE else v) for k,v in (details or {}).items()}
    try:
        db.add(AuditLog(action=action,status=status,ip_address=ip_address,user_id=user_id,username=username,http_method=http_method,endpoint=endpoint,status_code=status_code,resource=resource,details=json.dumps(clean,ensure_ascii=False)))
        db.commit()
    except Exception:
        db.rollback();logger.exception('audit_write_failed')
    logger.warning(json.dumps({'action':action,'status':status,'ip':ip_address,'username':username,'code':status_code,'details':clean},ensure_ascii=False))
