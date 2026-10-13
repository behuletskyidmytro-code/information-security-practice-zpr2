from datetime import datetime, timedelta, timezone
from sqlalchemy import or_, func
from app.models import AuditLog
from app.audit.logger import log_event

def check_brute_force(db,ip,username,threshold=5,window_minutes=5):
    since=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(minutes=window_minutes)
    n=db.query(func.count(AuditLog.id)).filter(AuditLog.action=='login_failed',AuditLog.timestamp>=since,or_(AuditLog.ip_address==ip,AuditLog.username==username)).scalar()
    if n>=threshold:
        log_event(db,'brute_force_detected','warning',ip,username=username,details={'failed_attempts':n})
        return True
    return False

def get_security_stats(db,hours=24):
    since=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(hours=hours)
    rows=db.query(AuditLog.action,func.count(AuditLog.id)).filter(AuditLog.timestamp>=since).group_by(AuditLog.action).all()
    counts=dict(rows)
    return {'period_hours':hours,'total_events':sum(counts.values()),'failed_logins':counts.get('login_failed',0),'access_denied':counts.get('access_denied',0),'brute_force_alerts':counts.get('brute_force_detected',0),'events_by_action':counts}
