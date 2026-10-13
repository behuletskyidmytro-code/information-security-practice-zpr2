import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime,timezone
from app.database import DATABASE_URL
from app.crypto.key_manager import get_fernet

def backup():
    path=Path(DATABASE_URL.replace('sqlite:///',''))
    if not path.exists():raise FileNotFoundError(path)
    out_dir=path.parent/'backups';out_dir.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(suffix='.db');os.close(fd)
    try:
        with sqlite3.connect(path) as src,sqlite3.connect(tmp) as dst:src.backup(dst)
        raw=Path(tmp).read_bytes()
    finally:Path(tmp).unlink(missing_ok=True)
    out=out_dir/('app_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.db.enc')
    out.write_bytes(get_fernet().encrypt(raw));out.chmod(0o600)
    print('Backup:',out,'SHA256:',hashlib.sha256(out.read_bytes()).hexdigest())
    for old in sorted(out_dir.glob('app_*.db.enc'))[:-7]:old.unlink()
    return out
if __name__=='__main__':backup()
