import sqlite3
import sys
from pathlib import Path
from app.crypto.key_manager import get_fernet

def restore(source,target='/tmp/restore_test.db'):
    raw=get_fernet().decrypt(Path(source).read_bytes())
    path=Path(target);path.write_bytes(raw)
    with sqlite3.connect(path) as con:
        print('integrity_check=',con.execute('PRAGMA integrity_check').fetchone()[0])
        print('users=',con.execute('SELECT count(*) FROM users').fetchone()[0])
    path.unlink(missing_ok=True)
if __name__=='__main__':restore(sys.argv[1])
