import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent.parent.parent / "securevault.db"
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

key_tables = ['users', 'customers', 'accounts', 'cards', 'trusted_devices']

for table in key_tables:
    cols = cursor.execute(f"PRAGMA table_info('{table}')").fetchall()
    print(f"=== {table} ===")
    for c in cols:
        print(f"  {c[1]}: {c[2]} (notnull={bool(c[3])}, default={c[4]}, pk={bool(c[5])})")
