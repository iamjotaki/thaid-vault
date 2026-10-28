import sqlite3
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

conn = sqlite3.connect(r'C:\ThaiD-Vault\vault.db')
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = c.fetchall()
print('Tables:', tables)
for t in tables:
    t_name = t[0]
    c.execute(f'SELECT count(*) FROM {t_name}')
    count = c.fetchone()[0]
    print(f'\nTable {t_name}: {count} rows')
    c.execute(f'PRAGMA table_info({t_name})')
    cols = [col[1] for col in c.fetchall()]
    print(f'  Columns: {cols}')
    c.execute(f'SELECT * FROM {t_name}')
    rows = c.fetchall()
    for r in rows:
        print('  Row:', r)

conn.close()
