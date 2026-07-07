import subprocess, hashlib, sqlite3, yaml

def run_cmd(user_input):
    # semgrep: dangerous-subprocess-use / command-injection
    subprocess.run(user_input, shell=True)

def get_user(db, name):
    # semgrep: formatted-sql-query / tainted-sql-string
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()

def weak_hash(pw):
    # semgrep: insecure-hash-algorithm-md5
    return hashlib.md5(pw.encode()).hexdigest()

def load_config(blob):
    # semgrep: avoid-unsafe-yaml-load
    return yaml.load(blob)
