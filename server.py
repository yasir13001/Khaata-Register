# server.py
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
import csv, os
from datetime import datetime
from decimal import Decimal, InvalidOperation
import bcrypt
from collections import defaultdict
import uuid
from pydantic import BaseModel
import secrets
import socket
import json
import sys
import uvicorn
from pathlib import Path
import sqlite3
import io
from contextlib import asynccontextmanager
from fastapi import Form



secrets.token_hex(32)

# <--------Init application------->
@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    init_db()
    yield
app = FastAPI(lifespan=lifespan)

app.add_middleware(SessionMiddleware, secret_key=secrets)

DATE_FORMAT = "%Y-%m-%d"
FIELDNAMES = ["ID", "Date", "Time", "Customer", "Description", "Credit", "Payment", "Balance", "Owner"]

# ----- Serve templates/static (create these folders)
templates = Jinja2Templates(directory="templates")
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")

#-----Database config --------

DB_FILE = "app.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # enables row["ID"]
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS credits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        time TEXT,
        customer TEXT,
        description TEXT,
        credit REAL DEFAULT 0,
        payment REAL DEFAULT 0,
        balance REAL DEFAULT 0,
        owner TEXT
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        time TEXT,
        customer TEXT,
        items TEXT,
        amount REAL,
        owner TEXT
    )""")
    
    # Create default admin if none exists
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        import bcrypt
        hashed = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
                  ("admin", hashed, "admin"))
    conn.commit()
    conn.close()
# < ------------- User Helper Functions ----------->

def add_user(username: str, password: str, role: str = "user"):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return False
    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (username, hashed, role))
    conn.commit()
    conn.close()
    return True

def get_user_role(username: str):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.execute("SELECT role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def authenticate_user(username: str, password: str):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0].encode()):
        return row[1]
    return None

def read_users():
    conn = get_db_connection()
    users = conn.execute("SELECT username, role FROM users").fetchall()
    conn.close()
    return [dict(u) for u in users]

def users_exist() -> bool:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    return count > 0

def add_user(username: str, password: str, role: str = "user") -> bool:
    if get_user_role(username):  # already exists
        return False
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), role)
    )
    conn.commit()
    conn.close()
    return True

def authenticate_user(username, password):
    conn = get_db_connection()
    row = conn.execute("SELECT password_hash, role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return row["role"]
    return None

def get_user_role(username):
    conn = get_db_connection()
    row = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row["role"] if row else None

# ---------- Config ----------

def require_login(request: Request):
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not logged in")
    return username

def require_admin(username: str = Depends(require_login)):
    role = get_user_role(username)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return username

# ---------- Helpers: Credits and Purchases ----------

def read_credits():
    ensure_credits_table()  # make sure table exists
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM credits")
    rows = cur.fetchall()
    conn.close()
    # Convert sqlite3.Row to dict
    return [dict(r) for r in rows]

def add_credit(customer, amount, description, owner):
    conn = get_db_connection()
    c = conn.cursor()
    from datetime import datetime
    now = datetime.now()
    date, time = now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")
    
    # Compute balance
    c.execute("SELECT SUM(credit)-SUM(payment) FROM credits WHERE customer=?", (customer,))
    prev_balance = c.fetchone()[0] or 0
    new_balance = prev_balance + amount
    
    c.execute("""INSERT INTO credits(date,time,customer,description,credit,payment,balance,owner)
                 VALUES(?,?,?,?,?,?,?,?)""",
              (date,time,customer,description,amount,0,new_balance,owner))
    conn.commit()
    conn.close()

def ensure_credits_table():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credits (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Date TEXT NOT NULL,
            Time TEXT NOT NULL,
            Customer TEXT NOT NULL,
            Description TEXT,
            Credit TEXT DEFAULT '0',
            Payment TEXT DEFAULT '0',
            Balance TEXT DEFAULT '0',
            Owner TEXT
        )
    """)
    conn.commit()
    conn.close()

def row_to_dict(r):
    return {
        "ID": r["id"],
        "Date": r["date"],
        "Time": r["time"],
        "Customer": r["customer"],
        "Description": r["description"],
        "Credit": str(r["credit"]),
        "Payment": str(r["payment"]),
        "Balance": str(r["balance"]),
        "Owner": r["owner"]
    }
def read_credits(owner: str | None = None):
    conn = get_db_connection()
    if owner:
        cur = conn.execute("SELECT * FROM credits WHERE Owner = ?", (owner,))
    else:
        cur = conn.execute("SELECT * FROM credits")
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return [row_to_dict(r) for r in rows]

def write_credit(record):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO credits (date, time, customer, description, credit, payment, balance, owner)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["Date"], record["Time"], record["Customer"], record["Description"],
        float(record.get("Credit", 0)), float(record.get("Payment", 0)),
        float(record.get("Balance", 0)), record["Owner"]
    ))
    conn.commit()
    conn.close()

def edit_credit(record_id: int, updates: dict):
    # Only allow updating Customer, Description, Credit, Payment
    allowed = {"Customer", "Description", "Credit", "Payment"}
    set_clause = ", ".join([f"{k} = ?" for k in updates if k in allowed])
    values = [str(updates[k]) for k in updates if k in allowed]
    
    if not set_clause:
        return False

    conn = get_db_connection()
    conn.execute(f"UPDATE credits SET {set_clause} WHERE ID = ?", (*values, record_id))
    conn.commit()
    conn.close()

    # Recompute all balances for the affected customer
    customer = updates.get("Customer")
    if customer:
        recompute_balances(customer)

    return True

def recompute_balances(customer: str):
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM credits WHERE Customer = ? ORDER BY ID ASC", (customer,))
    rows = cur.fetchall()
    balance = Decimal("0")
    for row in rows:
        balance += Decimal(row["Credit"]) - Decimal(row["Payment"])
        conn.execute("UPDATE credits SET Balance = ? WHERE ID = ?", (str(balance), row["ID"]))
    conn.commit()
    conn.close()

def delete_credit(record_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM credits WHERE ID = ?", (record_id,))
    conn.commit()
    conn.close()

def add_credit(customer: str, amount: Decimal, description: str, owner: str):
    balance = compute_balance(customer) + amount
    now = datetime.now()
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO credits (Date, Time, Customer, Description, Credit, Payment, Balance, Owner)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now.strftime(DATE_FORMAT),
        now.strftime("%H:%M:%S"),
        customer,
        description,
        str(amount),
        "0",
        str(balance),
        owner
    ))
    conn.commit()
    conn.close()

def compute_balance(customer_name: str) -> Decimal:
    conn = get_db_connection()
    cur = conn.execute("SELECT Credit, Payment FROM credits WHERE Customer = ?", (customer_name,))
    total = Decimal("0")
    for row in cur.fetchall():
        total += Decimal(row["Credit"]) - Decimal(row["Payment"])
    conn.close()
    return total

def add_payment(customer: str, amount: Decimal, description: str, owner: str):
    balance = compute_balance(customer) - amount
    now = datetime.now()
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO credits (Date, Time, Customer, Description, Credit, Payment, Balance, Owner)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now.strftime(DATE_FORMAT),
        now.strftime("%H:%M:%S"),
        customer,
        description,
        "0",
        str(amount),
        str(balance),
        owner
    ))
    conn.commit()
    conn.close()
    
def delete_credit(record_id: int):
    conn = get_db_connection()
    cur = conn.cursor()

    # Check if record exists
    cur.execute("SELECT * FROM credits WHERE ID = ?", (record_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False  # record not found

    # Delete the record
    cur.execute("DELETE FROM credits WHERE ID = ?", (record_id,))
    conn.commit()
    conn.close()
    return True

@app.get("/api/users")
def api_get_users():
    users = read_users()
    return {"users": users}

#   < ------delete user ------>
def delete_user(username: str):
    conn = get_db_connection()
    cur = conn.cursor()

    # Check if user exists
    user = cur.execute(
        "SELECT username, role FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        conn.close()
        return False, "User not found"

    # Prevent deleting last admin
    admin_count = cur.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    ).fetchone()[0]

    if user["role"] == "admin" and admin_count == 1:
        conn.close()
        return False, "Cannot delete the last admin"

    # Delete user
    else:
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True, "User deleted"

@app.delete("/api/delete_user/{username}")
def api_delete_user(username: str, request: Request):
    user = require_login(request)
    role = get_user_role(user)
    
    if role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")

    success, msg = delete_user(username)
    return {"success": success, "message": msg}

# Admin permission check
# ---------------------------
def require_admin(request: Request):
    username = request.session.get("user")  # use "user" instead of "username"
    if not username:
        raise HTTPException(status_code=401, detail="Not logged in")

    role = get_user_role(username)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    return username

@app.delete("/api/delete_record/{record_id}")
def api_delete_record(record_id: str, admin=Depends(require_admin)):
    if not delete_credit(record_id):
        raise HTTPException(status_code=404, detail="Record not found")
    return {"status": "deleted", "id": record_id}

class CreditUpdate(BaseModel):
    Customer: str | None = None
    Description: str | None = None
    Credit: str | None = None
    Payment: str | None = None

@app.post("/api/edit_credit/{record_id}")
async def api_edit_credit(record_id: str, update: CreditUpdate):
    updates = {k: v for k, v in update.dict(exclude_unset=True).items()}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    success = edit_credit(record_id, updates)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found")

    return {"status": "success", "id": record_id, "updates": updates}

# < -------Purchases Section ----->

def read_purchases():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM purchases").fetchall()
    conn.close()

    mapped = []
    for r in rows:
        mapped.append({
            "ID": r["id"],
            "Date": r["date"],
            "Time": r["time"],
            "Customer": r["customer"],
            "Items": r["items"],
            "Amount": r["amount"],
            "Owner": r["owner"]
        })
    return mapped

def write_purchase(record):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO purchases (date, time, customer, items, amount, owner)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        record["Date"], record["Time"], record["Customer"], record["Items"],
        float(record["Amount"]), record["Owner"]
    ))
    conn.commit()
    conn.close() 

@app.get("/purchases", response_class=HTMLResponse)
async def purchases_page():
    rows = read_purchases()

    html = """
    <html>
    <head>
        <title>Purchases</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background: #f2f2f2; }
            tr:nth-child(even) { background: #fafafa; }
        </style>
    </head>
    <body>
        <h2>All Purchases</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Date</th>
                <th>Time</th>
                <th>Customer</th>
                <th>Items</th>
                <th>Amount</th>
                <th>Owner</th>
            </tr>
    """

    for row in rows:
        html += f"""
            <tr>
                <td>{row.get("ID","")}</td>
                <td>{row.get("Date","")}</td>
                <td>{row.get("Time","")}</td>
                <td>{row.get("Customer","")}</td>
                <td>{row.get("Items","")}</td>
                <td>{row.get("Amount","")}</td>
                <td>{row.get("Owner","")}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    return HTMLResponse(content=html)

# ---------- Authentication helpers ----------
def require_login(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user

def is_admin(request: Request):
    user = request.session.get("user")
    if not user:
        return False
    role = get_user_role(user)
    return role == "admin"

# ---------- Web routes ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = request.session.get("user")
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "msg": ""})
    return RedirectResponse(url="/dashboard")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "msg": ""})

@app.post("/login")
def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    role = authenticate_user(username, password)
    if not role:
        return templates.TemplateResponse("login.html", {"request": request, "msg": "Invalid credentials"})
    request.session["user"] = username
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    # Check if any user already exists
    if users_exist():
        user = request.session.get("user")
        if not user or get_user_role(user) != "admin":
            return templates.TemplateResponse("login.html", {
                "request": request,
                "msg": "Only admin can register users."
            })

        current_role = get_user_role(user)
    else:
        # First user ever → must be admin
        current_role = "admin"

    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "msg": "",
            "current_user_role": current_role
        }
    )


@app.post("/register", response_class=HTMLResponse)
def do_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user")
):
    # Only admin can create users once users exist
    if users_exist():
        logged_user = request.session.get("user")
        if not logged_user or get_user_role(logged_user) != "admin":
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "msg": "Access denied"}
            )

        current_user_role = "admin"

    else:
        # First user ever must be admin
        role = "admin"
        current_user_role = "admin"

    # Add user
    if not add_user(username, password, role):
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "msg": f"User '{username}' already exists!",
                "current_user_role": current_user_role
            }
        )

    # SUCCESS → return form again, not login page
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "msg": f"User '{username}' created successfully!",
            "current_user_role": current_user_role
        }
    )

@app.get("/change_password", response_class=HTMLResponse)
def change_password_page(request: Request):
    user = require_login(request)
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "msg": ""
    })

@app.post("/change_password", response_class=HTMLResponse)
def change_password_submit(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...)
):
    user = require_login(request)

    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()

    import bcrypt

    # Incorrect old password
    if not bcrypt.checkpw(old_password.encode(), row["password_hash"].encode()):
        conn.close()
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "msg": "Old password is incorrect"
        })

    # Update password
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, user))
    conn.commit()
    conn.close()

    return templates.TemplateResponse("login.html", {
        "request": request,
        "msg": "Password changed successfully. Please log in again."
    })

@app.get("/admin/reset_password", response_class=HTMLResponse)
def admin_reset_password_page(request: Request):
    admin = require_login(request)
    if get_user_role(admin) != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    users = read_users()  # return list of {username, role, ...}

    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "users": users,
        "msg": ""
    })

@app.post("/admin/reset_password")
def admin_reset_password(
    request: Request,
    username: str = Form(...),
    new_password: str = Form(...)
):
    admin = require_login(request)
    if get_user_role(admin) != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    import bcrypt
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE username=?", (hashed, username))
    conn.commit()
    conn.close()

    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "users": read_users(),
        "msg": f"Password reset for {username}"
    })

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")
    role = get_user_role(user)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "role": role})

@app.get("/api/customers")
def api_customers(request: Request):
    _ = require_login(request)
    customers = sorted({r["Customer"] for r in read_credits() if r.get("Customer")})
    return {"customers": customers}

@app.get("/api/credits")
def api_credits(request: Request):
    user = require_login(request)
    role = get_user_role(user)
    rows = read_credits()  # this now returns a list of dicts from SQLite

    # If not admin, only show their own records
    if role != "admin":
        rows = [r for r in rows if r.get("Owner") == user]

    return {"records": rows}


@app.post("/api/add_credit")
async def api_add_credit(request: Request):
    user = require_login(request)
    form = await request.json()
    customer = form.get("customer")
    amount = form.get("amount")
    description = form.get("description", "Credit Added")
    if not customer or amount is None:
        raise HTTPException(status_code=400, detail="customer and amount required")
    try:
        amt = Decimal(str(amount))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid amount")

    add_credit(customer, amt, description, user)
    return {"ok": True}

@app.post("/api/add_payment")
async def api_add_payment(request: Request):
    user = require_login(request)
    form = await request.json()
    customer = form.get("customer")
    amount = form.get("amount")
    description = form.get("description", "Payment Received")
    if not customer or amount is None:
        raise HTTPException(status_code=400, detail="customer and amount required")
    try:
        amt = Decimal(str(amount))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid amount")

    add_payment(customer, amt, description, user)
    return {"ok": True}


@app.get("/api/purchases")
def api_purchases(request: Request):
    user = require_login(request)
    role = get_user_role(user)
    rows = read_purchases()
    if role != "admin":
        rows = [r for r in rows if r.get("Owner") == user]
    return {"purchases": rows}

@app.post("/api/add_purchase")
async def api_add_purchase(request: Request):
    user = require_login(request)
    form = await request.json()
    customer = form.get("customer")
    items = form.get("items")
    amount = form.get("amount")
    if not customer or not items or amount is None:
        raise HTTPException(status_code=400, detail="customer, items, amount required")
    try:
        amt = Decimal(str(amount))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid amount")
    rec = {
        "Date": datetime.now().strftime(DATE_FORMAT),
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Customer": customer,
        "Items": items,
        "Amount": str(amt),
        "Owner": user
    }
    write_purchase(rec)
    return {"ok": True, "record": rec}

@app.get("/api/summary")
def api_summary(request: Request, filter: str = ""):
    user = require_login(request)
    rows = read_credits()
    data = defaultdict(lambda: {"Credit": Decimal("0"), "Payment": Decimal("0")})
    for r in rows:
        name = r.get("Customer","")
        try:
            data[name]["Credit"] += Decimal(r.get("Credit","0"))
            data[name]["Payment"] += Decimal(r.get("Payment","0"))
        except Exception:
            continue
    out = []
    for name, vals in data.items():
        if filter and filter.lower() not in name.lower():
            continue
        out.append({
            "customer": name,
            "total_credit": str(vals["Credit"]),
            "total_payment": str(vals["Payment"]),
            "balance": str(vals["Credit"] - vals["Payment"])
        })
    return {"summary": out}

@app.get("/api/balance/{customer}")
def api_balance(request: Request, customer: str):
    require_login(request)
    return {"balance": str(compute_balance(customer))}

# ---------- Utilities ----------
@app.get("/api/download/credits")
def api_download_credits(request: Request):
    user = require_login(request)
    role = get_user_role(user)
    
    # Fetch credits from SQLite
    rows = read_credits()  # make sure read_credits() returns list of dicts with keys matching FIELDNAMES
    
    if role != "admin":
        rows = [r for r in rows if r.get("Owner") == user]
    
    # Write to CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    
    return Response(content=output.getvalue(), media_type="text/csv")

@app.get("/daily-report")
def daily_report_page(request: Request, admin=Depends(require_admin)):
    return templates.TemplateResponse("daily_report.html", {"request": request})

@app.get("/api/daily_report")
def api_daily_report(date: str, admin=Depends(require_admin)):
    """Returns daily credit/payment summary."""
    records = read_credits()

    # Filter by date (YYYY-MM-DD)
    daily_rows = [r for r in records if r["Date"] == date]

    total_credit = 0
    total_payment = 0

    summary = {}  # customer → {credit, payment}

    for r in daily_rows:
        credit = float(r["Credit"] or 0)
        payment = float(r["Payment"] or 0)

        total_credit += credit
        total_payment += payment

        cust = r["Customer"]
        if cust not in summary:
            summary[cust] = {"credit": 0, "payment": 0}

        summary[cust]["credit"] += credit
        summary[cust]["payment"] += payment

    # Prepare final report
    report = {
        "date": date,
        "total_credit": total_credit,
        "total_payment": total_payment,
        "net_change": total_credit - total_payment,
        "per_customer": summary,
        "records": daily_rows
    }

    return report

@app.get("/filter", response_class=HTMLResponse)
def filter_page(request: Request):
    user = require_login(request)
    return templates.TemplateResponse("filter.html", {"request": request})

@app.post("/api/filter")
def filter_data(request: Request, data: dict):

    user = require_login(request)

    customer = data.get("customer")
    date_from = data.get("date_from")
    date_to = data.get("date_to")
    balance_min = data.get("balance_min")
    balance_max = data.get("balance_max")
    owner = data.get("owner")
    sql = "SELECT * FROM credits WHERE 1=1"
    params = []

    if customer:
        sql += " AND customer LIKE ?"
        params.append(f"%{customer}%")

    if date_from:
        sql += " AND date >= ?"
        params.append(date_from)

    if date_to:
        sql += " AND date <= ?"
        params.append(date_to)

    if balance_min:
        sql += " AND balance >= ?"
        params.append(balance_min)

    if balance_max:
        sql += " AND balance <= ?"
        params.append(balance_max)

    if owner:
        sql += " AND owner = ?"
        params.append(owner)

    # Always restrict to logged-in user unless admin
    if get_user_role(user) != "admin":
        sql += " AND owner = ?"
        params.append(user)

    conn = get_db_connection()
    rows = conn.execute(sql, tuple(params)).fetchall()
    conn.close()

    return {"results": [dict(r) for r in rows]}

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO
from fastapi.responses import StreamingResponse

@app.post("/api/filter/pdf")
def filter_pdf(data: dict, request: Request):
    user = require_login(request)

    # Reuse your filter logic
    filtered = filter_data(request, data)["results"]

    # Group records by customer
    grouped = {}
    for row in filtered:
        cust = row["customer"]
        grouped.setdefault(cust, []).append(row)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []

    for customer, records in grouped.items():
        # Customer title
        elements.append(Table([[f"Customer: {customer}"]], colWidths=[500]))
        elements[-1].setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))

        # Table header + rows
        table_data = [["Date", "Description", "Credit", "Payment", "Balance", "Owner"]]
        for r in records:
            table_data.append([
                r["date"],
                r.get("description", ""),
                r.get("credit", ""),
                r.get("payment", ""),
                r.get("balance", ""),
                r.get("owner", "")
            ])

        t = Table(table_data, colWidths=[60, 180, 50, 50, 50, 80])
        t.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, colors.black),        # borders
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),  # header background
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (2,1), (4,-1), 'RIGHT'),               # credit/payment/balance right
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t)
        elements.append(Table([[" "]]))  # spacing between customers

    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=filtered_report.pdf"}
    )

def get_local_ip():
    """Return the LAN IPv4 address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a non-routable address; this forces system to select default interface
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP

def load_config():
    config_path = Path("config.json")

    # Default config
    cfg = {
        "host": "0.0.0.0",
        "port": 8080,
        "log_level": "info",
        "access_log": True
    }

    # Load existing config if found
    if config_path.exists():
        with open(config_path, "r") as f:
            file_cfg = json.load(f)
            cfg.update(file_cfg)  # merge with defaults

    # If host is "auto", replace with actual IP
    if cfg.get("host") == "auto":
        cfg["host"] = get_local_ip()

    return cfg

log_file = open("server.log", "a", buffering=1)
sys.stdout = log_file
sys.stderr = log_file
# ---------- Startup ----------
if __name__ == "__main__":

    # <-----for delivery mode --------->
    # uvicorn.run(app,host=cfg.get("host", "0.0.0.0"),port=cfg.get("port", 8080),log_level=cfg.get("log_level", "info"),access_log=cfg.get("access_log", True))
    
    # <------for development mode-------->
    # To run uvicorn on terminal: uvicorn server:app --reload --host 192.168.10.6 --port 8080
    # uvicorn.run("server:app",host="192.168.10.6" ,reload=True , log_level="info",access_log=True)
    

# for delivery mode
# To build .exe :pyinstaller --onefile --add-data "templates;templates" --add-data "static;static" server.py
    cfg = load_config()
    uvicorn.run(
        app,
        host=cfg["host"],
        port=cfg["port"],
        log_level=cfg["log_level"],
        access_log=cfg["access_log"],
    )



