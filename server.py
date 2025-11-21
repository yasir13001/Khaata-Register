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

# ---------- Config ----------
APP_SECRET = os.environ.get("APP_SECRET", "change-this-secret-to-a-random-string")
USER_FILE = "users.csv"
CREDITS_FILE = "credits.csv"
PURCHASES_FILE = "purchases.csv"

FIELDNAMES = ["ID", "Date", "Time", "Customer", "Description", "Credit", "Payment", "Balance", "Owner"]
PURCHASE_FIELDS = ["ID", "Date", "Time", "Customer", "Items", "Amount", "Owner"]
DATE_FORMAT = "%Y-%m-%d"

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET)

# Serve templates/static (create these folders)
templates = Jinja2Templates(directory="templates")
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------- Helpers: Users ----------
def ensure_user_file():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash", "role"])
            # create default admin with password "admin" (change after first login)
            hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
            writer.writerow(["admin", hashed, "admin"])

def add_user(username: str, password: str, role: str = "user"):
    ensure_user_file()
    with open(USER_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), role])

def authenticate_user(username: str, password: str):
    ensure_user_file()
    with open(USER_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r["username"] == username:
                if bcrypt.checkpw(password.encode(), r["password_hash"].encode()):
                    return r["role"]
                else:
                    return None
    return None

def get_user_role(username: str):
    if not os.path.exists(USER_FILE):
        return None
    with open(USER_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r["username"] == username:
                return r["role"]
    return None

# ---------- Helpers: Credits and Purchases ----------
def ensure_file(filename, fieldnames):
    if not os.path.exists(filename):
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

def read_credits():
    ensure_file(CREDITS_FILE, FIELDNAMES)
    with open(CREDITS_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        # normalize missing Owner
        for r in rows:
            if "Owner" not in r:
                r["Owner"] = ""
        return rows

def write_credit(record):
    ensure_file(CREDITS_FILE, FIELDNAMES)
    with open(CREDITS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow(record)

def next_credit_id():
    if not os.path.exists(CREDITS_FILE):
        return "1"
    with open(CREDITS_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        ids = [int(r["ID"]) for r in reader if r.get("ID") and r["ID"].isdigit()]
        return str(max(ids) + 1) if ids else "1"

def compute_balance(customer_name):
    total = Decimal("0")
    for r in read_credits():
        if r.get("Customer") == customer_name:
            try:
                total += Decimal(r.get("Credit","0")) - Decimal(r.get("Payment","0"))
            except InvalidOperation:
                continue
    return total

# Purchases
def ensure_purchase_file():
    ensure_file(PURCHASES_FILE, PURCHASE_FIELDS)

def read_purchases():
    ensure_purchase_file()
    with open(PURCHASES_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)

def write_purchase(record):
    ensure_purchase_file()
    with open(PURCHASES_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PURCHASE_FIELDS)
        writer.writerow(record)

def next_purchase_id():
    if not os.path.exists(PURCHASES_FILE):
        return "1"
    with open(PURCHASES_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        ids = [int(r["ID"]) for r in reader if r.get("ID") and r["ID"].isdigit()]
        return str(max(ids)+1) if ids else "1"
    
from fastapi.responses import HTMLResponse

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
    # only admin can access registration page if users exist; otherwise allow first-time admin creation
    if os.path.exists(USER_FILE):
        user = request.session.get("user")
        if not user or get_user_role(user) != "admin":
            return templates.TemplateResponse("login.html", {"request": request, "msg": "Only admin can register users."})
    return templates.TemplateResponse("register.html", {"request": request, "msg": ""})

@app.post("/register")
def do_register(request: Request, username: str = Form(...), password: str = Form(...)):
    # only admin may create users if USER_FILE exists
    if os.path.exists(USER_FILE):
        user = request.session.get("user")
        if not user or get_user_role(user) != "admin":
            return templates.TemplateResponse("login.html", {"request": request, "msg": "Access denied"})
    add_user(username, password, "user")
    return templates.TemplateResponse("login.html", {"request": request, "msg": f"User {username} created. Please login."})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login")
    role = get_user_role(user)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "role": role})


# ---------- API endpoints (JSON) ----------
@app.get("/api/customers")
def api_customers(request: Request):
    _ = require_login(request)
    customers = sorted({r["Customer"] for r in read_credits() if r.get("Customer")})
    return {"customers": customers}

@app.get("/api/credits")
def api_credits(request: Request):
    user = require_login(request)
    role = get_user_role(user)
    rows = read_credits()
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
    rec = {
        "ID": next_credit_id(),
        "Date": datetime.now().strftime(DATE_FORMAT),
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Customer": customer,
        "Description": description,
        "Credit": str(amt),
        "Payment": "0",
        "Balance": str((compute_balance(customer) + amt)),
        "Owner": user
    }
    write_credit(rec)
    return {"ok": True, "record": rec}

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
    rec = {
        "ID": next_credit_id(),
        "Date": datetime.now().strftime(DATE_FORMAT),
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Customer": customer,
        "Description": description,
        "Credit": "0",
        "Payment": str(amt),
        "Balance": str((compute_balance(customer) - amt)),
        "Owner": user
    }
    write_credit(rec)
    return {"ok": True, "record": rec}

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
        "ID": next_purchase_id(),
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
    rows = read_credits()
    if role != "admin":
        rows = [r for r in rows if r.get("Owner") == user]
    # return CSV string
    import io
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    return Response(content=output.getvalue(), media_type="text/csv")

# ---------- Startup ----------
if __name__ == "__main__":
    ensure_user_file()
    ensure_file(CREDITS_FILE, FIELDNAMES)
    ensure_purchase_file()
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
