from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlencode
from datetime import datetime, timedelta
import secrets
import json
import os

app = FastAPI()

# CORS geral liberado (pra facilitar testes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Templates e static
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# arquivos
USERS_FILE = "users.json"
CLIENTS_FILE = "clients.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def load_clients():
    if not os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE, "w") as f:
            # criando um client inicial
            json.dump({
                "site123": {
                    "client_secret": "segredodo123",
                    "redirect_uris": [
                        "http://localhost:8001/callback",
                        "http://localhost:8000/static/callback.html"
                        "https://kiti.dev/exemplo site parceiro/callback.html"
                    ]
                }
            }, f, indent=2)
    with open(CLIENTS_FILE, "r") as f:
        return json.load(f)

def save_clients(clients):
    with open(CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2)

users_db = load_users()
clients_db = load_clients()

authorization_codes = {}
access_tokens = {}
TOKEN_EXPIRE_SECONDS = 600


# --- ROTAS OAUTH2 ---

@app.get("/authorize", response_class=HTMLResponse)
async def authorize(request: Request,
                    response_type: str = "code",
                    client_id: str = None,
                    redirect_uri: str = None,
                    state: str = None):
    if not client_id or not redirect_uri:
        raise HTTPException(400, "client_id e redirect_uri são obrigatórios")

    client = clients_db.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, "client_id ou redirect_uri inválido")

    return templates.TemplateResponse("login_oauth.html", {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "error": None
    })

@app.post("/authorize", response_class=HTMLResponse)
async def authorize_post(request: Request,
                         username: str = Form(...),
                         password: str = Form(...),
                         client_id: str = Form(...),
                         redirect_uri: str = Form(...),
                         state: str = Form(None)):

    users_db = load_users()
    client = clients_db.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, "client_id ou redirect_uri inválido")

    print(f"[LOGIN] Tentando user={username} senha={password}")

    if users_db.get(username) != password:
        return templates.TemplateResponse("login_oauth.html", {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "error": "usuário ou senha inválidos"
        })

    code = secrets.token_urlsafe(16)
    expires = datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    authorization_codes[code] = {"user": username, "client_id": client_id, "expires": expires}

    params = {"code": code}
    if state:
        params["state"] = state

    redirect_url = redirect_uri + "?" + urlencode(params)
    return RedirectResponse(url=redirect_url)

@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request, client_id: str, redirect_uri: str, state: str = None):
    return templates.TemplateResponse("register_oauth.html", {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "error": None
    })

@app.post("/register", response_class=HTMLResponse)
async def register_user(request: Request,
                        username: str = Form(...),
                        password: str = Form(...),
                        client_id: str = Form(...),
                        redirect_uri: str = Form(...),
                        state: str = Form(None)):

    users_db = load_users()
    client = clients_db.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, "client_id ou redirect_uri inválido")

    print(f"[REGISTER] Tentando criar user={username}")

    if username in users_db:
        return templates.TemplateResponse("register_oauth.html", {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "error": "esse user já existe"
        })

    users_db[username] = password
    save_users(users_db)

    code = secrets.token_urlsafe(16)
    expires = datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    authorization_codes[code] = {"user": username, "client_id": client_id, "expires": expires}

    params = {"code": code}
    if state:
        params["state"] = state

    redirect_url = redirect_uri + "?" + urlencode(params)
    return RedirectResponse(url=redirect_url)

@app.post("/token")
async def token(client_id: str = Form(...), client_secret: str = Form(...), code: str = Form(...)):
    client = clients_db.get(client_id)
    if not client or client["client_secret"] != client_secret:
        raise HTTPException(400, "client_id ou client_secret inválidos")

    code_data = authorization_codes.get(code)
    if not code_data:
        raise HTTPException(400, "authorization code inválido")
    if code_data["client_id"] != client_id or code_data["expires"] < datetime.utcnow():
        authorization_codes.pop(code, None)
        raise HTTPException(400, "authorization code inválido ou expirado")

    user = code_data["user"]
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    access_tokens[token] = {"user": user, "expires": expires}

    authorization_codes.pop(code, None)

    print(f"[TOKEN] Gerado token para user={user}")

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_SECONDS
    }

@app.get("/userinfo")
async def userinfo(token: str):
    token_data = access_tokens.get(token)
    if not token_data or token_data["expires"] < datetime.utcnow():
        raise HTTPException(401, "token inválido ou expirado")
    return {"username": token_data["user"]}

# --- ROTAS PRA SERVIR SITE PARCEIRO ---

@app.get("/parceiro/callback.html")
async def parceiro_callback_html():
    return FileResponse("static/callback.html")

@app.get("/parceiro/parceiro.html")
async def parceiro_html():
    return FileResponse("static/parceiro.html")

@app.get("/")
async def root():
    return {"message": "API OAuth2 rodando!"}


# --- ADMIN CLIENTES pra gerenciar redirect_uris ---

@app.get("/admin/clientes", response_class=HTMLResponse)
async def clientes_list(request: Request):
    clients = load_clients()
    return templates.TemplateResponse("admin_clientes.html", {
        "request": request,
        "clients": clients
    })

@app.post("/admin/clientes/adicionar_redirect")
async def add_redirect(client_id: str = Form(...), redirect_uri: str = Form(...)):
    clients = load_clients()
    if client_id not in clients:
        return RedirectResponse("/admin/clientes", status_code=303)

    if redirect_uri not in clients[client_id]["redirect_uris"]:
        clients[client_id]["redirect_uris"].append(redirect_uri)
        save_clients(clients)

    return RedirectResponse("/admin/clientes", status_code=303)
