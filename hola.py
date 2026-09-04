import datetime
import json
import hashlib
import os
import re
import secrets
import sqlite3
import smtplib
from threading import Lock
from typing import Annotated
from email.message import EmailMessage
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


app = FastAPI(
	title="Empleado Virtual Multiempresa",
	version="0.2.0",
	description="Plataforma multiempresa para asistentes, citas y conversaciones.",
)


def load_admin_key() -> str:
	key = os.getenv("VIRTUAL_EMPLOYEE_ADMIN_KEY")
	if key:
		return key
	key_file = "owner.key"
	if os.path.exists(key_file):
		return open(key_file, encoding="utf-8").read().strip()
	key = secrets.token_urlsafe(32)
	with open(key_file, "w", encoding="utf-8") as file:
		file.write(key)
	return key


ADMIN_KEY = load_admin_key()
ADMIN_EMAIL = "admin@plataforma.local"

PLANS = {
	"premium": {
		"name": "Premium",
		"price_cop": 150000,
		"limit": 250,
		"benefits": ["Chat IA privado", "Clientes y citas", "Base de conocimiento"],
	},
	"plus": {
		"name": "Plus",
		"price_cop": 250000,
		"limit": 500,
		"benefits": ["Todo del plan Premium", "Más volumen de atención", "Gestión avanzada"],
	},
	"enterprise": {
		"name": "Enterprise",
		"price_cop": 400000,
		"limit": None,
		"benefits": ["Todo del plan Plus", "Soporte exclusivo", "Atención escalable"],
	},
}


class CompanyConfig(BaseModel):
	name: str = Field(min_length=1)
	sector: str = Field(min_length=1)
	tone: str = "profesional y amable"
	business_hours: str = "Lunes a viernes, 08:00 a 17:00"
	about: str = ""
	knowledge: list[str] = Field(default_factory=list)


class Client(BaseModel):
	name: str = Field(min_length=1)
	phone: str = Field(min_length=5)
	email: str | None = None
	notes: str | None = None


class Appointment(BaseModel):
	client_name: str = Field(min_length=1)
	phone: str | None = Field(default=None, min_length=5)
	starts_at: datetime.datetime
	reason: str = Field(min_length=1)


class QuoteItem(BaseModel):
	description: str = Field(min_length=1)
	quantity: int = Field(gt=0)
	unit_price: float = Field(ge=0)


class Quote(BaseModel):
	client_name: str = Field(min_length=1)
	items: list[QuoteItem] = Field(min_length=1)
	notes: str | None = None


class AssistantMessage(BaseModel):
	message: str = Field(min_length=1)


class CompanySignup(BaseModel):
	company_id: str = Field(min_length=3, max_length=40, pattern=r"^[a-z0-9-]+$")
	name: str = Field(min_length=1)
	sector: str = Field(min_length=1)
	email: str = Field(min_length=5)
	password: str = Field(min_length=8)
	plan_id: str = "premium"


class CompanyLogin(BaseModel):
	email: str = Field(min_length=5)
	password: str = Field(min_length=8)


class ChannelMessage(BaseModel):
	sender: str = Field(min_length=3)
	message: str = Field(min_length=1)


class Conversation(BaseModel):
	channel: str
	sender: str
	incoming: str
	response: str


class KnowledgeUpdate(BaseModel):
	about: str = ""
	knowledge: list[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
	sender: str = Field(min_length=3)
	message: str = Field(min_length=1)


class ManualReply(BaseModel):
	sender: str = Field(min_length=3)
	message: str = Field(min_length=1)


class PlatformClient(BaseModel):
	name: str
	category: str = "cliente de la plataforma"


database = sqlite3.connect(
	os.getenv("VIRTUAL_EMPLOYEE_DATABASE", "virtual_employee.db"),
	check_same_thread=False,
)
database.row_factory = sqlite3.Row
database_lock = Lock()

with database:
	database.executescript(
		"""
		CREATE TABLE IF NOT EXISTS companies (
			company_id TEXT PRIMARY KEY,
			config TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS company_accounts (
			company_id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			plan_id TEXT NOT NULL DEFAULT 'basic'
		);
		CREATE TABLE IF NOT EXISTS company_sessions (
			token TEXT PRIMARY KEY,
			company_id TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_id TEXT NOT NULL,
			data TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS appointments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_id TEXT NOT NULL,
			data TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS quotes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_id TEXT NOT NULL,
			data TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS conversations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_id TEXT NOT NULL,
			channel TEXT NOT NULL,
			sender TEXT NOT NULL,
			incoming TEXT NOT NULL,
			response TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS chat_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			company_id TEXT NOT NULL,
			sender TEXT NOT NULL,
			role TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS platform_clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			category TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_clients_company ON clients(company_id);
		CREATE INDEX IF NOT EXISTS idx_appointments_company ON appointments(company_id);
		CREATE INDEX IF NOT EXISTS idx_quotes_company ON quotes(company_id);
		CREATE INDEX IF NOT EXISTS idx_conversations_company ON conversations(company_id);
		CREATE INDEX IF NOT EXISTS idx_chat_messages_company_sender ON chat_messages(company_id, sender);
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 5000;
		"""
	)

with database_lock:
	account_columns = {
		row["name"] for row in database.execute("PRAGMA table_info(company_accounts)")
	}
	if "status" not in account_columns:
		database.execute(
		"ALTER TABLE company_accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
	)
	if "plan_id" not in account_columns:
		database.execute(
		"ALTER TABLE company_accounts ADD COLUMN plan_id TEXT NOT NULL DEFAULT 'basic'"
	)
	database.commit()

with database_lock:
	database.execute(
		"INSERT INTO platform_clients (name, category) "
		"SELECT 'Rapilink', 'cliente de la plataforma' "
		"WHERE NOT EXISTS (SELECT 1 FROM platform_clients WHERE name = 'Rapilink')"
	)
	database.commit()


def password_hash(password: str) -> str:
	salt = secrets.token_bytes(16)
	digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
	return f"{salt.hex()}:{digest.hex()}"


def password_matches(password: str, stored: str) -> bool:
	salt_hex, digest_hex = stored.split(":", 1)
	digest = hashlib.pbkdf2_hmac(
		"sha256", password.encode(), bytes.fromhex(salt_hex), 120_000
	)
	return secrets.compare_digest(digest.hex(), digest_hex)


def company_from_token(token: str | None) -> str:
	if not token:
		raise HTTPException(status_code=401, detail="Debes iniciar sesión.")
	with database_lock:
		row = database.execute(
			"SELECT company_id FROM company_sessions WHERE token = ?", (token,)
		).fetchone()
	if row is None:
		raise HTTPException(status_code=401, detail="La sesión no es válida.")
	return row["company_id"]


def company_id_from_header(
	company_id: Annotated[str | None, Header(alias="X-Company-ID")] = None,
) -> str:
	if not company_id:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Debes enviar el encabezado X-Company-ID.",
		)
	with database_lock:
		company = database.execute(
			"SELECT 1 FROM companies WHERE company_id = ?", (company_id,)
		).fetchone()
	if company is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail="La empresa no está registrada.",
		)
	return company_id


def get_company_plan(company_id: str) -> tuple[str, dict]:
	with database_lock:
		row = database.execute(
			"SELECT plan_id FROM company_accounts WHERE company_id = ?", (company_id,)
		).fetchone()
	plan_id = row["plan_id"] if row and row["plan_id"] in PLANS else "premium"
	return plan_id, PLANS[plan_id]


def enforce_booking_limit(company_id: str, appointment: Appointment) -> None:
	_, plan = get_company_plan(company_id)
	limit = plan["limit"]
	if limit is None:
		return
	with database_lock:
		if appointment.phone:
			known = database.execute(
				"SELECT 1 FROM clients WHERE company_id = ? AND json_extract(data, '$.phone') = ?",
				(company_id, appointment.phone),
			).fetchone()
			new_clients = 0 if known else 1
		else:
			new_clients = 1
		current = database.execute(
			"SELECT COUNT(*) FROM clients WHERE company_id = ?", (company_id,)
		).fetchone()[0]
	if current + new_clients > limit:
		raise HTTPException(
			status_code=403,
			detail=f"Esta empresa alcanzó el límite de {limit} clientes de su plan.",
		)


def require_admin_key(
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> None:
	if not admin_key or not secrets.compare_digest(admin_key, ADMIN_KEY):
		raise HTTPException(
			status_code=status.HTTP_403_FORBIDDEN,
			detail="Se requiere la clave privada del propietario.",
		)


def fetch_company_config(company_id: str) -> CompanyConfig:
	with database_lock:
		row = database.execute(
			"SELECT config FROM companies WHERE company_id = ?", (company_id,)
		).fetchone()
	return CompanyConfig.model_validate_json(row["config"])


def update_company_knowledge(company_id: str, about: str, knowledge: list[str]) -> CompanyConfig:
	config = fetch_company_config(company_id)
	config.about = about.strip()
	config.knowledge = [item.strip() for item in knowledge if item and item.strip()]
	with database_lock, database:
		database.execute(
			"UPDATE companies SET config = ? WHERE company_id = ?",
			(config.model_dump_json(), company_id),
		)
	return config


def generate_ai_reply(company_id: str, message: str) -> str:
	config = fetch_company_config(company_id)
	context_parts = [
		f"Eres el asistente de {config.name}.",
		f"Sector: {config.sector}.",
		f"Horario: {config.business_hours}.",
	]
	if config.about:
		context_parts.append(f"Información de la empresa: {config.about}.")
	if config.knowledge:
		context_parts.append(f"Conocimiento autorizado: {'; '.join(config.knowledge)}.")
	context_parts.append("Responde en español, con claridad, sin inventar datos y con tono profesional y amable.")
	api_key = os.getenv("OPENAI_API_KEY")
	if api_key:
		try:
			payload = json.dumps({
				"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
				"input": "\n".join(context_parts + [f"Mensaje del cliente: {message}"]),
			}).encode()
			request = Request(
				"https://api.openai.com/v1/responses",
				data=payload,
				headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
				method="POST",
			)
			with urlopen(request, timeout=20) as response:
				result = json.loads(response.read())
			text = result.get("output_text")
			if text:
				return text.strip()
		except Exception:
			pass
	message_lower = message.lower()
	if "horario" in message_lower or "atienden" in message_lower or "abren" in message_lower:
		return f"El horario de {config.name} es: {config.business_hours}."
	if "cita" in message_lower or "agenda" in message_lower or "reserv" in message_lower:
		return "Puedo ayudarte a agendar. Envíame tu nombre, teléfono, día, hora y motivo de la cita."
	if "cotiza" in message_lower or "precio" in message_lower or "presupuesto" in message_lower or "cuesta" in message_lower:
		return "Puedo preparar una cotización. Indícame el servicio y la cantidad que necesitas."
	if config.about:
		return f"Según la información de {config.name}: {config.about[:220]}"
	if config.knowledge:
		return f"Según la información de {config.name}: {config.knowledge[0]}"
	return f"Soy el asistente de {config.name}. Puedo ayudarte con citas, horarios y cotizaciones."


def send_whatsapp_message(recipient: str, message: str) -> None:
	token = os.getenv("META_WHATSAPP_TOKEN")
	phone_number_id = os.getenv("META_WHATSAPP_PHONE_NUMBER_ID")
	if not token or not phone_number_id:
		return
	payload = json.dumps({"messaging_product": "whatsapp", "to": recipient, "type": "text", "text": {"body": message}}).encode()
	request = Request(
		f"https://graph.facebook.com/v22.0/{phone_number_id}/messages",
		data=payload,
		headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
		method="POST",
	)
	with urlopen(request, timeout=20):
		pass


def send_email_message(recipient: str, subject: str, message: str) -> None:
	host = os.getenv("SMTP_HOST")
	user = os.getenv("SMTP_USER")
	password = os.getenv("SMTP_PASSWORD")
	if not host or not user or not password:
		return
	email = EmailMessage()
	email["From"] = user
	email["To"] = recipient
	email["Subject"] = subject
	email.set_content(message)
	with smtplib.SMTP_SSL(host, int(os.getenv("SMTP_PORT", "465"))) as smtp:
		smtp.login(user, password)
		smtp.send_message(email)


def process_channel_message(company_id: str, channel: str, request: ChannelMessage) -> str:
	company_id_from_header(company_id)
	reply = generate_ai_reply(company_id, request.message)
	with database_lock, database:
		database.execute(
			"INSERT INTO conversations (company_id, channel, sender, incoming, response) VALUES (?, ?, ?, ?, ?)",
			(company_id, channel, request.sender, request.message, reply),
		)
	return reply


def store_chat_message(company_id: str, sender: str, role: str, message: str) -> None:
	with database_lock, database:
		database.execute(
			"INSERT INTO chat_messages (company_id, sender, role, message, created_at) VALUES (?, ?, ?, ?, ?)",
			(company_id, sender, role, message, datetime.datetime.utcnow().isoformat()),
		)


def configured_channels() -> dict[str, bool]:
	return {
		"ai": bool(os.getenv("OPENAI_API_KEY")),
		"whatsapp": bool(os.getenv("META_WHATSAPP_TOKEN") and os.getenv("META_WHATSAPP_PHONE_NUMBER_ID")),
		"email": bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASSWORD")),
	}


def read_records(table: str, company_id: str) -> list[dict]:
	with database_lock:
		rows = database.execute(
			f"SELECT data FROM {table} WHERE company_id = ? ORDER BY id",
			(company_id,),
		).fetchall()
	return [json.loads(row["data"]) for row in rows]


@app.get("/health")
def health() -> dict[str, str]:
	return {"status": "ok"}


@app.get("/plans")
def plans() -> dict[str, dict]:
	return PLANS


@app.get("/integrations/status")
def integrations_status() -> dict[str, bool]:
	return configured_channels()


@app.post("/chat/{company_id}")
def public_chat(company_id: str, request: ChatRequest) -> dict[str, str]:
	company_id_from_header(company_id)
	store_chat_message(company_id, request.sender, "client", request.message)
	reply = generate_ai_reply(company_id, request.message)
	store_chat_message(company_id, request.sender, "ai", reply)
	return {"sender": request.sender, "reply": reply, "mode": "ai"}


@app.get("/my-knowledge", response_model=CompanyConfig)
def my_knowledge(authorization: Annotated[str | None, Header()] = None) -> CompanyConfig:
	token = authorization.removeprefix("Bearer ") if authorization else None
	return fetch_company_config(company_from_token(token))


@app.put("/my-knowledge", response_model=CompanyConfig)
def save_my_knowledge(
	update: KnowledgeUpdate,
	authorization: Annotated[str | None, Header()] = None,
) -> CompanyConfig:
	token = authorization.removeprefix("Bearer ") if authorization else None
	return update_company_knowledge(company_from_token(token), update.about, update.knowledge)


@app.get("/my-chat")
def my_chat(authorization: Annotated[str | None, Header()] = None) -> list[dict]:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	with database_lock:
		rows = database.execute(
			"SELECT sender, role, message, created_at FROM chat_messages "
			"WHERE company_id = ? ORDER BY id DESC", (company_id,)
		).fetchall()
	return [dict(row) for row in rows]


@app.post("/my-chat/reply")
def manual_chat_reply(
	reply: ManualReply,
	authorization: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	store_chat_message(company_id, reply.sender, "human", reply.message)
	return {"status": "sent", "sender": reply.sender}


@app.get("/owner/platform-summary")
def platform_summary(
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> dict[str, int]:
	require_admin_key(admin_key)
	with database_lock:
		company_count = database.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
		client_count = database.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
		appointment_count = database.execute(
			"SELECT COUNT(*) FROM appointments"
		).fetchone()[0]
	return {
		"companies": company_count,
		"clients": client_count,
		"appointments": appointment_count,
	}


@app.get("/owner/pending-companies")
def pending_companies(
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> list[dict[str, str]]:
	require_admin_key(admin_key)
	with database_lock:
		rows = database.execute(
			"SELECT a.company_id, c.config, a.email FROM company_accounts a "
			"JOIN companies c ON c.company_id = a.company_id WHERE a.status = 'pending'"
		).fetchall()
	return [
		{
			"company_id": row["company_id"],
			"name": json.loads(row["config"])["name"],
			"email": row["email"],
			"status": "pending_payment",
		}
		for row in rows
	]


@app.get("/owner/companies")
def owner_companies(
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> list[dict[str, str]]:
	require_admin_key(admin_key)
	with database_lock:
		rows = database.execute(
			"SELECT a.company_id, a.email, a.status, a.plan_id, c.config FROM company_accounts a "
			"JOIN companies c ON c.company_id = a.company_id ORDER BY a.company_id"
		).fetchall()
	return [
		{
			"company_id": row["company_id"],
			"email": row["email"],
			"status": row["status"],
			"plan_id": row["plan_id"],
			"plan": PLANS.get(row["plan_id"], PLANS["premium"])["name"],
			"name": json.loads(row["config"])["name"],
		}
		for row in rows
	]


@app.post("/owner/approve/{company_id}")
def approve_company(
	company_id: str,
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> dict[str, str]:
	require_admin_key(admin_key)
	with database_lock, database:
		result = database.execute(
			"UPDATE company_accounts SET status = 'active' WHERE company_id = ?",
			(company_id,),
		)
	if result.rowcount == 0:
		raise HTTPException(status_code=404, detail="La empresa no está registrada.")
	return {"company_id": company_id, "status": "active"}


@app.post("/owner/status/{company_id}/{new_status}")
def change_company_status(
	company_id: str,
	new_status: str,
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> dict[str, str]:
	require_admin_key(admin_key)
	if new_status not in {"active", "disabled", "pending"}:
		raise HTTPException(status_code=400, detail="Estado no válido.")
	with database_lock, database:
		result = database.execute(
			"UPDATE company_accounts SET status = ? WHERE company_id = ?",
			(new_status, company_id),
		)
	if result.rowcount == 0:
		raise HTTPException(status_code=404, detail="La empresa no está registrada.")
	return {"company_id": company_id, "status": new_status}


@app.post("/signup")
def signup(request: CompanySignup) -> dict[str, str]:
	if request.plan_id not in PLANS:
		raise HTTPException(status_code=400, detail="El plan seleccionado no existe.")
	if PLANS[request.plan_id]["price_cop"] <= 100000:
		raise HTTPException(status_code=400, detail="La cuenta debe tener un valor mensual superior a $100.000 COP.")
	config = CompanyConfig(name=request.name, sector=request.sector)
	account_status = "pending"
	try:
		with database_lock, database:
			database.execute(
				"INSERT INTO companies (company_id, config) VALUES (?, ?)",
				(request.company_id, config.model_dump_json()),
			)
			database.execute(
				"INSERT INTO company_accounts (company_id, email, password_hash, status, plan_id) "
				"VALUES (?, ?, ?, ?, ?)",
				(request.company_id, request.email.lower(), password_hash(request.password), account_status, request.plan_id),
			)
	except sqlite3.IntegrityError:
		raise HTTPException(status_code=409, detail="El código o correo ya está registrado.")
	return {
		"message": "Registro recibido. El propietario debe activar la cuenta después del pago mensual.",
		"plan": PLANS[request.plan_id]["name"],
		"amount_cop": str(PLANS[request.plan_id]["price_cop"]),
		"limit": str(PLANS[request.plan_id]["limit"] or "ilimitado"),
		"payment_method": "Nequi",
		"payment_number": "3113617292",
	}


@app.post("/login")
def login(request: CompanyLogin) -> dict[str, str]:
	with database_lock:
		row = database.execute(
			"SELECT company_id, password_hash, status FROM company_accounts WHERE email = ?",
			(request.email.lower(),),
		).fetchone()
	if row is None or not password_matches(request.password, row["password_hash"]):
		raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos.")
	if row["status"] != "active":
		if row["status"] == "disabled":
			raise HTTPException(status_code=403, detail="El acceso de esta empresa está desactivado.")
		raise HTTPException(
			status_code=402,
			detail="Pago pendiente. Envía el valor del plan al Nequi 3113617292 y espera la activación del propietario.",
		)
	token = secrets.token_urlsafe(32)
	with database_lock, database:
		database.execute(
			"INSERT INTO company_sessions (token, company_id) VALUES (?, ?)",
			(token, row["company_id"]),
		)
	return {"token": token, "company_id": row["company_id"]}


@app.get("/legacy-portal", response_class=HTMLResponse)
def company_portal() -> str:
	return """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Portal de empresa</title><style>body{font-family:Segoe UI,sans-serif;background:#eef3ed;color:#173b2b;margin:0}.wrap{max-width:720px;margin:auto;padding:36px 20px}.box{background:#fff;padding:28px;border-radius:14px;margin:16px 0;box-shadow:0 8px 24px #173b2b12}h1{font:600 38px Georgia,serif}input,button{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;border:1px solid #cedbce;border-radius:7px;font-size:15px}button{background:#173b2b;color:white;cursor:pointer}.hidden{display:none}.client{padding:12px 0;border-bottom:1px solid #e4ebe4}</style></head><body><main class="wrap"><h1>Portal de tu empresa</h1><section id="login" class="box"><h2>Entrar</h2><input id="email" placeholder="Correo"><input id="password" type="password" placeholder="Contraseña"><button onclick="login()">Iniciar sesión</button><p id="loginMsg"></p><hr><h2>Crear cuenta</h2><input id="companyId" placeholder="Código de empresa, ejemplo: mi-negocio"><input id="companyName" placeholder="Nombre de empresa"><input id="sector" placeholder="Sector"><input id="signupEmail" placeholder="Correo de acceso"><input id="signupPassword" type="password" placeholder="Contraseña (mínimo 8 caracteres)"><button onclick="signup()">Registrar empresa</button><p id="signupMsg"></p></section><section id="app" class="hidden"><div class="box"><h2>Mis clientes</h2><input id="clientName" placeholder="Nombre del cliente"><input id="clientPhone" placeholder="Teléfono"><input id="clientEmail" placeholder="Correo (opcional)"><button onclick="addClient()">Añadir cliente</button><div id="clients"></div><button onclick="logout()">Cerrar sesión</button></div></section></main><script>let token='';async function signup(){const r=await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:companyId.value,name:companyName.value,sector:sector.value,email:signupEmail.value,password:signupPassword.value})});signupMsg.textContent=(await r.json()).message||'No se pudo registrar';}async function login(){const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){loginMsg.textContent=d.detail;return}token=d.token;login.classList?.;document.querySelector('#login').classList.add('hidden');document.querySelector('#app').classList.remove('hidden');loadClients();}async function loadClients(){const r=await fetch('/my-clients',{headers:{Authorization:'Bearer '+token}});const list=await r.json();clients.innerHTML=list.map(c=>'<div class="client">'+c.name+' · '+c.phone+'</div>').join('')||'<p>No tienes clientes todavía.</p>';}async function addClient(){await fetch('/my-clients',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({name:clientName.value,phone:clientPhone.value,email:clientEmail.value||null})});clientName.value='';clientPhone.value='';clientEmail.value='';loadClients();}function logout(){token='';location.reload();}</script></body></html>"""


@app.get("/portal", response_class=HTMLResponse)
def clean_company_portal() -> str:
	return """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Portal de empresa</title><style>body{font-family:Segoe UI,sans-serif;background:#eef3ed;color:#173b2b;margin:0}.wrap{max-width:720px;margin:auto;padding:36px 20px}.box{background:#fff;padding:28px;border-radius:14px;margin:16px 0;box-shadow:0 8px 24px #173b2b12}h1{font:600 38px Georgia,serif}input,button{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;border:1px solid #cedbce;border-radius:7px;font-size:15px}button{background:#173b2b;color:white;cursor:pointer}.hidden{display:none}.client{padding:12px 0;border-bottom:1px solid #e4ebe4}</style></head><body><main class="wrap"><h1>Portal de tu empresa</h1><section id="login" class="box"><h2>Entrar</h2><input id="email" placeholder="Correo"><input id="password" type="password" placeholder="Contraseña"><button onclick="doLogin()">Iniciar sesión</button><p id="loginMsg"></p><hr><h2>Crear cuenta</h2><input id="companyId" placeholder="Código de empresa, ejemplo: mi-negocio"><input id="companyName" placeholder="Nombre de empresa"><input id="sector" placeholder="Sector"><input id="signupEmail" placeholder="Correo de acceso"><input id="signupPassword" type="password" placeholder="Contraseña (mínimo 8 caracteres)"><button onclick="doSignup()">Registrar empresa</button><p id="signupMsg"></p></section><section id="app" class="hidden"><div class="box"><h2>Mis clientes</h2><input id="clientName" placeholder="Nombre del cliente"><input id="clientPhone" placeholder="Teléfono"><input id="clientEmail" placeholder="Correo (opcional)"><button onclick="addClient()">Añadir cliente</button><div id="clients"></div><button onclick="logout()">Cerrar sesión</button></div></section></main><script>let token='';async function doSignup(){const r=await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:companyId.value,name:companyName.value,sector:sector.value,email:signupEmail.value,password:signupPassword.value})});const d=await r.json();signupMsg.textContent=d.message||d.detail||'No se pudo registrar';}async function doLogin(){const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){loginMsg.textContent=d.detail;return}token=d.token;document.querySelector('#login').classList.add('hidden');document.querySelector('#app').classList.remove('hidden');loadClients();}async function loadClients(){const r=await fetch('/my-clients',{headers:{Authorization:'Bearer '+token}});const list=await r.json();clients.innerHTML=list.map(c=>'<div class="client">'+c.name+' · '+c.phone+'</div>').join('')||'<p>No tienes clientes todavía.</p>';}async function addClient(){const r=await fetch('/my-clients',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({name:clientName.value,phone:clientPhone.value,email:clientEmail.value||null})});if(r.ok){clientName.value='';clientPhone.value='';clientEmail.value='';loadClients();}}function logout(){token='';location.reload();}</script></body></html>"""


@app.get("/my-clients", response_model=list[Client])
def my_clients(authorization: Annotated[str | None, Header()] = None) -> list[Client]:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	return [Client.model_validate(record) for record in read_records("clients", company_id)]


@app.post("/my-clients", response_model=Client)
def add_my_client(
	client: Client,
	authorization: Annotated[str | None, Header()] = None,
) -> Client:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	with database_lock, database:
		database.execute(
			"INSERT INTO clients (company_id, data) VALUES (?, ?)",
			(company_id, client.model_dump_json()),
		)
	return client


@app.get("/my-appointments", response_model=list[Appointment])
def my_appointments(
	authorization: Annotated[str | None, Header()] = None,
) -> list[Appointment]:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	return [
		Appointment.model_validate(record)
		for record in read_records("appointments", company_id)
	]


@app.get("/my-conversations", response_model=list[Conversation])
def my_conversations(
	authorization: Annotated[str | None, Header()] = None,
) -> list[Conversation]:
	token = authorization.removeprefix("Bearer ") if authorization else None
	company_id = company_from_token(token)
	with database_lock:
		rows = database.execute(
			"SELECT channel, sender, incoming, response FROM conversations "
			"WHERE company_id = ? ORDER BY id DESC",
			(company_id,),
		).fetchall()
	return [Conversation(**dict(row)) for row in rows]


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
	return workspace_page()
	return """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Empleado Virtual</title><style>
:root{font-family:Segoe UI,sans-serif;color:#e9f7ff;background:#07131d}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 10%,#123c4d 0,#07131d 38%),#07131d}.shell{max-width:960px;margin:auto;padding:48px 24px}.hero{position:relative;overflow:hidden;background:linear-gradient(135deg,#0a2230,#0b1723 58%,#102f39);color:#e9f7ff;padding:44px;border:1px solid #35d6d044;border-radius:18px;box-shadow:0 0 0 1px #35d6d018,0 20px 60px #0008}.hero:after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 20%,#45f0d20b 50%,transparent 80%);pointer-events:none}.eyebrow{color:#55efd4;letter-spacing:2px;text-transform:uppercase;font-size:12px}.hero h1{font:600 48px Georgia,serif;max-width:620px;margin:14px 0}.hero p{max-width:560px;line-height:1.7;color:#b9d4df}.bar{display:flex;gap:10px;margin-top:28px}.bar input{flex:1;padding:14px;border:1px solid #55efd455;background:#071923;color:#e9f7ff;border-radius:8px;font-size:15px;outline:none}.bar input:focus{border-color:#55efd4;box-shadow:0 0 16px #55efd433}.bar button{background:#55efd4;color:#06201f;border:0;border-radius:8px;padding:0 22px;font-weight:700;cursor:pointer;box-shadow:0 0 20px #55efd455}.bar button:hover{background:#b0fff0}.result{margin-top:20px;white-space:pre-wrap;line-height:1.6;color:#dffefa}.trust{display:flex;gap:18px;margin-top:25px;color:#8eb0bb;font-size:13px}.trust span:before{content:"✓";color:#55efd4;margin-right:7px}@media(max-width:650px){.shell{padding:24px 16px}.hero{padding:28px 22px}.hero h1{font-size:36px}.bar{flex-direction:column}.bar button{height:46px}.trust{flex-direction:column;gap:8px}}
</style></head><body><main class="shell"><section class="hero"><div class="eyebrow">Atención inteligente · Público</div><h1>Estamos para ayudarte.</h1><p>Escribe una pregunta o una tarea y nuestro asistente te responderá de forma rápida y segura.</p><div class="bar"><input id="company" value="demo" placeholder="Código de atención"><input id="message" value="¿Cuál es el horario de atención?" placeholder="Escribe tu mensaje"><button onclick="ask()">Consultar</button></div><div id="answer" class="result"></div><div class="trust"><span>Respuesta inmediata</span><span>Datos protegidos</span><span>Atención personalizada</span></div></section></main><script>
async function ask(){const id=document.querySelector('#company').value;const box=document.querySelector('#answer');box.textContent='Procesando...';const r=await fetch('/assistant',{method:'POST',headers:{'Content-Type':'application/json','X-Company-ID':id},body:JSON.stringify({message:document.querySelector('#message').value})});const data=await r.json();box.textContent=r.ok?data.reply:data.detail;}ask();
</script></body></html>"""


@app.post("/admin-login")
def admin_login(request: CompanyLogin) -> dict[str, str]:
	if request.email.lower() != ADMIN_EMAIL or not secrets.compare_digest(request.password, ADMIN_KEY):
		raise HTTPException(status_code=401, detail="Credenciales de administrador incorrectas.")
	return {"admin_key": ADMIN_KEY}


def fixed_workspace_page() -> str:
	return """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Plataforma Neon</title><style>:root{font-family:Segoe UI,sans-serif;color:#e9f7ff;background:#061019}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 5%,#123d4b,#061019 42%)}main{max-width:1050px;margin:auto;padding:28px 20px}.panel{background:#0b202d;border:1px solid #55efd444;border-radius:16px;padding:28px;margin:16px 0;box-shadow:0 0 28px #55efd414,0 18px 50px #0007}h1{font:600 44px Georgia,serif;margin:8px 0 12px}h2{font-size:21px}.sub{color:#a9c5d0;line-height:1.6}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.tabs button,.action{border:1px solid #55efd455;background:#0b1a25;color:#dffefa;padding:11px 15px;border-radius:8px;cursor:pointer}.tabs button.active,.action.primary{background:#55efd4;color:#06201f;font-weight:700}.view{display:none}.view.active{display:block}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.field{display:grid;gap:6px;margin:9px 0}label{color:#9fc0cb;font-size:13px}input{width:100%;padding:12px;border:1px solid #55efd455;background:#061923;color:#e9f7ff;border-radius:8px;font-size:15px}.notice{color:#55efd4;line-height:1.5;min-height:22px}.pay{border:1px solid #c7f86a55;background:#c7f86a0d;padding:16px;border-radius:10px;margin:15px 0}.pay strong{color:#c7f86a;font-size:20px}.row{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #ffffff16;padding:13px 0;gap:10px}.row small{color:#a9c5d0}.danger{border-color:#ff769055;color:#ffb3b3}@media(max-width:700px){h1{font-size:35px}.grid{grid-template-columns:1fr}}
</style></head><body><main><header><div class="sub">NEON//WORKSPACE · PLATAFORMA MULTIEMPRESA</div><h1>Una sola plataforma. Cada negocio, su propio espacio.</h1><p class="sub">Agenda citas, administra clientes y controla accesos con una experiencia privada y preparada para crecer.</p></header><nav class="tabs"><button class="active" onclick="show('book',this)">Agendar cita</button><button onclick="show('company',this)">Espacio de empresa</button><button onclick="show('admin',this)">Administración</button></nav><section id="book" class="view active"><div class="panel"><h2>Agendar una cita</h2><div class="grid"><div class="field"><label>Código de empresa</label><input id="bookCompany" value="claro"></div><div class="field"><label>Nombre</label><input id="bookName"></div><div class="field"><label>Teléfono</label><input id="bookPhone"></div><div class="field"><label>Fecha y hora</label><input id="bookDate" type="datetime-local"></div></div><div class="field"><label>Motivo</label><input id="bookReason"></div><button class="action primary" onclick="book()">Solicitar cita</button><p id="bookMsg" class="notice"></p></div></section><section id="company" class="view"><div class="grid"><div class="panel"><h2>Entrar a mi espacio</h2><div class="field"><label>Correo</label><input id="loginEmail" type="email"></div><div class="field"><label>Contraseña</label><input id="loginPassword" type="password"></div><button class="action primary" onclick="companyLogin()">Iniciar sesión</button><p id="loginMsg" class="notice"></p></div><div class="panel"><h2>Registrar empresa</h2><div class="pay"><strong>$100.000 COP / mes</strong><br>Pago por Nequi: <b>3113617292</b><br><small>Después de confirmar el pago activaremos tu espacio.</small></div><div class="field"><label>Datos de empresa</label><input id="signupId" placeholder="mi-empresa"><input id="signupName" placeholder="Nombre"><input id="signupSector" placeholder="Sector"></div><div class="field"><label>Acceso</label><input id="signupEmail" type="email" placeholder="Correo"><input id="signupPassword" type="password" placeholder="Mínimo 8 caracteres"></div><button class="action" onclick="signup()">Enviar registro</button><p id="signupMsg" class="notice"></p></div></div><div id="companySpace" class="panel" style="display:none"><h2>Mis clientes</h2><div class="grid"><input id="newClientName" placeholder="Nombre"><input id="newClientPhone" placeholder="Teléfono"></div><button class="action primary" onclick="addClient()">Añadir cliente</button><div id="clientList"></div></div></section><section id="admin" class="view"><div id="adminLoginPanel" class="panel"><h2>Acceso del propietario</h2><input id="adminEmail" value="admin@plataforma.local"><input id="adminPassword" type="password" placeholder="Contraseña privada"><button class="action primary" onclick="doAdminLogin()">Entrar a administración</button><p id="adminMsg" class="notice"></p></div><div id="adminSpace" class="panel" style="display:none"><h2>Empresas registradas</h2><p class="sub">Activa después de confirmar el pago o desactiva cuando sea necesario.</p><div id="companyList"></div></div></section></main><script>let companyToken='';let adminKey='';function show(id,button){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelector('#'+id).classList.add('active');document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));button.classList.add('active')}async function signup(){const r=await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:signupId.value,name:signupName.value,sector:signupSector.value,email:signupEmail.value,password:signupPassword.value})});const d=await r.json();signupMsg.textContent=r.ok?d.message+' Envía $100.000 COP al Nequi 3113617292.':d.detail;}async function companyLogin(){const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})});const d=await r.json();loginMsg.textContent=r.ok?'Sesión iniciada.':d.detail;if(r.ok){companyToken=d.token;document.querySelector('#companySpace').style.display='block';loadClients();}}async function loadClients(){const r=await fetch('/my-clients',{headers:{Authorization:'Bearer '+companyToken}});const list=await r.json();clientList.innerHTML=list.map(c=>'<p>'+c.name+' · '+c.phone+'</p>').join('')||'<p>No hay clientes.</p>';}async function addClient(){const r=await fetch('/my-clients',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+companyToken},body:JSON.stringify({name:newClientName.value,phone:newClientPhone.value})});if(r.ok){newClientName.value='';newClientPhone.value='';loadClients();}}async function book(){const r=await fetch('/book',{method:'POST',headers:{'Content-Type':'application/json','X-Company-ID':bookCompany.value},body:JSON.stringify({client_name:bookName.value,phone:bookPhone.value,starts_at:new Date(bookDate.value).toISOString(),reason:bookReason.value})});const d=await r.json();bookMsg.textContent=r.ok?'Solicitud enviada correctamente.':d.detail;}async function doAdminLogin(){const r=await fetch('/admin-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:adminEmail.value,password:adminPassword.value})});const d=await r.json();if(!r.ok){adminMsg.textContent=d.detail;return}adminKey=d.admin_key;document.querySelector('#adminLoginPanel').style.display='none';document.querySelector('#adminSpace').style.display='block';loadCompanies();}async function loadCompanies(){const r=await fetch('/owner/companies',{headers:{'X-Admin-Key':adminKey}});const list=await r.json();companyList.innerHTML=list.map(c=>'<div class="row"><div><b>'+c.name+'</b><br><small>'+c.company_id+' · '+c.email+' · '+c.status+'</small></div><div><button class="action primary" onclick="setStatus(\\''+c.company_id+'\\',\\'active\\')">Activar</button><button class="action danger" onclick="setStatus(\\''+c.company_id+'\\',\\'disabled\\')">Desactivar</button></div></div>').join('')||'<p>No hay empresas.</p>';}async function setStatus(id,status){await fetch('/owner/status/'+id+'/'+status,{method:'POST',headers:{'X-Admin-Key':adminKey}});loadCompanies();}</script></body></html>"""


def wendy_dashboard_page() -> str:
	return """<!doctype html>
<html lang="es">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>Nexora AI</title>
	<style>
		:root {
			--bg: #06141c;
			--panel: rgba(18, 40, 51, 0.92);
			--panel-soft: rgba(11, 27, 37, 0.94);
			--border: rgba(89, 247, 211, 0.32);
			--text: #ecfdfd;
			--muted: #9ab7c2;
			--accent: #59f7d3;
			--shadow: rgba(89,247,211,0.16);
		}
		* { box-sizing: border-box; }
		body {
			margin: 0;
			font-family: "Segoe UI", sans-serif;
			color: var(--text);
			background: radial-gradient(circle at top, #123a4c 0%, #06141c 42%);
		}
		.shell { max-width: 1200px; margin: 0 auto; padding: 28px 18px 54px; }
		.topbar { display: flex; justify-content: space-between; align-items: center; gap: 20px; margin-bottom: 20px; }
		.brand { font-size: 12px; letter-spacing: 2px; text-transform: uppercase; color: var(--accent); font-weight: 700; }
		.brand strong { display: block; margin-top: 6px; font-size: 24px; letter-spacing: 0; color: var(--text); }
		.badge { background: rgba(89,247,211,0.08); border: 1px solid var(--border); border-radius: 999px; padding: 8px 14px; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; color: var(--accent); }
		.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 18px; box-shadow: 0 12px 32px var(--shadow); overflow: hidden; }
		.hero { padding: 28px 26px; background: linear-gradient(135deg, rgba(13,31,42,0.9), rgba(8,17,25,0.92)); }
		.hero h1 { margin: 10px 0 8px; font-size: clamp(2rem, 5vw, 3.3rem); line-height: 1.1; font-weight: 800; }
		.subtitle { color: var(--muted); line-height: 1.7; margin: 0; max-width: 620px; }
		.grid-two { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin-top: 22px; }
		.field { display: flex; flex-direction: column; gap: 8px; }
		.field label { font-size: 12px; color: var(--muted); letter-spacing: 0.08em; text-transform: uppercase; }
		input, textarea, button { font: inherit; }
		input, textarea { width: 100%; background: rgba(6,20,28,0.8); color: var(--text); border: 1px solid var(--border); border-radius: 12px; padding: 12px 13px; outline: none; }
		input:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(89,247,211,0.1); }
		textarea { min-height: 120px; resize: vertical; }
		.primary-btn, .secondary-btn { border: none; border-radius: 12px; padding: 12px 16px; cursor: pointer; font-weight: 700; transition: filter 0.2s ease; }
		.primary-btn { background: linear-gradient(135deg, var(--accent), #8af1d9); color: #05232a; box-shadow: 0 10px 24px rgba(89,247,211,0.2); }
		.secondary-btn { background: rgba(125,216,255,0.12); color: var(--text); border: 1px solid rgba(125,216,255,0.3); }
		.primary-btn:hover, .secondary-btn:hover { filter: brightness(1.06); }
		.notice { min-height: 22px; color: var(--accent); margin-top: 12px; font-size: 14px; line-height: 1.5; }
		.company-panel { display: none; padding: 22px; margin-top: 22px; }
		.company-panel.visible { display: block; }
		.company-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 18px; }
		.company-header h2 { margin: 0; font-size: 1.6rem; }
		.chat-layout { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 18px; }
		.chat-card { background: var(--panel-soft); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
		.chat-header { background: rgba(89,247,211,0.05); border-bottom: 1px solid var(--border); padding: 16px 18px; font-weight: 700; color: var(--accent); }
		.chat-body { height: 360px; overflow-y: auto; padding: 16px; background: #0b1b25; }
		.message { max-width: 78%; padding: 11px 13px; border-radius: 14px; margin-bottom: 12px; line-height: 1.5; font-size: 14px; word-wrap: break-word; }
		.message.ai { background: rgba(89,247,211,0.08); border: 1px solid rgba(89,247,211,0.2); margin-right: auto; }
		.message.client { background: rgba(199,248,106,0.08); border: 1px solid rgba(199,248,106,0.2); margin-right: auto; }
		.message.human { background: rgba(125,216,255,0.08); border: 1px solid rgba(125,216,255,0.2); margin-left: auto; }
		.chat-footer { display: grid; grid-template-columns: 1fr 2.6fr auto; gap: 10px; padding: 14px; border-top: 1px solid var(--border); background: rgba(7,19,25,0.9); }
		.info-card { background: var(--panel-soft); border: 1px solid var(--border); border-radius: 16px; padding: 18px; }
		.info-card h3 { margin-top: 0; margin-bottom: 16px; font-size: 1.08rem; }
		.meta-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; margin-top: 22px; }
		.mini-panel { background: var(--panel-soft); border: 1px solid var(--border); border-radius: 16px; padding: 18px; }
		.mini-panel h3 { margin-top: 0; margin-bottom: 12px; font-size: 1.03rem; }
		.list { display: flex; flex-direction: column; gap: 10px; color: var(--muted); font-size: 14px; }
		.list-item { padding: 10px 12px; border-radius: 10px; background: rgba(6,20,28,0.7); border: 1px solid rgba(255,255,255,0.04); }
		.list-item strong { display: block; color: var(--text); margin-bottom: 4px; }
		@media (max-width: 900px) {
			.grid-two, .chat-layout, .meta-grid { grid-template-columns: 1fr; }
			.company-header { flex-direction: column; align-items: flex-start; }
			.chat-footer { grid-template-columns: 1fr; }
		}
	</style>
</head>
<body>
	<main class="shell">
		<header class="topbar">
			<div class="brand">Nexora AI<strong>IA Empresarial</strong></div>
			<div class="badge">Cuenta privada</div>
		</header>

		<section class="panel hero">
			<div class="brand">Plataforma multiempresa</div>
			<h1>Chats privados para cada empresa</h1>
			<p class="subtitle">Cada cuenta gestiona su propio chat, sus clientes, sus citas y su información interna. La inteligencia artificial responde solo con los datos de esa empresa, nunca con los de otra.</p>
			<div class="grid-two">
				<div class="field"><label>Código de la empresa</label><input id="bookCompany"></div>
				<div class="field"><label>Nombre</label><input id="bookName"></div>
				<div class="field"><label>Teléfono</label><input id="bookPhone"></div>
				<div class="field"><label>Fecha y hora</label><input id="bookDate" type="datetime-local"></div>
				<div class="field" style="grid-column: 1 / -1;"><label>Motivo</label><input id="bookReason"></div>
				<div class="field" style="grid-column: 1 / -1;"><button id="bookSubmit" class="primary-btn" type="button">Solicitar cita</button><div id="bookMsg" class="notice"></div></div>
			</div>
		</section>

		<section class="panel company-panel" id="companySpace">
			<div class="company-header">
				<h2 id="companyTitle">Panel de empresa</h2>
				<button id="logoutCompanyBtn" class="secondary-btn" type="button">Cerrar sesión</button>
			</div>
			<div class="chat-layout">
				<div class="chat-card">
					<div class="chat-header">Chat de atención</div>
					<div class="chat-body" id="chatMessages"></div>
					<div class="chat-footer">
						<input id="chatSender">
						<input id="chatInput">
						<button id="chatSend" class="primary-btn" type="button">Enviar</button>
					</div>
				</div>
				<div class="info-card">
					<h3>Información privada para la IA</h3>
					<div class="field"><label>Descripción general</label><textarea id="companyAbout"></textarea></div>
					<div class="field" style="margin-top: 14px;"><label>Inventario, precios y conocimiento</label><textarea id="companyKnowledge"></textarea></div>
					<button id="infoSave" class="primary-btn" type="button" style="margin-top: 14px; width: 100%;">Guardar información</button>
					<div id="companyInfoStatus" class="notice"></div>
				</div>
			</div>
			<div class="meta-grid">
				<div class="mini-panel"><h3>Clientes</h3><div id="clientList" class="list"></div></div>
				<div class="mini-panel"><h3>Citas</h3><div id="appointmentList" class="list"></div></div>
			</div>
		</section>

		<section class="panel hero" style="margin-top: 22px;">
			<div class="brand">Cuenta empresa</div>
			<div class="grid-two" style="margin-top: 14px;">
				<div class="field"><label>Correo</label><input id="loginEmail" type="email"></div>
				<div class="field"><label>Contraseña</label><input id="loginPassword" type="password"></div>
				<div class="field" style="grid-column: 1 / -1;"><button id="loginSubmit" class="primary-btn" type="button">Iniciar sesión</button><div id="loginMsg" class="notice"></div></div>
			</div>

			<div class="grid-two" style="margin-top: 16px;">
				<div class="field"><label>Código único</label><input id="signupId"></div>
				<div class="field"><label>Nombre de la empresa</label><input id="signupName"></div>
				<div class="field"><label>Sector</label><input id="signupSector"></div>
				<div class="field"><label>Plan</label><input id="signupPlan"></div>
				<div class="field"><label>Correo</label><input id="signupEmail" type="email"></div>
				<div class="field"><label>Contraseña</label><input id="signupPassword" type="password"></div>
				<div class="field" style="grid-column: 1 / -1;"><button id="signupSubmit" class="primary-btn" type="button">Registrar empresa</button><div id="signupMsg" class="notice"></div></div>
			</div>
		</section>

		<section class="panel hero" style="margin-top: 22px;">
			<div class="brand">Administración</div>
			<div class="grid-two" style="margin-top: 14px;">
				<div class="field"><label>Correo del propietario</label><input id="adminEmail" type="email"></div>
				<div class="field"><label>Clave de acceso</label><input id="adminPassword" type="password"></div>
				<div class="field" style="grid-column: 1 / -1;"><button id="adminSubmit" class="primary-btn" type="button">Entrar al panel</button><div id="adminMsg" class="notice"></div></div>
			</div>
			<div id="adminPanel" class="company-panel" style="display:none; margin-top: 18px;">
				<div class="company-header">
					<h2>Empresas registradas</h2>
					<button id="logoutAdminBtn" class="secondary-btn" type="button">Cerrar panel</button>
				</div>
				<div id="adminCompanyList" class="list"></div>
			</div>
		</section>
	</main>

	<script>
		let companyToken = '';
		let adminKey = '';

		function readableError(data) {
			if (Array.isArray(data && data.detail)) {
				return data.detail.map(function (item) {
					return item.msg || item;
				}).join('. ');
			}
			return (data && data.detail) || 'No se pudo completar la solicitud.';
		}

		function renderMessages(messages) {
			var container = document.getElementById('chatMessages');
			if (!container) return;
			container.innerHTML = '';
			if (!messages.length) {
				container.innerHTML = '<div class="message ai">Aún no hay mensajes. Cuando un cliente escriba, aparecerá aquí.</div>';
				return;
			}
			messages.slice().reverse().forEach(function (item) {
				var el = document.createElement('div');
				var role = item.role === 'human' ? 'human' : (item.role === 'client' ? 'client' : 'ai');
				el.className = 'message ' + role;
				el.textContent = (item.sender || 'Sistema') + ': ' + item.message;
				container.appendChild(el);
			});
			container.scrollTop = container.scrollHeight;
		}

		function renderList(targetId, items, formatter) {
			var el = document.getElementById(targetId);
			if (!el) return;
			if (!items.length) {
				el.innerHTML = '<div class="list-item">Sin registros.</div>';
				return;
			}
			el.innerHTML = items.map(formatter).join('');
		}

		async function loadDashboard() {
			var headers = { Authorization: 'Bearer ' + companyToken };
			var [clientsRes, appointmentsRes, chatRes, infoRes] = await Promise.all([
				fetch('/my-clients', { headers: headers }),
				fetch('/my-appointments', { headers: headers }),
				fetch('/my-chat', { headers: headers }),
				fetch('/my-knowledge', { headers: headers })
			]);
			if (clientsRes.ok) {
				var clients = await clientsRes.json();
				renderList('clientList', clients, function (item) {
					return '<div class="list-item"><strong>' + (item.name || 'Cliente') + '</strong>' + (item.phone || 'Sin teléfono') + '</div>';
				});
			}
			if (appointmentsRes.ok) {
				var appointments = await appointmentsRes.json();
				renderList('appointmentList', appointments, function (item) {
					return '<div class="list-item"><strong>' + (item.client_name || 'Cita') + '</strong>' + new Date(item.starts_at).toLocaleString() + '<br>' + (item.reason || 'Sin motivo') + '</div>';
				});
			}
			if (chatRes.ok) {
				var messages = await chatRes.json();
				renderMessages(messages);
			}
			if (infoRes.ok) {
				var info = await infoRes.json();
				document.getElementById('companyTitle').textContent = info.name || 'Panel de empresa';
				document.getElementById('companyAbout').value = info.about || '';
				document.getElementById('companyKnowledge').value = (info.knowledge || []).join('\\n');
			}
		}

		async function signupCompany() {
			var payload = {
				company_id: document.getElementById('signupId').value,
				name: document.getElementById('signupName').value,
				sector: document.getElementById('signupSector').value,
				email: document.getElementById('signupEmail').value,
				password: document.getElementById('signupPassword').value,
				plan_id: document.getElementById('signupPlan').value || 'premium'
			};
			var response = await fetch('/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
			var data = await response.json();
			document.getElementById('signupMsg').textContent = response.ok ? (data.message + ' · ' + data.plan + ' · $' + data.amount_cop + ' COP/mes') : readableError(data);
		}

		async function adminLogin() {
			var response = await fetch('/admin-login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: document.getElementById('adminEmail').value, password: document.getElementById('adminPassword').value }) });
			var data = await response.json();
			if (!response.ok) {
				document.getElementById('adminMsg').textContent = readableError(data);
				return;
			}
			adminKey = data.admin_key;
			document.getElementById('adminMsg').textContent = 'Panel del propietario abierto.';
			document.getElementById('adminPanel').style.display = 'block';
			loadCompanies();
		}

		function logoutAdmin() {
			adminKey = '';
			document.getElementById('adminPanel').style.display = 'none';
			document.getElementById('adminMsg').textContent = 'Panel cerrado.';
		}

		async function loadCompanies() {
			if (!adminKey) return;
			var response = await fetch('/owner/companies', { headers: { 'X-Admin-Key': adminKey } });
			var data = await response.json();
			if (!response.ok) {
				document.getElementById('adminMsg').textContent = readableError(data);
				return;
			}
			var list = document.getElementById('adminCompanyList');
			list.innerHTML = data.map(function (item) {
				return '<div class="list-item"><strong>' + item.name + '</strong>' + item.company_id + ' · ' + item.status + ' · ' + item.plan + '<div style="display:flex; gap:8px; margin-top:10px;">' +
				'<button class="primary-btn" type="button" data-status-action="' + item.company_id + '|active">Activar</button>' +
				'<button class="secondary-btn" type="button" data-status-action="' + item.company_id + '|disabled">Desactivar</button>' +
				'</div></div>';
			}).join('') || '<div class="list-item">No hay empresas registradas.</div>';
		}

		async function toggleCompanyStatus(companyId, status) {
			if (!adminKey) return;
			var response = await fetch('/owner/status/' + companyId + '/' + status, { method: 'POST', headers: { 'X-Admin-Key': adminKey } });
			if (response.ok) loadCompanies();
		}

		async function companyLogin() {
			var response = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: document.getElementById('loginEmail').value, password: document.getElementById('loginPassword').value }) });
			var data = await response.json();
			if (!response.ok) {
				document.getElementById('loginMsg').textContent = readableError(data);
				return;
			}
			companyToken = data.token;
			document.getElementById('companySpace').classList.add('visible');
			document.getElementById('loginMsg').textContent = 'Sesión iniciada correctamente.';
			loadDashboard();
		}

		function logoutCompany() {
			companyToken = '';
			document.getElementById('companySpace').classList.remove('visible');
			document.getElementById('loginMsg').textContent = 'Sesión cerrada.';
		}

		async function saveCompanyInfo() {
			var payload = { about: document.getElementById('companyAbout').value, knowledge: document.getElementById('companyKnowledge').value.split('\\n').map(function (item) { return item.trim(); }).filter(Boolean) };
			var response = await fetch('/my-knowledge', { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + companyToken }, body: JSON.stringify(payload) });
			var data = await response.json();
			document.getElementById('companyInfoStatus').textContent = response.ok ? 'Información guardada y lista para la IA.' : readableError(data);
			if (response.ok) loadDashboard();
		}

		async function sendManualReply() {
			var sender = document.getElementById('chatSender').value.trim() || 'empresa';
			var message = document.getElementById('chatInput').value.trim();
			if (!message) return;
			var response = await fetch('/my-chat/reply', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + companyToken }, body: JSON.stringify({ sender: sender, message: message }) });
			if (response.ok) { document.getElementById('chatInput').value = ''; loadDashboard(); }
		}

		async function bookAppointment() {
			var payload = {
				client_name: document.getElementById('bookName').value,
				phone: document.getElementById('bookPhone').value,
				starts_at: new Date(document.getElementById('bookDate').value).toISOString(),
				reason: document.getElementById('bookReason').value
			};
			var response = await fetch('/book', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Company-ID': document.getElementById('bookCompany').value }, body: JSON.stringify(payload) });
			var data = await response.json();
			document.getElementById('bookMsg').textContent = response.ok ? 'Cita enviada correctamente.' : readableError(data);
		}

		function bindActionHandlers() {
			var mapped = {
				loginSubmit: companyLogin,
				signupSubmit: signupCompany,
				adminSubmit: adminLogin,
				bookSubmit: bookAppointment,
				chatSend: sendManualReply,
				infoSave: saveCompanyInfo,
				logoutCompanyBtn: logoutCompany,
				logoutAdminBtn: logoutAdmin
			};
			Object.keys(mapped).forEach(function (id) {
				var el = document.getElementById(id);
				if (el && typeof mapped[id] === 'function') {
					el.onclick = mapped[id];
				}
			});
			document.addEventListener('click', function (event) {
				var target = event.target;
				if (!(target instanceof HTMLElement)) return;
				var action = target.getAttribute('data-status-action');
				if (!action) return;
				var pieces = action.split('|');
				if (pieces[0] && pieces[1]) toggleCompanyStatus(pieces[0], pieces[1]);
			});
		}

		window.companyLogin = companyLogin;
		window.signupCompany = signupCompany;
		window.adminLogin = adminLogin;
		window.bookAppointment = bookAppointment;
		window.sendManualReply = sendManualReply;
		window.saveCompanyInfo = saveCompanyInfo;
		window.logoutCompany = logoutCompany;
		window.logoutAdmin = logoutAdmin;
		window.toggleCompanyStatus = toggleCompanyStatus;
		window.loadCompanies = loadCompanies;
		bindActionHandlers();
	</script>
</body>
</html>"""


@app.get("/workspace", response_class=HTMLResponse)
def workspace_page() -> str:
	return wendy_dashboard_page()
	return """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Plataforma Neon</title><style>:root{font-family:Segoe UI,sans-serif;color:#e9f7ff;background:#061019}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 5%,#123d4b,#061019 42%)}.wrap{max-width:1050px;margin:auto;padding:28px 20px 60px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.brand{font:600 26px Georgia,serif}.status{color:#55efd4;font-size:12px;letter-spacing:1px}.hero,.panel{background:#0b202d;border:1px solid #55efd444;border-radius:16px;padding:28px;box-shadow:0 0 28px #55efd414,0 18px 50px #0007}.hero{background:linear-gradient(135deg,#0d2b38,#0a1722 65%)}h1{font:600 44px Georgia,serif;margin:8px 0 12px}h2{font-size:21px;margin-top:0}.sub{color:#a9c5d0;line-height:1.6;max-width:680px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.tabs button,.action{border:1px solid #55efd455;background:#0b1a25;color:#dffefa;padding:11px 15px;border-radius:8px;cursor:pointer}.tabs button.active,.action.primary{background:#55efd4;color:#06201f;font-weight:700}.view{display:none}.view.active{display:block}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.field{display:grid;gap:6px;margin:9px 0}label{color:#9fc0cb;font-size:13px}input{width:100%;padding:12px;border:1px solid #55efd455;background:#061923;color:#e9f7ff;border-radius:8px;font-size:15px}input:focus{outline:0;border-color:#55efd4;box-shadow:0 0 14px #55efd433}.action{margin-top:8px}.notice{color:#55efd4;line-height:1.5;min-height:22px}.pay{border:1px solid #c7f86a55;background:#c7f86a0d;padding:16px;border-radius:10px;margin:15px 0}.pay strong{color:#c7f86a;font-size:20px}.company{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #ffffff16;padding:13px 0;gap:10px}.company small{color:#a9c5d0}.danger{border-color:#ff769055;color:#ffb3b3}.clients{margin-top:18px;color:#c8e3ea;line-height:1.8}@media(max-width:700px){h1{font-size:35px}.grid{grid-template-columns:1fr}.top{align-items:flex-start;gap:12px;flex-direction:column}}
</style></head><body><main class="wrap"><header class="top"><div class="brand">NEON//WORKSPACE</div><div class="status">● PLATAFORMA ACTIVA</div></header><section class="hero"><div class="status">ASISTENCIA INTELIGENTE MULTIEMPRESA</div><h1>Una sola plataforma. Cada negocio, su propio espacio.</h1><p class="sub">Agenda citas, registra clientes y administra accesos con una experiencia rápida, privada y preparada para crecer.</p></section><nav class="tabs"><button class="active" onclick="show('book',this)">Agendar cita</button><button onclick="show('company',this)">Espacio de empresa</button><button onclick="show('admin',this)">Administración</button></nav><section id="book" class="view active"><div class="panel"><h2>Agenda una cita</h2><p class="sub">Elige la empresa y envía tu solicitud.</p><div class="grid"><div class="field"><label>Empresa</label><input id="bookCompany" value="claro" placeholder="Código de empresa"></div><div class="field"><label>Nombre</label><input id="bookName" placeholder="Tu nombre"></div><div class="field"><label>Teléfono</label><input id="bookPhone" placeholder="Tu teléfono"></div><div class="field"><label>Fecha y hora</label><input id="bookDate" type="datetime-local"></div></div><div class="field"><label>Motivo</label><input id="bookReason" placeholder="¿En qué podemos ayudarte?"></div><button class="action primary" onclick="book()">Solicitar cita</button><p id="bookMsg" class="notice"></p></div></section><section id="company" class="view"><div class="grid"><div class="panel"><h2>Entrar a mi espacio</h2><div class="field"><label>Correo</label><input id="loginEmail" type="email" placeholder="correo@empresa.com"></div><div class="field"><label>Contraseña</label><input id="loginPassword" type="password" placeholder="Tu contraseña"></div><button class="action primary" onclick="companyLogin()">Iniciar sesión</button><p id="loginMsg" class="notice"></p></div><div class="panel"><h2>Registrar empresa</h2><div class="pay"><strong>$100.000 COP / mes</strong><br>Pago por Nequi: <b>3113617292</b><br><small>Después de confirmar el pago activaremos tu espacio.</small></div><div class="field"><label>Código</label><input id="signupId" placeholder="mi-empresa"></div><div class="field"><label>Nombre y sector</label><input id="signupName" placeholder="Nombre de empresa"><input id="signupSector" placeholder="Sector"></div><div class="field"><label>Correo y contraseña</label><input id="signupEmail" type="email" placeholder="correo@empresa.com"><input id="signupPassword" type="password" placeholder="Mínimo 8 caracteres"></div><button class="action" onclick="signup()">Enviar registro</button><p id="signupMsg" class="notice"></p></div></div><div id="companySpace" class="panel" style="display:none;margin-top:16px"><h2>Mis clientes</h2><div class="grid"><input id="newClientName" placeholder="Nombre del cliente"><input id="newClientPhone" placeholder="Teléfono"></div><button class="action primary" onclick="addClient()">Añadir cliente</button><div id="clientList" class="clients"></div></div></section><section id="admin" class="view"><div id="adminLogin" class="panel"><h2>Acceso del propietario</h2><p class="sub">Aquí puedes revisar pagos y controlar el acceso de cada empresa.</p><div class="field"><label>Correo administrador</label><input id="adminEmail" value="admin@plataforma.local"></div><div class="field"><label>Contraseña</label><input id="adminPassword" type="password"></div><button class="action primary" onclick="adminLogin()">Entrar a administración</button><p id="adminMsg" class="notice"></p></div><div id="adminSpace" class="panel" style="display:none"><h2>Empresas registradas</h2><p class="sub">Activa después de confirmar el pago o desactiva cuando sea necesario.</p><div id="companyList"></div></div></section></main><script>let companyToken='';let adminKey='';function show(id,button){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelector('#'+id).classList.add('active');document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));button.classList.add('active')}async function signup(){const r=await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:signupId.value,name:signupName.value,sector:signupSector.value,email:signupEmail.value,password:signupPassword.value})});const d=await r.json();signupMsg.textContent=r.ok?d.message+' Envía $100.000 COP al Nequi 3113617292.':d.detail;}async function companyLogin(){const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})});const d=await r.json();if(!r.ok){loginMsg.textContent=d.detail;return}companyToken=d.token;loginMsg.textContent='Sesión iniciada.';document.querySelector('#companySpace').style.display='block';loadClients();}async function loadClients(){const r=await fetch('/my-clients',{headers:{Authorization:'Bearer '+companyToken}});const list=await r.json();clientList.innerHTML=list.map(c=>'<div>'+c.name+' · '+c.phone+'</div>').join('')||'No hay clientes todavía.';}async function addClient(){const r=await fetch('/my-clients',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+companyToken},body:JSON.stringify({name:newClientName.value,phone:newClientPhone.value})});if(r.ok){newClientName.value='';newClientPhone.value='';loadClients();}}async function book(){const r=await fetch('/book',{method:'POST',headers:{'Content-Type':'application/json','X-Company-ID':bookCompany.value},body:JSON.stringify({client_name:bookName.value,phone:bookPhone.value,starts_at:new Date(bookDate.value).toISOString(),reason:bookReason.value})});const d=await r.json();bookMsg.textContent=r.ok?'Solicitud enviada correctamente.':d.detail;}async function adminLogin(){const r=await fetch('/admin-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:adminEmail.value,password:adminPassword.value})});const d=await r.json();if(!r.ok){adminMsg.textContent=d.detail;return}adminKey=d.admin_key;adminLogin.style.display='none';adminSpace.style.display='block';loadCompanies();}async function loadCompanies(){const r=await fetch('/owner/companies',{headers:{'X-Admin-Key':adminKey}});const list=await r.json();companyList.innerHTML=list.map(c=>'<div class="company"><div><b>'+c.name+'</b><br><small>'+c.company_id+' · '+c.email+' · '+c.status+'</small></div><div><button class="action primary" onclick="setStatus(\\''+c.company_id+'\\',\\'active\\')">Activar</button><button class="action danger" onclick="setStatus(\\''+c.company_id+'\\',\\'disabled\\')">Desactivar</button></div></div>').join('')||'No hay empresas registradas.';}async function setStatus(id,status){await fetch('/owner/status/'+id+'/'+status,{method:'POST',headers:{'X-Admin-Key':adminKey}});loadCompanies();}</script></body></html>"""


@app.post("/companies/{company_id}", response_model=CompanyConfig)
def register_company(
	company_id: str,
	config: CompanyConfig,
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> CompanyConfig:
	require_admin_key(admin_key)
	with database_lock, database:
		database.execute(
			"INSERT OR REPLACE INTO companies (company_id, config) VALUES (?, ?)",
			(company_id, config.model_dump_json()),
		)
	return config


@app.get("/companies/me", response_model=CompanyConfig)
def get_company_config(
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> CompanyConfig:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	return fetch_company_config(company_id)


@app.post("/assistant")
def assistant_reply(
	request: AssistantMessage,
	company_id: Annotated[str, Header(alias="X-Company-ID")],
) -> dict[str, str]:
	company_id_from_header(company_id)
	config = fetch_company_config(company_id)
	reply = generate_ai_reply(company_id, request.message)
	return {"reply": reply, "company": config.name}


@app.get("/webhooks/whatsapp/{company_id}")
def whatsapp_verify(
	company_id: str,
	mode: str | None = None,
	verify_token: str | None = None,
	challenge: str | None = None,
) -> str:
	with database_lock:
		exists = database.execute(
			"SELECT 1 FROM companies WHERE company_id = ?", (company_id,)
		).fetchone()
	if exists is None:
		raise HTTPException(status_code=404, detail="La empresa no está registrada.")
	if mode == "subscribe" and verify_token == os.getenv("META_WHATSAPP_VERIFY_TOKEN"):
		return challenge or ""
	raise HTTPException(status_code=403, detail="Verificación de WhatsApp rechazada.")


@app.post("/webhooks/whatsapp/{company_id}")
def whatsapp_webhook(company_id: str, payload: dict) -> dict[str, str]:
	entry = payload.get("entry", [{}])[0]
	change = entry.get("changes", [{}])[0].get("value", {})
	messages = change.get("messages", [])
	if not messages:
		return {"status": "ignored"}
	message = messages[0]
	request = ChannelMessage(sender=message["from"], message=message.get("text", {}).get("body", ""))
	reply = process_channel_message(company_id, "whatsapp", request)
	send_whatsapp_message(request.sender, reply)
	return {"channel": "whatsapp", "reply": reply}


@app.post("/webhooks/email/{company_id}")
def email_webhook(company_id: str, request: ChannelMessage) -> dict[str, str]:
	reply = process_channel_message(company_id, "email", request)
	send_email_message(request.sender, "Respuesta de tu asistente", reply)
	return {"channel": "email", "reply": reply}


@app.post("/book", response_model=Appointment)
def public_booking(
	appointment: Appointment,
	company_id: Annotated[str, Header(alias="X-Company-ID")],
) -> Appointment:
	company_id_from_header(company_id)
	enforce_booking_limit(company_id, appointment)
	with database_lock, database:
		if appointment.phone:
			existing = database.execute(
				"SELECT id FROM clients WHERE company_id = ? AND json_extract(data, '$.phone') = ?",
				(company_id, appointment.phone),
			).fetchone()
			if existing is None:
				client = Client(name=appointment.client_name, phone=appointment.phone)
				database.execute(
					"INSERT INTO clients (company_id, data) VALUES (?, ?)",
					(company_id, client.model_dump_json()),
				)
		database.execute(
			"INSERT INTO appointments (company_id, data) VALUES (?, ?)",
			(company_id, appointment.model_dump_json()),
		)
	return appointment


@app.get("/reservar/{company_id}", response_class=HTMLResponse)
def booking_page(company_id: str) -> str:
	company_id_from_header(company_id)
	config = fetch_company_config(company_id)
	return f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agendar con {config.name}</title><style>:root{{font-family:Segoe UI,sans-serif;color:#e9f7ff;background:#07131d}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 15% 0,#123c4d 0,#07131d 42%),#07131d}}main{{max-width:540px;margin:auto;padding:40px 20px}}section{{background:#0b202d;border:1px solid #55efd444;padding:30px;border-radius:16px;box-shadow:0 0 28px #55efd41a,0 20px 60px #0008}}.eyebrow{{color:#55efd4;text-transform:uppercase;letter-spacing:2px;font-size:12px}}h1{{font:600 38px Georgia,serif;margin:12px 0}}p{{color:#a9c5d0;line-height:1.5}}input,button{{box-sizing:border-box;width:100%;padding:14px;margin:7px 0;border:1px solid #55efd455;background:#071923;color:#e9f7ff;border-radius:8px;font-size:15px}}input:focus{{outline:0;border-color:#55efd4;box-shadow:0 0 14px #55efd433}}button{{background:#55efd4;color:#06201f;border:0;cursor:pointer;font-weight:700;box-shadow:0 0 18px #55efd433}}#message{{line-height:1.5;margin-top:16px;color:#dffefa}}</style></head><body><main><section><div class="eyebrow">Agenda segura</div><h1>Reserva tu cita</h1><p>Completa tus datos y recibirás confirmación de {config.name}.</p><input id="name" placeholder="Tu nombre"><input id="phone" placeholder="Tu teléfono"><input id="date" type="datetime-local"><input id="reason" placeholder="Motivo de la cita"><button onclick="book()">Solicitar cita</button><div id="message"></div></section></main><script>async function book(){{const message=document.querySelector('#message');const data={{client_name:document.querySelector('#name').value,phone:document.querySelector('#phone').value,starts_at:new Date(document.querySelector('#date').value).toISOString(),reason:document.querySelector('#reason').value}};const r=await fetch('/book',{{method:'POST',headers:{{'Content-Type':'application/json','X-Company-ID':'{company_id}'}},body:JSON.stringify(data)}});const result=await r.json();message.textContent=r.ok?'Solicitud recibida. {config.name} se pondrá en contacto contigo.':result.detail;}}</script></body></html>"""


@app.get("/reports/summary")
def report_summary(
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> dict[str, int | str]:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	return {
		"company": fetch_company_config(company_id).name,
		"clients": len(read_records("clients", company_id)),
		"appointments": len(read_records("appointments", company_id)),
		"quotes": len(read_records("quotes", company_id)),
	}


@app.post("/clients", response_model=Client)
def create_client(
	client: Client,
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> Client:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	with database_lock, database:
		database.execute(
			"INSERT INTO clients (company_id, data) VALUES (?, ?)",
			(company_id, client.model_dump_json()),
		)
	return client


@app.get("/clients", response_model=list[Client])
def list_clients(
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> list[Client]:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	return [Client.model_validate(record) for record in read_records("clients", company_id)]


@app.post("/appointments", response_model=Appointment)
def create_appointment(
	appointment: Appointment,
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> Appointment:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	with database_lock, database:
		database.execute(
			"INSERT INTO appointments (company_id, data) VALUES (?, ?)",
			(company_id, appointment.model_dump_json()),
		)
	return appointment


@app.get("/appointments", response_model=list[Appointment])
def list_appointments(
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> list[Appointment]:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	return [
		Appointment.model_validate(record)
		for record in read_records("appointments", company_id)
	]


@app.post("/quotes")
def create_quote(
	quote: Quote,
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> dict:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	total = sum(item.quantity * item.unit_price for item in quote.items)
	quote_record = {
		"client_name": quote.client_name,
		"items": quote.items,
		"notes": quote.notes,
		"total": round(total, 2),
		"status": "draft",
	}
	with database_lock, database:
		database.execute(
			"INSERT INTO quotes (company_id, data) VALUES (?, ?)",
			(company_id, json.dumps(quote_record, default=str)),
		)
	return quote_record


@app.get("/quotes")
def list_quotes(
	company_id: Annotated[str, Header(alias="X-Company-ID")],
	admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> list[dict]:
	require_admin_key(admin_key)
	company_id_from_header(company_id)
	return read_records("quotes", company_id)


_original_fixed_workspace_page = fixed_workspace_page


def fixed_workspace_page() -> str:
	page = _original_fixed_workspace_page()
	page = page.replace(
		'<div class="field"><label>Código</label><input id="signupId" placeholder="mi-empresa"></div><div class="field"><label>Nombre y sector</label><input id="signupName" placeholder="Nombre"><input id="signupSector" placeholder="Sector"></div><div class="field"><label>Acceso</label><input id="signupEmail" type="email" placeholder="Correo"><input id="signupPassword" type="password" placeholder="Mínimo 8 caracteres"></div>',
		'<div class="field"><label>Código único de la empresa</label><input id="signupId" placeholder="mi-empresa"></div><div class="field"><label>Nombre de la empresa</label><input id="signupName" placeholder="Nombre"></div><div class="field"><label>Actividad o sector</label><input id="signupSector" placeholder="Sector"></div><div class="field"><label>Correo para iniciar sesión</label><input id="signupEmail" type="email" placeholder="Correo"></div><div class="field"><label>Contraseña de acceso</label><input id="signupPassword" type="password" placeholder="Mínimo 8 caracteres"></div>',
		1,
	)
	page = page.replace("<title>Plataforma Neon</title>", "<title>Nexora AI</title>", 1)
	page = page.replace(
		"<div class=\"sub\">NEON//WORKSPACE · PLATAFORMA MULTIEMPRESA</div>",
		"<div class=\"sub\">NEXORA AI · PLATAFORMA MULTIEMPRESA</div>",
		1,
	)
	page = page.replace(
		"<h1>Una sola plataforma. Cada negocio, su propio espacio.</h1>",
		"<h1>Nexora AI</h1><p class=\"sub\" style=\"color:#55efd4;font-size:18px;\">Construimos hoy la confianza que impulsa el futuro de tu empresa.</p><h1 style=\"font-size:28px;\">Una sola plataforma. Cada negocio, su propio espacio.</h1>",
		1,
	)
	page = re.sub(r" placeholder=\"[^\"]*\"", "", page)
	page = page.replace(' value="claro"', "")
	page = page.replace(' value="demo"', "")
	page = page.replace(' value="¿Cuál es el horario de atención?"', "")
	page = page.replace(' value="admin@plataforma.local"', "")
	page = page.replace(
		'<div class="field"><label>Datos de empresa</label><input id="signupPlan" type="hidden" value="basic"><input id="signupId"><input id="signupName"><input id="signupSector"></div><div class="field"><label>Acceso</label><input id="signupEmail" type="email"><input id="signupPassword" type="password"></div>',
		'<input id="signupPlan" type="hidden" value="basic"><div class="field"><label>Código único de la empresa</label><input id="signupId"></div><div class="field"><label>Nombre de la empresa</label><input id="signupName"></div><div class="field"><label>Actividad o sector</label><input id="signupSector"></div><div class="field"><label>Correo para iniciar sesión</label><input id="signupEmail" type="email"></div><div class="field"><label>Contraseña de acceso</label><input id="signupPassword" type="password"></div>',
		1,
	)
	plans_markup = "<section class=\"plan-grid\"><div class=\"plan\"><b>Esencial · Gratis</b><p>Hasta 40 clientes agendando citas</p><small>Agenda básica · Registro de clientes · Portal empresarial</small><button onclick=\"choosePlan('basic')\">Elegir plan</button></div><div class=\"plan\"><b>Profesional · $50.000 COP/mes</b><p>Hasta 100 clientes agendando citas</p><small>Todo lo esencial · Más capacidad · Asistente y conversaciones</small><button onclick=\"choosePlan('pro')\">Elegir plan</button></div><div class=\"plan featured\"><b>Ilimitado · $100.000 COP/mes</b><p>Clientes agendando citas sin límite</p><small>Todo lo profesional · Sin límite · Máxima capacidad</small><button onclick=\"choosePlan('unlimited')\">Elegir plan</button></div></section>"
	page = re.sub(r"<div class=\"pay\">.*?</div>", "", page, count=1, flags=re.S)
	plans_markup += "<div class=\"pay\"><strong>Pago de planes pagos por Nequi: 3113617292</strong><br><small>Después de confirmar el pago activaremos el espacio de la empresa.</small></div>"
	page = page.replace(
		"<section id=\"company\" class=\"view\">",
		"<section id=\"company\" class=\"view\">" + plans_markup,
		1,
	)
	page = page.replace("<input id=\"signupId\"", "<input id=\"signupPlan\" type=\"hidden\" value=\"basic\"><input id=\"signupId\"", 1)
	page = page.replace(".row{display:flex;", ".plan-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}.plan{background:#0b202d;border:1px solid #55efd455;border-radius:12px;padding:18px}.plan b{color:#c7f86a;font-size:18px}.plan p{color:#e9f7ff}.plan small{display:block;color:#a9c5d0;line-height:1.5;min-height:48px}.plan button{margin-top:12px;padding:10px;border:1px solid #55efd455;background:#55efd4;color:#06201f;border-radius:7px;font-weight:700;cursor:pointer}.featured{box-shadow:0 0 24px #55efd433}@media(max-width:700px){.plan-grid{grid-template-columns:1fr}}.row{display:flex;", 1)
	page = page.replace(
		"<header><div class=\"sub\">NEON//WORKSPACE · PLATAFORMA MULTIEMPRESA</div>",
		"<header style=\"display:flex;justify-content:space-between;align-items:flex-start;gap:24px;\"><div><div class=\"sub\">NEON//WORKSPACE · PLATAFORMA MULTIEMPRESA</div>",
		1,
	)
	page = page.replace(
		"</p></header><nav class=\"tabs\">",
		"</p></div><aside style=\"border:1px solid #55efd455;background:#071923;padding:14px 16px;border-radius:10px;min-width:235px;box-shadow:0 0 18px #55efd422;\"><div style=\"color:#55efd4;font-size:11px;letter-spacing:1px;text-transform:uppercase;\">Creador</div><strong style=\"display:block;margin:6px 0;color:#e9f7ff;\">Juaquin Gonzalez</strong><small style=\"display:block;color:#a9c5d0;\">WhatsApp: 3113617292</small><small style=\"display:block;color:#a9c5d0;word-break:break-word;\">Correo: nexoraai231@gmail.com</small></aside></header><nav class=\"tabs\">",
		1,
	)
	page = page.replace(
		"@media(max-width:700px){h1{font-size:35px}.grid{grid-template-columns:1fr}}",
		"@media(max-width:700px){h1{font-size:35px}.grid{grid-template-columns:1fr}header{flex-direction:column}header aside{width:100%;min-width:0!important}}",
		1,
	)
	page = re.sub(
		r"<script>.*?</script>",
		"""<script>
let companyToken = '';
let adminKey = '';
function show(section, button) { document.querySelectorAll('.view').forEach(item => item.classList.remove('active')); document.getElementById(section).classList.add('active'); document.querySelectorAll('.tabs button').forEach(item => item.classList.remove('active')); button.classList.add('active'); }
function choosePlan(plan) { show('company', document.querySelectorAll('.tabs button')[1]); signupPlan.value=plan; signupMsg.textContent='Plan seleccionado: '+plan; }
function readableError(data) { if (Array.isArray(data.detail)) return data.detail.map(error => error.msg).join('. '); return data.detail || 'No se pudo completar la solicitud.'; }
async function signup() { const response=await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:signupId.value,name:signupName.value,sector:signupSector.value,email:signupEmail.value,password:signupPassword.value,plan_id:signupPlan.value})}); const data=await response.json(); if(!response.ok){signupMsg.textContent=readableError(data);return;} signupMsg.textContent=data.message+' Plan: '+data.plan+' · $'+data.amount_cop+' COP/mes · Límite: '+data.limit+'.'; if(data.amount_cop!=='0'){const payment=document.createElement('a');payment.href='nequi://';payment.textContent='Abrir Nequi para pagar';payment.style='display:inline-block;margin-top:10px;color:#c7f86a;font-weight:700';payment.onclick=()=>setTimeout(()=>{signupMsg.textContent='Si Nequi no se abrió, envía $'+data.amount_cop+' COP al número 3113617292 y espera la activación.';},700);signupMsg.appendChild(document.createElement('br'));signupMsg.appendChild(payment);} }
async function book() { const response=await fetch('/book',{method:'POST',headers:{'Content-Type':'application/json','X-Company-ID':bookCompany.value},body:JSON.stringify({client_name:bookName.value,phone:bookPhone.value,starts_at:new Date(bookDate.value).toISOString(),reason:bookReason.value})}); const data=await response.json(); bookMsg.textContent=response.ok?'Solicitud enviada correctamente.':data.detail; }
async function companyLogin() { const response = await fetch('/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})}); const data = await response.json(); loginMsg.textContent = response.ok ? 'Sesión iniciada.' : readableError(data); if (response.ok) { companyToken=data.token; companySpace.style.display='block'; loadClients(); loadAppointments(); } }
async function loadClients() { const response=await fetch('/my-clients',{headers:{Authorization:'Bearer '+companyToken}}); const list=await response.json(); clientList.innerHTML=list.map(item=>'<p>'+item.name+' · '+item.phone+'</p>').join('')||'<p>No hay clientes.</p>'; }
async function loadAppointments() { const response=await fetch('/my-appointments',{headers:{Authorization:'Bearer '+companyToken}}); const list=await response.json(); appointmentList.innerHTML=list.map(item=>'<p><strong>'+item.client_name+'</strong> · '+(item.phone||'Sin teléfono')+' · '+new Date(item.starts_at).toLocaleString()+' · '+item.reason+'</p>').join('')||'<p>No hay citas.</p>'; }
async function addClient() { const response=await fetch('/my-clients',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+companyToken},body:JSON.stringify({name:newClientName.value,phone:newClientPhone.value})}); if(response.ok){newClientName.value='';newClientPhone.value='';loadClients();} }
async function doAdminLogin() { const response=await fetch('/admin-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:adminEmail.value,password:adminPassword.value})}); const data=await response.json(); if(!response.ok){adminMsg.textContent=data.detail;return;} adminKey=data.admin_key; adminLoginPanel.style.display='none'; adminSpace.style.display='block'; loadCompanies(); }
async function loadCompanies() { const response=await fetch('/owner/companies',{headers:{'X-Admin-Key':adminKey}}); const list=await response.json(); companyList.innerHTML=''; list.forEach(item=>{ const row=document.createElement('div'); row.className='row'; const info=document.createElement('span'); info.textContent=item.name+' · '+item.company_id+' · '+item.status; const activate=document.createElement('button'); activate.className='action primary'; activate.textContent='Activar'; activate.onclick=()=>setStatus(item.company_id,'active'); const disable=document.createElement('button'); disable.className='action danger'; disable.textContent='Desactivar'; disable.onclick=()=>setStatus(item.company_id,'disabled'); row.append(info,activate,disable); companyList.appendChild(row); }); }
async function setStatus(companyId,newStatus) { await fetch('/owner/status/'+companyId+'/'+newStatus,{method:'POST',headers:{'X-Admin-Key':adminKey}}); loadCompanies(); }
</script>""",
		page,
		count=1,
		flags=re.S,
	)
	page = page.replace(
		'<div id="clientList"></div></div></section><section id="admin"',
		'<div id="clientList"></div><h2>Mis citas</h2>'
		'<div id="appointmentList" class="clients"></div></div></section><section id="admin"',
	)
	page = page.replace(
		"loadClients();}}async function loadClients()",
		"loadClients();loadAppointments();}}async function loadClients()",
	)
	page = re.sub(
		r'<div class="field"><label>Datos de empresa</label><input id="signupPlan".*?<input id="signupSector"></div><div class="field"><label>Acceso</label><input id="signupEmail" type="email"><input id="signupPassword" type="password"></div>',
		'<input id="signupPlan" type="hidden" value="basic"><div class="field"><label>Código único de la empresa</label><input id="signupId"></div><div class="field"><label>Nombre de la empresa</label><input id="signupName"></div><div class="field"><label>Actividad o sector</label><input id="signupSector"></div><div class="field"><label>Correo para iniciar sesión</label><input id="signupEmail" type="email"></div><div class="field"><label>Contraseña de acceso</label><input id="signupPassword" type="password"></div>',
		page,
		count=1,
		flags=re.S,
	)
	return page
