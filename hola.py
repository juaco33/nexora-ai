import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from threading import Lock
from typing import Annotated, Any
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Nexora AI",
    version="0.3.0",
    description="Landing page + multi-company assistant + booking flow.",
)

DB_PATH = os.getenv("VIRTUAL_EMPLOYEE_DATABASE") or os.getenv("NEXORA_DB_PATH") or os.path.join(os.path.dirname(__file__), "nexora.db")
ADMIN_EMAIL = (os.getenv("VIRTUAL_EMPLOYEE_ADMIN_EMAIL") or os.getenv("NEXORA_ADMIN_EMAIL") or "admin@nexora.ai").lower()
ADMIN_KEY = os.getenv("VIRTUAL_EMPLOYEE_ADMIN_KEY") or os.getenv("NEXORA_ADMIN_KEY") or ""
if not ADMIN_KEY:
  owner_key_path = os.path.join(os.path.dirname(__file__), "owner.key")
  if os.path.isfile(owner_key_path):
    with open(owner_key_path, encoding="utf-8") as key_file:
      ADMIN_KEY = key_file.read().strip()
database_lock = Lock()


class CompanySignup(BaseModel):
    company_id: str = Field(..., min_length=3)
    name: str = Field(..., min_length=2)
    sector: str = ""
    email: str
    password: str = Field(..., min_length=6)
    plan_id: str = "starter"
    profile_photo_url: str | None = None
    description: str = ""


class CompanyLogin(BaseModel):
    email: str
    password: str


class CompanyProfileUpdate(BaseModel):
    about: str | None = None
    description: str | None = None
    profile_photo_url: str | None = None
    knowledge: list[str] | None = None


class AppointmentRequest(BaseModel):
    client_name: str = Field(..., min_length=1)
    phone: str = ""
    starts_at: str = Field(..., min_length=1)
    reason: str = ""


class MessageRequest(BaseModel):
    message: str = Field(..., min_length=1)


class ChatReply(BaseModel):
    sender: str = "empresa"
    message: str = Field(..., min_length=1)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
  salt = secrets.token_bytes(16)
  digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
  return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> tuple[bool, str | None]:
  if stored_hash.startswith("pbkdf2_sha256$"):
    _, salt_hex, digest_hex = stored_hash.split("$", 2)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310_000)
    return hmac.compare_digest(digest.hex(), digest_hex), None
  legacy_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
  valid = hmac.compare_digest(legacy_digest, stored_hash)
  return valid, hash_password(password) if valid else None


def make_token(company_id: str, email: str) -> str:
  return secrets.token_urlsafe(32)


def initialize_db() -> None:
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS companies (
            company_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            sector TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan_id TEXT DEFAULT 'starter',
            status TEXT DEFAULT 'active',
            description TEXT DEFAULT '',
            about TEXT DEFAULT '',
            profile_photo_url TEXT DEFAULT '',
            knowledge TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            phone TEXT,
            reason TEXT,
            starts_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


initialize_db()


def company_from_token(token: str | None) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido.")
    conn = get_db()
    row = conn.execute(
      "SELECT sessions.company_id, companies.status FROM sessions JOIN companies USING (company_id) WHERE sessions.token = ?",
      (token,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Sesión inválida.")
    if row["status"] != "active":
      raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    return row["company_id"]


def company_record(company_id: str) -> dict[str, Any] | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM companies WHERE company_id = ?", (company_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def public_company_payload(company: dict[str, Any]) -> dict[str, Any]:
    return {
        "company_id": company["company_id"],
        "name": company["name"],
        "sector": company["sector"],
        "description": company["description"],
        "about": company["about"],
        "profile_photo_url": company["profile_photo_url"],
        "status": company["status"],
        "plan": company["plan_id"],
    }


def workspace_page() -> str:
    return """<!doctype html>
<html lang=\"es\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Nexora AI</title>
  <style>
    :root {
      --bg: #051821;
      --panel: rgba(10, 25, 35, 0.96);
      --panel-soft: rgba(12, 33, 42, 0.9);
      --border: rgba(89, 247, 211, 0.28);
      --text: #effefb;
      --muted: #a7c7d0;
      --accent: #59f7d3;
      --alt: #a7ffb5;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top, #173d4d 0%, #051821 38%, #020d13 100%);
    }
    .shell { max-width: 1200px; margin: 0 auto; padding: 24px 18px 60px; }
    .topbar { display: flex; justify-content: space-between; align-items: center; padding: 8px 0 18px; }
    .brand { font-size: 12px; letter-spacing: 0.18em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
    .brand strong { display: block; margin-top: 8px; font-size: 28px; letter-spacing: -0.04em; text-transform: none; color: var(--text); }
    .badge { padding: 8px 14px; border-radius: 999px; border: 1px solid var(--border); background: rgba(89,247,211,0.08); color: var(--accent); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; }
    .hero {
      padding: 36px 30px;
      border-radius: 24px;
      border: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(11,30,39,0.95), rgba(5,22,30,0.96));
      box-shadow: 0 18px 60px rgba(0,0,0,0.25);
      position: relative;
      overflow: hidden;
    }
    .hero::before { content: ""; position: absolute; inset: 0; background: radial-gradient(circle at top right, rgba(89,247,211,0.15), transparent 34%); }
    .hero > * { position: relative; z-index: 1; }
    .eyebrow { display: inline-flex; padding: 8px 12px; border-radius: 999px; background: rgba(89,247,211,0.08); border: 1px solid rgba(89,247,211,0.2); color: var(--accent); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 700; }
    h1 { margin: 18px 0 12px; font-size: clamp(2.7rem, 5vw, 4.3rem); line-height: 0.98; letter-spacing: -0.06em; }
    .subtitle { max-width: 720px; margin: 0; color: var(--muted); line-height: 1.7; font-size: 1.05rem; }
    .actions { display:flex; flex-wrap:wrap; gap:12px; margin-top:22px; }
    button, input, textarea { font: inherit; }
    .primary-btn, .secondary-btn {
      border: none;
      border-radius: 12px;
      padding: 12px 18px;
      font-weight: 700;
      cursor: pointer;
    }
    .primary-btn { background: linear-gradient(135deg, var(--accent), #8ae9d3); color: #04262d; box-shadow: 0 12px 30px rgba(89,247,211,0.18); }
    .secondary-btn { background: rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.1); color: var(--text); }
    .stats { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:14px; margin-top:28px; }
    .stat { padding: 16px 14px; border-radius: 16px; background: rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06); }
    .stat strong { display:block; font-size:1.5rem; color:var(--accent); margin-bottom:6px; }
    .stat span { color:var(--muted); font-size:0.8rem; }
    .section { margin-top: 28px; }
    .section h2 { margin: 0 0 10px; font-size: clamp(1.8rem,3vw,2.4rem); letter-spacing: -0.04em; }
    .section p { margin: 0; color: var(--muted); line-height: 1.7; }
    .cards { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:18px; margin-top:18px; }
    .card { padding: 22px 20px; border-radius: 18px; background: var(--panel-soft); border:1px solid var(--border); }
    .card h3 { margin: 0 0 10px; }
    .card p { margin: 0; color: var(--muted); }
    .panel { padding: 22px 22px 26px; border-radius:20px; border:1px solid var(--border); background: rgba(9,24,31,0.96); box-shadow: 0 18px 44px rgba(0,0,0,0.2); }
    .grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:16px; margin-top:18px; }
    .field { display:flex; flex-direction:column; gap:8px; }
    .field label { font-size: 11px; color: var(--muted); letter-spacing: 0.1em; text-transform: uppercase; }
    input, textarea { width: 100%; padding: 12px 13px; border-radius:12px; border:1px solid var(--border); background: rgba(5,18,25,0.9); color: var(--text); }
    textarea { min-height: 110px; resize: vertical; }
    .notice { min-height: 22px; margin-top: 10px; color: var(--accent); }
    .public-tabs { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:10px; margin:26px 0 18px; }
    .public-tab { padding:13px 16px; border-radius:12px; border:1px solid var(--border); background: rgba(255,255,255,0.02); color: var(--text); font-weight:700; cursor:pointer; }
    .public-tab.active { background: var(--accent); color:#04252d; }
    .public-section { display:none; }
    .public-section.active { display:block; }
    .company-profile-card { display:none; align-items:center; gap:14px; margin:0 0 18px; padding:16px; border:1px solid rgba(89,247,211,0.2); border-radius:16px; background: rgba(89,247,211,0.04); }
    .company-profile-card.visible { display:flex; }
    .company-profile-card img { width:72px; height:72px; border-radius:50%; object-fit:cover; border:2px solid rgba(89,247,211,0.4); }
    .booking-chat { margin-top: 18px; border-radius:16px; border:1px solid var(--border); overflow:hidden; background: rgba(9,22,30,0.8); }
    .booking-chat-header { padding:14px 16px; border-bottom:1px solid var(--border); color: var(--accent); font-weight:700; }
    .booking-chat-body { max-height: 220px; overflow-y:auto; padding: 14px; }
    .booking-chat-message { max-width:82%; padding:10px 12px; margin-bottom:8px; border-radius:12px; }
    .booking-chat-message.ai { background: rgba(89,247,211,0.08); border:1px solid rgba(89,247,211,0.2); }
    .booking-chat-message.client { background: rgba(125,216,255,0.08); border:1px solid rgba(125,216,255,0.18); margin-left:auto; }
    .booking-chat-footer { display:grid; grid-template-columns:1fr auto; gap:10px; padding:12px; border-top:1px solid var(--border); }
    .company-panel { display:none; margin-top:18px; }
    .company-panel.visible { display:block; }
    .company-header { display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:18px; }
    .company-header h2 { margin:0; }
    .chat-layout { display:grid; grid-template-columns: minmax(0,1.4fr) minmax(0,1fr); gap:18px; }
    .chat-card, .info-card, .mini-panel { background: rgba(10,25,35,0.92); border:1px solid var(--border); border-radius:18px; overflow:hidden; }
    .chat-header { padding:16px 18px; border-bottom:1px solid var(--border); background: rgba(89,247,211,0.06); color: var(--accent); font-weight:700; }
    .chat-body { height:340px; overflow-y:auto; padding:16px; background: rgba(6,19,25,0.92); }
    .message { max-width:78%; margin-bottom:12px; padding:11px 13px; border-radius:14px; }
    .message.ai { background: rgba(89,247,211,0.08); border:1px solid rgba(89,247,211,0.2); margin-right:auto; }
    .message.human { background: rgba(125,216,255,0.08); border:1px solid rgba(125,216,255,0.18); margin-left:auto; }
    .chat-footer { display:grid; grid-template-columns:1fr 2.2fr auto; gap:10px; padding:12px; border-top:1px solid var(--border); }
    .info-card, .mini-panel { padding:18px; }
    .meta-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:18px; margin-top:22px; }
    .list-item { padding:10px 12px; border-radius:10px; background: rgba(5,17,24,0.8); border:1px solid rgba(255,255,255,0.04); color: var(--muted); margin-bottom:8px; }
    .list-item strong { display:block; color: var(--text); margin-bottom:4px; }
    .admin-panel { display:none; margin-top:18px; }
    .admin-panel.visible { display:block; }
    @media (max-width: 980px) { .cards, .stats, .grid, .chat-layout, .meta-grid { grid-template-columns:1fr; } }
    @media (max-width: 640px) { .public-tabs, .stats, .cards { grid-template-columns:1fr; } .topbar, .company-header { flex-direction:column; align-items:flex-start; } .chat-footer { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main class=\"shell\">
    <header class=\"topbar\">
      <div class=\"brand\">Nexora AI<strong>IA Empresarial</strong></div>
      <div class=\"badge\">Cuenta privada</div>
    </header>

    <section class=\"hero\">
      <div class=\"eyebrow\">Plataforma multiempresa</div>
      <h1>La IA que hace que cada negocio se vea más profesional y venda más.</h1>
      <p class=\"subtitle\">Atiende clientes 24/7, organiza citas y ofrece una atención premium con contexto real para cada empresa.</p>
      <div class=\"actions\">
        <button class=\"primary-btn js-scroll-target\" type=\"button\" data-target=\"bookingSection\">Solicitar demo</button>
        <button class=\"secondary-btn js-scroll-target\" type=\"button\" data-target=\"companyAccessSection\">Registrar empresa</button>
      </div>
      <div class=\"stats\">
        <div class=\"stat\"><strong>24/7</strong><span>Atención activa</span></div>
        <div class=\"stat\"><strong>+40%</strong><span>Más conversiones</span></div>
        <div class=\"stat\"><strong>1</strong><span>Plataforma por empresa</span></div>
        <div class=\"stat\"><strong>0</strong><span>Interrupciones manuales</span></div>
      </div>
    </section>

    <section class=\"section\">
      <h2>Todo lo que tu empresa necesita para vender mejor</h2>
      <p>Una solución creada para operar con claridad, atender rápido y convertir más visitas en oportunidades reales.</p>
      <div class=\"cards\">
        <div class=\"card\"><h3>Reservas automáticas</h3><p>Agenda citas y reduce errores con un proceso más claro para cada cliente.</p></div>
        <div class=\"card\"><h3>Chat IA privado</h3><p>Responde con contexto y ayuda cada negocio sin mezclar información entre empresas.</p></div>
        <div class=\"card\"><h3>Clientes mejor atendidos</h3><p>Organiza historial, conversaciones y seguimiento por empresa para ofrecer atención más clara.</p></div>
        <div class=\"card\"><h3>Control total</h3><p>Gestiona clientes, planes, accesos y operaciones desde un panel central y seguro.</p></div>
      </div>
    </section>

    <nav class=\"public-tabs\" aria-label=\"Secciones principales\">
      <button class=\"public-tab active\" type=\"button\" data-target=\"bookingSection\">Solicitar cita</button>
      <button class=\"public-tab\" type=\"button\" data-target=\"companyAccessSection\">Cuenta de empresa</button>
      <button class=\"public-tab\" type=\"button\" data-target=\"adminAccessSection\">Administrador</button>
    </nav>

    <section class=\"panel public-section active\" id=\"bookingSection\">
      <div class=\"company-profile-card\" id=\"companyProfileCard\">
        <img id=\"companyProfileImage\" alt=\"Logo\" src=\"\" />
        <div>
          <h3 id=\"companyProfileName\">Empresa</h3>
          <p id=\"companyProfileDescription\">La información pública aparecerá cuando el código sea válido.</p>
        </div>
      </div>

      <div style=\"padding:18px;border:1px solid var(--border);border-radius:16px;background:rgba(89,247,211,0.04);margin-bottom:18px;\">
        <div style=\"display:inline-block;margin-bottom:10px;font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--accent);font-weight:700;\">Flujo recomendado</div>
        <div style=\"display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;\">
          <span style=\"padding:7px 10px;border-radius:999px;border:1px solid rgba(89,247,211,0.2);background:rgba(5,17,24,0.8);color:var(--text);font-size:12px;\">1. Elige servicio</span>
          <span style=\"padding:7px 10px;border-radius:999px;border:1px solid rgba(89,247,211,0.2);background:rgba(5,17,24,0.8);color:var(--text);font-size:12px;\">2. Confirma</span>
          <span style=\"padding:7px 10px;border-radius:999px;border:1px solid rgba(89,247,211,0.2);background:rgba(5,17,24,0.8);color:var(--text);font-size:12px;\">3. Recibe recordatorio</span>
        </div>
        <p id=\"bookingPreviewText\" style=\"margin:0;color:var(--muted);line-height:1.7;\">El cliente recibe respuesta rápida, confirmación instantánea y una experiencia clara desde el primer contacto.</p>
      </div>

      <div class=\"grid\">
        <div class=\"field\"><label>Código de la empresa</label><input id=\"bookCompany\" type=\"text\"></div>
        <div class=\"field\"><label>Nombre</label><input id=\"bookName\" type=\"text\"></div>
        <div class=\"field\"><label>Teléfono</label><input id=\"bookPhone\" type=\"text\"></div>
        <div class=\"field\"><label>Fecha y hora</label><input id=\"bookDate\" type=\"datetime-local\"></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><label>Motivo</label><input id=\"bookReason\" type=\"text\"></div>

        <div class=\"booking-chat\" style=\"grid-column:1 / -1;\">
          <div class=\"booking-chat-header\">Habla con la empresa</div>
          <div class=\"field\" style=\"padding: 14px 14px 0;\"><label>Código de la empresa destinataria</label><input id=\"chatCompanyCode\" type=\"text\"></div>
          <div class=\"booking-chat-body\" id=\"publicChatMessages\"><div class=\"booking-chat-message ai\">Hola. Pregúntame por horarios, servicios o cómo agendar tu cita.</div></div>
          <div class=\"booking-chat-footer\"><input id=\"publicChatInput\" type=\"text\" placeholder=\"Escribe tu mensaje\"><button id=\"publicChatSend\" class=\"secondary-btn\" type=\"button\">Enviar</button></div>
        </div>

        <div class=\"field\" style=\"grid-column:1 / -1;\"><button id=\"bookSubmit\" class=\"primary-btn\" type=\"button\">Solicitar cita</button><div id=\"bookMsg\" class=\"notice\"></div></div>
      </div>
    </section>

    <section class=\"panel public-section\" id=\"companyAccessSection\">
      <div class=\"brand\" style=\"margin-bottom:12px;\">Cuenta empresa</div>
      <div class=\"grid\">
        <div class=\"field\"><label>Correo</label><input id=\"loginEmail\" type=\"email\"></div>
        <div class=\"field\"><label>Contraseña</label><input id=\"loginPassword\" type=\"password\"></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><button id=\"loginSubmit\" class=\"primary-btn\" type=\"button\">Iniciar sesión</button><div id=\"loginMsg\" class=\"notice\"></div></div>
      </div>

      <div class=\"grid\" style=\"margin-top:22px;\">
        <div class=\"field\"><label>Código único</label><input id=\"signupId\" type=\"text\"></div>
        <div class=\"field\"><label>Nombre de la empresa</label><input id=\"signupName\" type=\"text\"></div>
        <div class=\"field\"><label>Sector</label><input id=\"signupSector\" type=\"text\"></div>
        <div class=\"field\"><label>Plan</label><input id=\"signupPlan\" type=\"text\" placeholder=\"starter\"></div>
        <div class=\"field\"><label>Correo</label><input id=\"signupEmail\" type=\"email\"></div>
        <div class=\"field\"><label>Contraseña</label><input id=\"signupPassword\" type=\"password\"></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><label>Descripción breve</label><textarea id=\"companyDescription\" placeholder=\"Describe tu negocio, servicios y valor para tus clientes.\"></textarea></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><button id=\"signupSubmit\" class=\"primary-btn\" type=\"button\">Registrar empresa</button><div id=\"signupMsg\" class=\"notice\"></div></div>
      </div>
    </section>

    <section class=\"panel public-section\" id=\"adminAccessSection\">
      <div class=\"brand\" style=\"margin-bottom:12px;\">Administración</div>
      <div class=\"grid\">
        <div class=\"field\"><label>Correo del propietario</label><input id=\"adminEmail\" type=\"email\"></div>
        <div class=\"field\"><label>Clave de acceso</label><input id=\"adminPassword\" type=\"password\"></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><button id=\"adminSubmit\" class=\"primary-btn\" type=\"button\">Entrar al panel</button><div id=\"adminMsg\" class=\"notice\"></div></div>
      </div>
      <div class=\"mini-panel admin-panel\" id=\"adminPanel\">
        <h3>Empresas registradas</h3>
        <div id=\"adminCompanyList\" class=\"list\"></div>
      </div>
    </section>

    <section class=\"panel company-panel\" id=\"companySpace\">
      <div class=\"company-header\">
        <h2 id=\"companyTitle\">Panel de empresa</h2>
        <button id=\"logoutCompanyBtn\" class=\"secondary-btn\" type=\"button\">Cerrar sesión</button>
      </div>
      <div class=\"chat-layout\">
        <div class=\"chat-card\">
          <div class=\"chat-header\">Chat de atención</div>
          <div class=\"chat-body\" id=\"chatMessages\"></div>
          <div class=\"chat-footer\">
            <input id=\"chatSender\" type=\"text\" placeholder=\"Remitente\">
            <input id=\"chatInput\" type=\"text\" placeholder=\"Escribe un mensaje\">
            <button id=\"chatSend\" class=\"primary-btn\" type=\"button\">Enviar</button>
          </div>
        </div>
        <div class=\"info-card\">
          <h3>Información para la IA</h3>
          <div class=\"field\" style=\"margin-top:14px;\"><label>Descripción general</label><textarea id=\"companyAbout\"></textarea></div>
          <div class=\"field\" style=\"margin-top:14px;\"><label>Descripción pública</label><textarea id=\"companyDescriptionField\"></textarea></div>
          <div class=\"field\" style=\"margin-top:14px;\"><label>Conocimiento y servicios</label><textarea id=\"companyKnowledge\"></textarea></div>
          <button id=\"infoSave\" class=\"primary-btn\" type=\"button\" style=\"margin-top:14px;width:100%;\">Guardar información</button>
          <div id=\"companyInfoStatus\" class=\"notice\"></div>
        </div>
      </div>
      <div class=\"meta-grid\">
        <div class=\"mini-panel\"><h3>Clientes</h3><div id=\"clientList\" class=\"list\"></div></div>
        <div class=\"mini-panel\"><h3>Citas</h3><div id=\"appointmentList\" class=\"list\"></div></div>
      </div>
    </section>
  </main>

  <script>
    let companyToken = '';
    let adminKey = '';

    function showSection(sectionId) {
      document.querySelectorAll('.public-section').forEach((section) => {
        section.classList.toggle('active', section.id === sectionId);
      });
      document.querySelectorAll('.public-tab').forEach((tab) => {
        tab.classList.toggle('active', tab.dataset.target === sectionId);
      });
    }

    function errorMessage(data, fallback) {
      if (Array.isArray(data?.detail)) {
        return data.detail.map((item) => item.msg || 'Revisa los datos ingresados.').join(' ');
      }
      return data?.detail || fallback;
    }

    function updatePreview() {
      const name = document.getElementById('bookName')?.value || 'cliente';
      const reason = document.getElementById('bookReason')?.value || 'solicita información';
      const phone = document.getElementById('bookPhone')?.value || 'sin teléfono registrado';
      const preview = document.getElementById('bookingPreviewText');
      if (preview) preview.textContent = `${name} puede reservar con claridad, recibir confirmación automática y un recordatorio antes de la cita para ${reason}. El contacto final queda registrado como ${phone}.`;
    }

    function renderDashboardMessages(messages) {
      const container = document.getElementById('chatMessages');
      if (!container) return;
      container.innerHTML = '';
      if (!messages.length) {
        container.innerHTML = '<div class="message ai">Aún no hay mensajes. Cuando un cliente escriba, aparecerá aquí.</div>';
        return;
      }
      messages.slice().reverse().forEach((item) => {
        const el = document.createElement('div');
        const role = item.role === 'human' ? 'human' : item.role === 'client' ? 'client' : 'ai';
        el.className = 'message ' + role;
        el.textContent = (item.sender || 'Sistema') + ': ' + item.message;
        container.appendChild(el);
      });
      container.scrollTop = container.scrollHeight;
    }

    function renderList(id, items, formatter) {
      const el = document.getElementById(id);
      if (!el) return;
      if (!items.length) {
        el.innerHTML = '<div class="list-item">Sin registros.</div>';
        return;
      }
      el.innerHTML = items.map(formatter).join('');
    }

    async function loadDashboard() {
      const headers = { Authorization: 'Bearer ' + companyToken };
      const [clientsRes, appointmentsRes, chatRes, infoRes] = await Promise.all([
        fetch('/my-clients', { headers }),
        fetch('/my-appointments', { headers }),
        fetch('/my-chat', { headers }),
        fetch('/my-knowledge', { headers })
      ]);
      if (clientsRes.ok) {
        const clients = await clientsRes.json();
        renderList('clientList', clients, (item) => `<div class="list-item"><strong>${item.name || 'Cliente'}</strong>${item.phone || 'Sin teléfono'}</div>`);
      }
      if (appointmentsRes.ok) {
        const appointments = await appointmentsRes.json();
        renderList('appointmentList', appointments, (item) => `<div class="list-item"><strong>${item.client_name || 'Cita'}</strong>${new Date(item.starts_at).toLocaleString()}<br>${item.reason || 'Sin motivo'}</div>`);
      }
      if (chatRes.ok) {
        const messages = await chatRes.json();
        renderDashboardMessages(messages);
      }
      if (infoRes.ok) {
        const info = await infoRes.json();
        document.getElementById('companyTitle').textContent = info.name || 'Panel de empresa';
        document.getElementById('companyAbout').value = info.about || '';
        document.getElementById('companyDescriptionField').value = info.description || '';
        document.getElementById('companyKnowledge').value = (info.knowledge || []).join('\\n');
      }
    }

    async function loadPublicCompanyProfile(companyId) {
      if (!companyId) {
        const card = document.getElementById('companyProfileCard');
        if (card) card.classList.remove('visible');
        return;
      }
      const response = await fetch('/companies/' + companyId + '/public');
      const card = document.getElementById('companyProfileCard');
      const image = document.getElementById('companyProfileImage');
      const name = document.getElementById('companyProfileName');
      const description = document.getElementById('companyProfileDescription');
      if (!card || !image || !name || !description) return;
      if (!response.ok) {
        card.classList.remove('visible');
        return;
      }
      const data = await response.json();
      image.src = data.profile_photo_url || 'https://via.placeholder.com/120x120/0b202d/59f7d3?text=' + encodeURIComponent(data.name || 'Empresa');
      name.textContent = data.name || 'Empresa';
      description.textContent = data.description || data.about || 'La empresa aún no ha agregado una descripción pública.';
      card.classList.add('visible');
    }

    async function companySignup() {
      const companyId = document.getElementById('signupId').value.trim();
      const companyName = document.getElementById('signupName').value.trim();
      const email = document.getElementById('signupEmail').value.trim();
      const password = document.getElementById('signupPassword').value;
      if (companyId.length < 3 || companyName.length < 2 || !email.includes('@') || password.length < 6) {
        document.getElementById('signupMsg').textContent = 'Completa código, nombre y correo válidos. La contraseña debe tener al menos 6 caracteres.';
        return;
      }
      const payload = {
        company_id: companyId,
        name: companyName,
        sector: document.getElementById('signupSector').value.trim(),
        email,
        password,
        plan_id: document.getElementById('signupPlan').value.trim() || 'starter',
        description: document.getElementById('companyDescription').value.trim()
      };
      const response = await fetch('/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      document.getElementById('signupMsg').textContent = response.ok ? `${data.message} · ${data.plan} · $${data.amount_cop} COP/mes` : errorMessage(data, 'No se pudo registrar la empresa.');
    }

    async function companyLogin() {
      const payload = {
        email: document.getElementById('loginEmail').value.trim(),
        password: document.getElementById('loginPassword').value
      };
      const response = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok) {
        document.getElementById('loginMsg').textContent = errorMessage(data, 'Credenciales inválidas.');
        return;
      }
      companyToken = data.token;
      document.getElementById('companySpace').classList.add('visible');
      document.getElementById('loginMsg').textContent = 'Sesión iniciada correctamente.';
      await loadDashboard();
    }

    function logoutCompany() {
      companyToken = '';
      document.getElementById('companySpace').classList.remove('visible');
      document.getElementById('loginMsg').textContent = 'Sesión cerrada.';
    }

    async function saveCompanyInfo() {
      const payload = {
        about: document.getElementById('companyAbout').value,
        description: document.getElementById('companyDescriptionField').value,
        knowledge: document.getElementById('companyKnowledge').value.split('\\n').map((item) => item.trim()).filter(Boolean)
      };
      const response = await fetch('/my-knowledge', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + companyToken },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      document.getElementById('companyInfoStatus').textContent = response.ok ? 'Información guardada y lista para la IA.' : errorMessage(data, 'No se pudo guardar.');
      if (response.ok) await loadDashboard();
    }

    async function sendManualReply() {
      const sender = document.getElementById('chatSender').value.trim() || 'empresa';
      const message = document.getElementById('chatInput').value.trim();
      if (!message) return;
      const response = await fetch('/my-chat/reply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + companyToken },
        body: JSON.stringify({ sender, message })
      });
      if (response.ok) {
        document.getElementById('chatInput').value = '';
        await loadDashboard();
      }
    }

    async function bookAppointment() {
      const companyId = document.getElementById('bookCompany').value.trim();
      const clientName = document.getElementById('bookName').value.trim();
      const startsAt = document.getElementById('bookDate').value;
      if (!companyId || !clientName || !startsAt) {
        document.getElementById('bookMsg').textContent = 'Completa el código de la empresa, el nombre y la fecha y hora.';
        return;
      }
      const payload = {
        client_name: clientName,
        phone: document.getElementById('bookPhone').value.trim(),
        starts_at: startsAt,
        reason: document.getElementById('bookReason').value.trim()
      };
      const response = await fetch('/book', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Company-ID': companyId },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      document.getElementById('bookMsg').textContent = response.ok ? 'Cita enviada correctamente.' : errorMessage(data, 'No se pudo registrar la cita.');
    }

    async function sendPublicChat() {
      const input = document.getElementById('publicChatInput');
      const body = document.getElementById('publicChatMessages');
      const message = input.value.trim();
      const companyId = document.getElementById('chatCompanyCode').value.trim();
      if (!companyId) {
        document.getElementById('bookMsg').textContent = 'Escribe primero el código de la empresa.';
        return;
      }
      if (!message) return;
      const clientMessage = document.createElement('div');
      clientMessage.className = 'booking-chat-message client';
      clientMessage.textContent = message;
      body.appendChild(clientMessage);
      input.value = '';
      const waiting = document.createElement('div');
      waiting.className = 'booking-chat-message ai';
      waiting.textContent = 'Estoy revisando la información de la empresa...';
      body.appendChild(waiting);
      body.scrollTop = body.scrollHeight;
      const response = await fetch('/assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Company-ID': companyId },
        body: JSON.stringify({ message })
      });
      const data = await response.json();
      waiting.textContent = response.ok ? data.reply : errorMessage(data, 'No se pudo contactar la empresa.');
      document.getElementById('bookMsg').textContent = response.ok ? 'Respuesta recibida de la empresa.' : 'No se pudo contactar la empresa.';
      body.scrollTop = body.scrollHeight;
    }

    async function adminLogin() {
      const payload = {
        email: document.getElementById('adminEmail').value.trim(),
        password: document.getElementById('adminPassword').value
      };
      const response = await fetch('/admin-login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok) {
        document.getElementById('adminMsg').textContent = errorMessage(data, 'Credenciales inválidas.');
        return;
      }
      adminKey = data.admin_key;
      document.getElementById('adminPanel').classList.add('visible');
      document.getElementById('adminMsg').textContent = 'Panel del propietario abierto.';
      await loadCompanies();
    }

    async function loadCompanies() {
      if (!adminKey) return;
      const response = await fetch('/owner/companies', { headers: { 'X-Admin-Key': adminKey } });
      const data = await response.json();
      if (!response.ok) {
        document.getElementById('adminMsg').textContent = errorMessage(data, 'No fue posible cargar las empresas.');
        return;
      }
      const list = document.getElementById('adminCompanyList');
      if (!list) return;
      list.replaceChildren();
      if (!data.length) {
        const empty = document.createElement('div');
        empty.className = 'list-item';
        empty.textContent = 'No hay empresas registradas.';
        list.appendChild(empty);
        return;
      }
      data.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'list-item';
        const title = document.createElement('strong');
        title.textContent = item.name;
        row.append(title, document.createTextNode(`${item.company_id} · ${item.status} · ${item.plan}`));
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:8px;margin-top:10px';
        [['Activar', 'active', 'primary-btn'], ['Desactivar', 'disabled', 'secondary-btn']].forEach(([label, status, className]) => {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = className;
          button.dataset.statusAction = `${item.company_id}|${status}`;
          button.textContent = label;
          actions.appendChild(button);
        });
        row.appendChild(actions);
        list.appendChild(row);
      });
    }

    async function toggleStatus(companyId, status) {
      if (!adminKey) return;
      const response = await fetch('/owner/status/' + companyId + '/' + status, { method: 'POST', headers: { 'X-Admin-Key': adminKey } });
      if (response.ok) await loadCompanies();
    }

    document.addEventListener('click', async (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      const targetSection = target.dataset.target;
      if (targetSection) {
        if (target.classList.contains('public-tab')) {
          showSection(targetSection);
          return;
        }
        if (target.classList.contains('js-scroll-target')) {
          showSection(targetSection);
          const el = document.getElementById(targetSection);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
          return;
        }
      }
      const action = target.getAttribute('data-status-action');
      if (action) {
        const [companyId, status] = action.split('|');
        if (companyId && status) await toggleStatus(companyId, status);
      }
    });

    document.getElementById('loginSubmit').onclick = companyLogin;
    document.getElementById('signupSubmit').onclick = companySignup;
    document.getElementById('adminSubmit').onclick = adminLogin;
    document.getElementById('bookSubmit').onclick = bookAppointment;
    document.getElementById('publicChatSend').onclick = sendPublicChat;
    document.getElementById('chatSend').onclick = sendManualReply;
    document.getElementById('infoSave').onclick = saveCompanyInfo;
    document.getElementById('logoutCompanyBtn').onclick = logoutCompany;
    document.querySelectorAll('.public-tab').forEach((tab) => tab.addEventListener('click', () => showSection(tab.dataset.target)));
    document.querySelectorAll('.js-scroll-target').forEach((node) => node.addEventListener('click', () => showSection(node.dataset.target)));
    ['bookName', 'bookPhone', 'bookReason'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', updatePreview);
    });
    const companyCodeInput = document.getElementById('bookCompany');
    if (companyCodeInput) companyCodeInput.addEventListener('input', () => loadPublicCompanyProfile(companyCodeInput.value.trim()));
    const publicChatCodeInput = document.getElementById('chatCompanyCode');
    if (publicChatCodeInput) publicChatCodeInput.addEventListener('input', () => loadPublicCompanyProfile(publicChatCodeInput.value.trim()));
    updatePreview();
  </script>
</body>
</html>"""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return workspace_page()


def generate_ai_reply(company: dict[str, Any], user_message: str) -> str:
  knowledge = json.loads(company["knowledge"] or "[]")
  context = {
    "company": company["name"],
    "sector": company["sector"],
    "description": company["description"] or company["about"],
    "services_and_knowledge": knowledge,
  }
  api_key = os.getenv("OPENAI_API_KEY")
  if api_key:
    request = Request(
      "https://api.openai.com/v1/chat/completions",
      data=json.dumps(
        {
          "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
          "messages": [
            {
              "role": "system",
              "content": "Responde en español, de forma breve y amable, como asistente de esta empresa. Usa solo este contexto y no inventes precios ni disponibilidad: "
              + json.dumps(context, ensure_ascii=False),
            },
            {"role": "user", "content": user_message},
          ],
          "temperature": 0.4,
        }
      ).encode("utf-8"),
      headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
      method="POST",
    )
    try:
      with urlopen(request, timeout=25) as response:
        result = json.loads(response.read().decode("utf-8"))
      answer = result["choices"][0]["message"]["content"].strip()
      if answer:
        return answer
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
      pass
  description = context["description"] or "Esta empresa todavía no ha agregado información detallada."
  services = ", ".join(knowledge[:5]) or "servicios y citas"
  return f"Hola, gracias por escribir a {company['name']}. {description} Podemos ayudarte con {services}. ¿Qué necesitas saber?"


@app.post("/signup")
def signup(payload: CompanySignup) -> dict[str, Any]:
    with database_lock:
        conn = get_db()
        existing = conn.execute("SELECT 1 FROM companies WHERE company_id = ? OR email = ?", (payload.company_id, payload.email.lower())).fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=400, detail="La empresa o el correo ya están registrados.")
        conn.execute(
            "INSERT INTO companies (company_id, name, sector, email, password_hash, plan_id, description, about, profile_photo_url, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
            (
                payload.company_id,
                payload.name,
                payload.sector,
                payload.email.lower(),
                hash_password(payload.password),
                payload.plan_id,
                payload.description,
                "",
                payload.profile_photo_url or "",
            ),
        )
        conn.commit()
        conn.close()
    price_map = {"starter": 150000, "professional": 250000, "enterprise": 400000}
    amount = price_map.get(payload.plan_id.lower(), 150000)
    return {"message": "Empresa registrada correctamente", "plan": payload.plan_id, "amount_cop": amount}


@app.post("/login")
def login(payload: CompanyLogin) -> dict[str, str]:
    conn = get_db()
    row = conn.execute("SELECT * FROM companies WHERE email = ?", (payload.email.lower(),)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    password_valid, upgraded_hash = verify_password(payload.password, row["password_hash"])
    if not password_valid:
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    if row["status"] != "active":
        raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    token = make_token(row["company_id"], row["email"])
    conn = get_db()
    if upgraded_hash:
        conn.execute("UPDATE companies SET password_hash = ? WHERE company_id = ?", (upgraded_hash, row["company_id"]))
    conn.execute("INSERT OR REPLACE INTO sessions (token, company_id, email) VALUES (?, ?, ?)", (token, row["company_id"], row["email"]))
    conn.commit()
    conn.close()
    return {"token": token, "company_id": row["company_id"], "name": row["name"]}


@app.post("/admin-login")
def admin_login(payload: CompanyLogin) -> dict[str, str]:
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Configura VIRTUAL_EMPLOYEE_ADMIN_KEY para habilitar el administrador.")
    if payload.email.lower() != ADMIN_EMAIL or payload.password != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Credenciales de administrador incorrectas.")
    return {"admin_key": ADMIN_KEY}


@app.get("/owner/companies")
def owner_companies(x_admin_key: Annotated[str | None, Header()] = None) -> list[dict[str, Any]]:
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Clave de administrador inválida.")
    conn = get_db()
    rows = conn.execute("SELECT * FROM companies ORDER BY created_at DESC").fetchall()
    conn.close()
    return [public_company_payload(dict(row)) for row in rows]


@app.post("/owner/status/{company_id}/{status}")
def owner_status(company_id: str, status: str, x_admin_key: Annotated[str | None, Header()] = None) -> dict[str, str]:
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Clave de administrador inválida.")
    if status not in {"active", "disabled"}:
        raise HTTPException(status_code=400, detail="Estado inválido.")
    conn = get_db(); conn.execute("UPDATE companies SET status = ? WHERE company_id = ?", (status, company_id)); conn.commit(); conn.close()
    return {"status": status, "company_id": company_id}


@app.get("/my-knowledge")
def read_my_knowledge(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    knowledge = json.loads(company["knowledge"] or "[]")
    return {
        "name": company["name"],
        "about": company["about"],
        "description": company["description"],
        "profile_photo_url": company["profile_photo_url"],
        "knowledge": knowledge,
    }


@app.put("/my-knowledge")
def write_my_knowledge(payload: CompanyProfileUpdate, authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    row = conn.execute("SELECT * FROM companies WHERE company_id = ?", (company_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    knowledge = payload.knowledge if payload.knowledge is not None else json.loads(row["knowledge"] or "[]")
    conn.execute(
        "UPDATE companies SET about = ?, description = ?, profile_photo_url = ?, knowledge = ? WHERE company_id = ?",
        (payload.about if payload.about is not None else row["about"], payload.description if payload.description is not None else row["description"], payload.profile_photo_url if payload.profile_photo_url is not None else row["profile_photo_url"], json.dumps(knowledge), company_id),
    )
    conn.commit(); conn.close()
    return {"updated": True}


@app.get("/my-clients")
def my_clients(authorization: Annotated[str | None, Header()] = None) -> list[dict[str, Any]]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients WHERE company_id = ? ORDER BY created_at DESC", (company_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.post("/my-clients")
def add_my_client(payload: dict[str, Any], authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    name = (payload.get("name") or "Cliente").strip()
    phone = (payload.get("phone") or "").strip()
    email = (payload.get("email") or "").strip()
    conn = get_db()
    conn.execute("INSERT INTO clients (company_id, name, phone, email) VALUES (?, ?, ?, ?)", (company_id, name, phone, email))
    conn.commit(); conn.close()
    return {"name": name, "phone": phone, "email": email}


@app.get("/my-appointments")
def my_appointments(authorization: Annotated[str | None, Header()] = None) -> list[dict[str, Any]]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    rows = conn.execute("SELECT * FROM appointments WHERE company_id = ? ORDER BY starts_at DESC", (company_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/my-chat")
def my_chat(authorization: Annotated[str | None, Header()] = None) -> list[dict[str, Any]]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    rows = conn.execute("SELECT * FROM conversations WHERE company_id = ? ORDER BY id ASC", (company_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.post("/my-chat/reply")
def my_chat_reply(payload: ChatReply, authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db(); conn.execute("INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'human', ?)", (company_id, payload.sender, payload.message)); conn.commit(); conn.close()
    return {"status": "ok"}


@app.post("/book")
def create_booking(payload: AppointmentRequest, x_company_id: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    company_id = x_company_id or payload.model_dump().get("company_id")
    if not company_id:
        raise HTTPException(status_code=400, detail="Falta el código de la empresa.")
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    conn = get_db()
    conn.execute(
        "INSERT INTO appointments (company_id, client_name, phone, reason, starts_at) VALUES (?, ?, ?, ?, ?)",
        (company_id, payload.client_name, payload.phone, payload.reason, payload.starts_at),
    )
    conn.execute(
        "INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'client', ?)",
        (company_id, payload.client_name, f"Solicitud de cita: {payload.reason} para {payload.starts_at}"),
    )
    conn.commit(); conn.close()
    return {"status": "ok", "company_id": company_id}


@app.post("/assistant")
def assistant(payload: MessageRequest, x_company_id: Annotated[str | None, Header()] = None) -> dict[str, str]:
    company_id = x_company_id
    if not company_id:
        raise HTTPException(status_code=400, detail="Falta el código de la empresa.")
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    if company["status"] != "active":
      raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    reply = generate_ai_reply(company, payload.message)
    conn = get_db(); conn.execute("INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'client', ?)", (company_id, 'cliente', payload.message)); conn.execute("INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'ai', ?)", (company_id, 'ia', reply)); conn.commit(); conn.close()
    return {"reply": reply, "company": company['name']}


@app.get("/companies/{company_id}/public")
def public_company(company_id: str) -> dict[str, Any]:
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    if company["status"] == "disabled":
        raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    return public_company_payload(company)


@app.get("/admin")
def admin_root() -> dict[str, str]:
    return {"status": "ok", "email": ADMIN_EMAIL}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hola:app", host="0.0.0.0", port=8000, reload=False)
