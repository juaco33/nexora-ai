import datetime as dt
import base64
import re
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import unicodedata
from threading import Lock
from typing import Annotated, Any, Literal, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from cryptography.fernet import Fernet, InvalidToken
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
PLAN_PRICES_COP = {
    "starter": 39_900,
    "professional": 79_900,
    "enterprise": 139_900,
}
PLAN_MONTHLY_AI_REPLIES = {
    "starter": 100,
    "professional": 500,
    "enterprise": 2_000,
}
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
DEFAULT_WEEKLY_HOURS = {
    day: {"open": "09:00", "close": "17:00"} if index < 5 else None
    for index, day in enumerate(WEEKDAYS)
}
COMPANY_SECTORS = {
    "gastronomico": "Gastronómico",
    "estetico": "Estético",
    "hoteleria": "Hotelería",
    "turismo": "Turismo",
    "salud": "Salud",
    "educacion": "Educación",
    "comercio": "Comercio y tiendas",
    "servicios_profesionales": "Servicios profesionales",
    "mascotas": "Mascotas y veterinaria",
    "automotriz": "Automotriz",
    "entretenimiento": "Entretenimiento y eventos",
    "inmobiliario": "Inmobiliario y construcción",
    "tecnologia": "Tecnología",
    "otro": "Otro",
}
CompanySector = Literal[
    "gastronomico",
    "estetico",
    "hoteleria",
    "turismo",
    "salud",
    "educacion",
    "comercio",
    "servicios_profesionales",
    "mascotas",
    "automotriz",
    "entretenimiento",
    "inmobiliario",
    "tecnologia",
    "otro",
]
LEGACY_SECTOR_ALIASES = {
    "restaurante": "gastronomico",
    "restaurantes": "gastronomico",
    "gastronomia": "gastronomico",
    "alimentos": "gastronomico",
    "estetica": "estetico",
    "belleza": "estetico",
    "peluqueria": "estetico",
    "hotel": "hoteleria",
    "hoteles": "hoteleria",
    "hospedaje": "hoteleria",
    "viajes": "turismo",
    "agencia de viajes": "turismo",
    "clinica": "salud",
    "clinicas": "salud",
    "medicina": "salud",
    "educacion": "educacion",
    "tienda": "comercio",
    "tiendas": "comercio",
    "comercio": "comercio",
    "profesional": "servicios_profesionales",
    "servicios": "servicios_profesionales",
    "veterinaria": "mascotas",
    "autos": "automotriz",
    "eventos": "entretenimiento",
    "construccion": "inmobiliario",
    "inmobiliaria": "inmobiliario",
    "software": "tecnologia",
    "tecnologia": "tecnologia",
    "comercio y tiendas": "comercio",
    "servicios profesionales": "servicios_profesionales",
    "mascotas y veterinaria": "mascotas",
    "entretenimiento y eventos": "entretenimiento",
    "inmobiliario y construccion": "inmobiliario",
}


class CompanySignup(BaseModel):
    company_id: str = Field(..., min_length=3)
    name: str = Field(..., min_length=2)
    sector: CompanySector = "otro"
    email: str
    password: str = Field(..., min_length=6)
    plan_id: Literal["starter", "professional", "enterprise"] = "starter"
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
    weekly_hours: dict[str, Any] | None = None
    appointment_duration_minutes: Literal[15, 30, 45, 60, 90, 120] | None = None


class AppointmentRequest(BaseModel):
    client_name: str = Field(..., min_length=1)
    phone: str = ""
    starts_at: str = Field(..., min_length=1)
    reason: str = ""


class AvailabilityResponse(BaseModel):
    date: str
    duration_minutes: int
    slots: list[dict[str, Any]]


class MessageRequest(BaseModel):
    message: str = Field(..., min_length=1)


class ChatReply(BaseModel):
    sender: str = "empresa"
    message: str = Field(..., min_length=1)


class AppointmentStatusUpdate(BaseModel):
    status: Literal["confirmed", "cancelled"]


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
            weekly_hours TEXT DEFAULT '{}',
            appointment_duration_minutes INTEGER DEFAULT 60,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    company_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(companies)").fetchall()
    }
    for column, definition in (
        ("weekly_hours", "TEXT NOT NULL DEFAULT '{}'"),
        ("appointment_duration_minutes", "INTEGER NOT NULL DEFAULT 60"),
    ):
        if column not in company_columns:
            conn.execute(f"ALTER TABLE companies ADD COLUMN {column} {definition}")
    conn.execute(
        "UPDATE companies SET weekly_hours = ? WHERE weekly_hours IS NULL OR weekly_hours = '{}'",
        (json.dumps(DEFAULT_WEEKLY_HOURS),),
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
            status TEXT NOT NULL DEFAULT 'pending',
            duration_minutes INTEGER NOT NULL DEFAULT 60,
            calendar_event_id TEXT,
            calendar_event_link TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    appointment_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()
    }
    for column, definition in (
        ("status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("duration_minutes", "INTEGER NOT NULL DEFAULT 60"),
        ("calendar_event_id", "TEXT"),
        ("calendar_event_link", "TEXT"),
    ):
        if column not in appointment_columns:
            conn.execute(f"ALTER TABLE appointments ADD COLUMN {column} {definition}")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS calendar_connections (
            company_id TEXT PRIMARY KEY,
            encrypted_token TEXT NOT NULL,
            account_email TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS calendar_oauth_states (
            state_hash TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            session_token_hash TEXT NOT NULL,
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


def canonical_sector(value: str | None) -> str:
    raw_value = (value or "").strip().casefold()
    if raw_value in COMPANY_SECTORS:
        return raw_value
    normalized = unicodedata.normalize("NFKD", value or "")
    normalized = "".join(character for character in normalized if not unicodedata.combining(character))
    normalized = " ".join(normalized.casefold().replace("_", " ").replace("-", " ").split())
    if normalized in COMPANY_SECTORS:
        return normalized.replace(" ", "_")
    return LEGACY_SECTOR_ALIASES.get(normalized, "otro")


def public_company_listing(company: dict[str, Any]) -> dict[str, Any]:
    sector = canonical_sector(company.get("sector"))
    return {
        "company_id": company["company_id"],
        "name": company["name"],
        "sector": sector,
        "sector_label": COMPANY_SECTORS[sector],
        "description": company.get("description") or company.get("about") or "",
        "profile_photo_url": company.get("profile_photo_url") or "",
    }


def plan_ai_reply_limit(plan_id: str) -> int:
    limit = PLAN_MONTHLY_AI_REPLIES.get(plan_id.lower())
    if limit is None:
        raise HTTPException(status_code=409, detail="El plan de esta empresa no es válido. Contacta al administrador.")
    return limit


def monthly_ai_reply_count(company_id: str) -> int:
    conn = get_db()
    row = conn.execute(
        """
        SELECT COUNT(*) AS reply_count FROM conversations
        WHERE company_id = ? AND role = 'ai'
          AND created_at >= strftime('%Y-%m-01 00:00:00', 'now')
        """,
        (company_id,),
    ).fetchone()
    conn.close()
    return int(row["reply_count"])


def company_ai_usage(company: dict[str, Any]) -> dict[str, int]:
    return {
        "ai_replies_used": monthly_ai_reply_count(company["company_id"]),
        "ai_replies_limit": plan_ai_reply_limit(company["plan_id"]),
    }


def validate_weekly_hours(value: Any) -> dict[str, dict[str, str] | None]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="Configura un horario válido para cada día de la semana.")
    value = cast(dict[str, Any], value)
    if set(value) - set(WEEKDAYS):
        raise HTTPException(status_code=422, detail="Configura un horario válido para cada día de la semana.")
    schedule: dict[str, dict[str, str] | None] = {}
    for day in WEEKDAYS:
        hours_value: Any = value.get(day)
        if hours_value is None:
            schedule[day] = None
            continue
        if not isinstance(hours_value, dict):
            raise HTTPException(status_code=422, detail=f"El horario de {day} debe incluir apertura y cierre.")
        hours = cast(dict[str, Any], hours_value)
        if set(hours) != {"open", "close"}:
            raise HTTPException(status_code=422, detail=f"El horario de {day} debe incluir apertura y cierre.")
        opening = hours["open"]
        closing = hours["close"]
        if not isinstance(opening, str) or not isinstance(closing, str):
            raise HTTPException(status_code=422, detail=f"El horario de {day} no es válido.")
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", opening) or not re.fullmatch(
            r"(?:[01]\d|2[0-3]):[0-5]\d", closing
        ):
            raise HTTPException(status_code=422, detail=f"Usa horas válidas en formato de 24 horas para {day}.")
        if opening >= closing:
            raise HTTPException(status_code=422, detail=f"La hora de cierre debe ser posterior a la apertura para {day}.")
        schedule[day] = {"open": opening, "close": closing}
    return schedule


def company_weekly_hours(company: dict[str, Any]) -> dict[str, dict[str, str] | None]:
    try:
        stored = json.loads(company.get("weekly_hours") or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="El horario guardado de la empresa no es válido.") from exc
    if stored == {}:
        stored = DEFAULT_WEEKLY_HOURS
    if not isinstance(stored, dict):
        raise HTTPException(status_code=500, detail="El horario guardado de la empresa no es válido.")
    return validate_weekly_hours(stored)


def local_datetime(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="La fecha y hora de la cita no tienen un formato válido.") from exc
    if parsed.tzinfo is not None:
        try:
            parsed = parsed.astimezone(ZoneInfo(os.getenv("NEXORA_TIME_ZONE", "America/Bogota"))).replace(tzinfo=None)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="NEXORA_TIME_ZONE no es una zona horaria válida.") from exc
    return parsed


def available_slots(
    company: dict[str, Any],
    booking_date: dt.date,
    conn: sqlite3.Connection,
) -> list[dict[str, Any]]:
    try:
        timezone = ZoneInfo(os.getenv("NEXORA_TIME_ZONE", "America/Bogota"))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="NEXORA_TIME_ZONE no es una zona horaria válida.") from exc
    now = dt.datetime.now(timezone).replace(tzinfo=None)
    if booking_date < now.date():
        return []
    schedule = company_weekly_hours(company)
    hours = schedule[WEEKDAYS[booking_date.weekday()]]
    if not hours:
        return []
    duration = int(company.get("appointment_duration_minutes") or 60)
    if duration not in (15, 30, 45, 60, 90, 120):
        raise HTTPException(status_code=500, detail="La duración de cita configurada no es válida.")
    opening = dt.datetime.combine(booking_date, dt.time.fromisoformat(hours["open"]))
    closing = dt.datetime.combine(booking_date, dt.time.fromisoformat(hours["close"]))
    rows = conn.execute(
        """
        SELECT starts_at, duration_minutes FROM appointments
        WHERE company_id = ? AND status IN ('pending', 'confirmed')
          AND starts_at >= ? AND starts_at < ?
        """,
        (company["company_id"], booking_date.isoformat(), (booking_date + dt.timedelta(days=1)).isoformat()),
    ).fetchall()
    booked: list[tuple[dt.datetime, dt.datetime]] = []
    for row in rows:
        booked_start = local_datetime(row["starts_at"])
        booked_duration = int(row["duration_minutes"] or 60)
        booked.append((booked_start, booked_start + dt.timedelta(minutes=booked_duration)))
    slots: list[dict[str, Any]] = []
    start = opening
    while start + dt.timedelta(minutes=duration) <= closing:
        end = start + dt.timedelta(minutes=duration)
        available = start > now and not any(start < busy_end and end > busy_start for busy_start, busy_end in booked)
        slots.append(
            {
                "starts_at": start.isoformat(timespec="minutes"),
                "available": available,
            }
        )
        start = end
    return slots


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


def calendar_configuration_ready() -> bool:
    configured = all(
        os.getenv(name)
        for name in (
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REDIRECT_URI",
            "NEXORA_TOKEN_ENCRYPTION_KEY",
        )
    )
    if not configured:
        return False
    try:
        calendar_fernet()
    except HTTPException:
        return False
    return True


def calendar_fernet() -> Fernet:
    encryption_key = os.getenv("NEXORA_TOKEN_ENCRYPTION_KEY")
    if not encryption_key:
        raise HTTPException(status_code=503, detail="Falta configurar NEXORA_TOKEN_ENCRYPTION_KEY.")
    try:
        return Fernet(encryption_key.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="NEXORA_TOKEN_ENCRYPTION_KEY no es una clave Fernet válida.") from exc


def google_oauth_config() -> tuple[str, str, str]:
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=503, detail="Configura GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET y GOOGLE_REDIRECT_URI.")
    return client_id, client_secret, redirect_uri


def google_token_request(form_data: dict[str, str]) -> dict[str, Any]:
    client_id, client_secret, _ = google_oauth_config()
    request_data = {
        **form_data,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    request = Request(
        "https://oauth2.googleapis.com/token",
        data=urlencode(request_data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise HTTPException(status_code=502, detail="Google rechazó la solicitud OAuth; revisa la configuración de credenciales y permisos.") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="No fue posible completar la solicitud OAuth con Google.") from exc
    if not isinstance(result, dict) or not isinstance(result.get("access_token"), str):
        raise HTTPException(status_code=502, detail="Google devolvió una respuesta OAuth incompleta.")
    return result


def read_calendar_tokens(company_id: str) -> tuple[dict[str, Any], int]:
    conn = get_db()
    row = conn.execute(
        "SELECT encrypted_token, expires_at FROM calendar_connections WHERE company_id = ?",
        (company_id,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=409, detail="Conecta Google Calendar antes de confirmar citas.")
    try:
        tokens = json.loads(calendar_fernet().decrypt(row["encrypted_token"].encode("ascii")))
    except InvalidToken as exc:
        raise HTTPException(status_code=500, detail="No se pudo descifrar la conexión de Google Calendar.") from exc
    if not isinstance(tokens, dict):
        raise HTTPException(status_code=500, detail="La conexión guardada de Google Calendar no es válida.")
    return tokens, row["expires_at"]


def save_calendar_tokens(
    company_id: str,
    tokens: dict[str, Any],
    expires_at: int,
    account_email: str = "",
) -> None:
    encrypted_token = calendar_fernet().encrypt(
        json.dumps(tokens, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    conn = get_db()
    conn.execute(
        """
        INSERT INTO calendar_connections (company_id, encrypted_token, account_email, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(company_id) DO UPDATE SET
            encrypted_token = excluded.encrypted_token,
            account_email = excluded.account_email,
            expires_at = excluded.expires_at,
            updated_at = CURRENT_TIMESTAMP
        """,
        (company_id, encrypted_token, account_email, expires_at),
    )
    conn.commit()
    conn.close()


def refresh_calendar_access_token(company_id: str) -> str:
    tokens, _ = read_calendar_tokens(company_id)
    refresh_token = tokens.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise HTTPException(status_code=409, detail="La conexión de Google no tiene permiso de renovación. Desconéctala y vuelve a conectarla.")
    refreshed = google_token_request(
        {"grant_type": "refresh_token", "refresh_token": refresh_token}
    )
    tokens["access_token"] = refreshed["access_token"]
    expires_at = int(dt.datetime.now(dt.timezone.utc).timestamp()) + int(refreshed.get("expires_in", 3600))
    save_calendar_tokens(company_id, tokens, expires_at)
    return tokens["access_token"]


def google_calendar_request(
    company_id: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    allow_conflict: bool = False,
    ignore_missing: bool = False,
    retry_auth: bool = True,
) -> dict[str, Any]:
    tokens, expires_at = read_calendar_tokens(company_id)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    access_token = tokens.get("access_token")
    if expires_at <= now + 60:
        access_token = refresh_calendar_access_token(company_id)
    if not isinstance(access_token, str) or not access_token:
        raise HTTPException(status_code=409, detail="La conexión de Google Calendar no tiene un token de acceso válido.")
    request = Request(
        "https://www.googleapis.com/calendar/v3/" + path,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urlopen(request, timeout=20) as response:
            response_body = response.read()
        return json.loads(response_body.decode("utf-8")) if response_body else {}
    except HTTPError as exc:
        if exc.code == 401 and retry_auth:
            refresh_calendar_access_token(company_id)
            return google_calendar_request(
                company_id,
                method,
                path,
                payload,
                allow_conflict=allow_conflict,
                ignore_missing=ignore_missing,
                retry_auth=False,
            )
        if exc.code == 409 and allow_conflict:
            return {}
        if exc.code == 404 and ignore_missing:
            return {}
        raise HTTPException(
            status_code=502,
            detail=f"Google Calendar rechazó la operación (HTTP {exc.code}).",
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502, detail="No fue posible comunicarse con Google Calendar.") from exc


def calendar_event_times(starts_at: str, duration_minutes: int = 60) -> tuple[str, str, str]:
    try:
        starts = dt.datetime.fromisoformat(starts_at)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="La fecha y hora de la cita no tienen un formato válido.") from exc
    timezone_name = os.getenv("NEXORA_TIME_ZONE", "America/Bogota")
    try:
        timezone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="NEXORA_TIME_ZONE no es una zona horaria válida.") from exc
    if starts.tzinfo is None:
        starts = starts.replace(tzinfo=timezone)
    ends = starts + dt.timedelta(minutes=duration_minutes)
    return starts.isoformat(), ends.isoformat(), timezone_name


def create_calendar_event(company_id: str, appointment: dict[str, Any]) -> dict[str, str]:
    starts, ends, timezone_name = calendar_event_times(
        appointment["starts_at"], int(appointment.get("duration_minutes") or 60)
    )
    appointment_id = str(appointment["id"])
    event_id = "a" + base64.b32hexencode(
        hashlib.sha256(f"{company_id}:{appointment_id}".encode("utf-8")).digest()
    ).decode("ascii").lower().rstrip("=")
    reason = appointment["reason"] or "Sin detalle"
    payload = {
        "id": event_id,
        "summary": f"Cita · {appointment['client_name']}",
        "description": f"Motivo: {reason}\nTeléfono: {appointment['phone'] or 'No registrado'}\nCreada desde Nexora AI.",
        "start": {"dateTime": starts, "timeZone": timezone_name},
        "end": {"dateTime": ends, "timeZone": timezone_name},
    }
    event = google_calendar_request(
        company_id,
        "POST",
        "calendars/primary/events",
        payload,
        allow_conflict=True,
    )
    if not event.get("id"):
        event = google_calendar_request(
            company_id,
            "GET",
            f"calendars/primary/events/{quote(event_id, safe='')}",
        )
    if not event.get("id"):
        raise HTTPException(status_code=502, detail="Google Calendar no confirmó la creación del evento.")
    return {"id": event_id, "link": str(event.get("htmlLink") or "")}


def calendar_popup_response(connected: bool, message: str) -> HTMLResponse:
    payload = json.dumps(
        {"type": "nexora-calendar-connect", "connected": connected, "message": message}
    ).replace("<", "\\u003c")
    return HTMLResponse(
        "<!doctype html><html lang=\"es\"><meta charset=\"utf-8\"><title>Google Calendar · Nexora</title>"
        "<body style=\"font:16px Segoe UI,sans-serif;background:#051821;color:#effefb;padding:32px\">"
        "<p id=\"status\">Conexión finalizada. Puedes cerrar esta ventana.</p>"
        f"<script>const result={payload};const status=document.getElementById('status');status.textContent=result.message;"
        "if(window.opener){window.opener.postMessage(result,location.origin);window.close();}</script></body></html>",
        headers={"Cache-Control": "no-store"},
    )


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
    .site-nav { display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end; }
    .site-nav button { padding:9px 12px; border:1px solid transparent; border-radius:10px; background:transparent; color:var(--muted); cursor:pointer; }
    .site-nav button:hover { border-color:var(--border); color:var(--accent); }
    .section { margin-top: 28px; }
    .section h2 { margin: 0 0 10px; font-size: clamp(1.8rem,3vw,2.4rem); letter-spacing: -0.04em; }
    .section p { margin: 0; color: var(--muted); line-height: 1.7; }
    .cards { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:18px; margin-top:18px; }
    .directory-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; margin-top:18px; }
    .directory-card { display:flex; flex-direction:column; gap:10px; padding:18px; border:1px solid var(--border); border-radius:16px; background:var(--panel-soft); }
    .directory-card h3, .directory-card p { margin:0; }
    .directory-card p { color:var(--muted); line-height:1.55; }
    .directory-card .case-tag { margin:0; }
    .directory-card button { margin-top:auto; }
    .card { padding: 22px 20px; border-radius: 18px; background: var(--panel-soft); border:1px solid var(--border); }
    .card h3 { margin: 0 0 10px; }
    .card p { margin: 0; color: var(--muted); }
    .case-grid, .steps, .plans { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; margin-top:18px; }
    .case-card, .step-card, .plan-card { padding:22px; border:1px solid var(--border); border-radius:18px; background:var(--panel-soft); }
    .case-tag, .step-number { display:inline-block; margin-bottom:12px; color:var(--accent); font-size:11px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
    .case-card h3, .step-card h3 { margin:0 0 8px; }
    .case-card p, .step-card p { margin:0; color:var(--muted); line-height:1.65; }
    .demo-note { margin-top:16px !important; padding:14px 16px; border-left:3px solid var(--accent); border-radius:8px; background:rgba(89,247,211,.05); font-size:.9rem; }
    .plan-card { display:flex; flex-direction:column; }
    .plan-card.featured { border-color:var(--accent); box-shadow:0 12px 34px rgba(89,247,211,.08); }
    .plan-card h3 { margin:0; font-size:1.2rem; }
    .plan-price { margin:12px 0 4px !important; color:var(--text) !important; font-size:1.8rem; font-weight:800; letter-spacing:-.04em; }
    .plan-price small { color:var(--muted); font-size:.82rem; font-weight:500; letter-spacing:0; }
    .plan-card ul { flex:1; margin:16px 0 20px; padding-left:20px; color:var(--muted); line-height:1.9; }
    .plan-card .primary-btn, .plan-card .secondary-btn { width:100%; }
    .faq-list { display:grid; gap:10px; margin-top:18px; }
    .faq-list details { padding:16px 18px; border:1px solid var(--border); border-radius:14px; background:var(--panel-soft); }
    .faq-list summary { color:var(--text); font-weight:700; cursor:pointer; }
    .faq-list details p { margin-top:10px; }
    #pricing, #industries, #how-it-works, #faq, #signupForm { scroll-margin-top:20px; }
    .panel { padding: 22px 22px 26px; border-radius:20px; border:1px solid var(--border); background: rgba(9,24,31,0.96); box-shadow: 0 18px 44px rgba(0,0,0,0.2); }
    .grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:16px; margin-top:18px; }
    .field { display:flex; flex-direction:column; gap:8px; }
    .field label { font-size: 11px; color: var(--muted); letter-spacing: 0.1em; text-transform: uppercase; }
    input, textarea, select { width: 100%; padding: 12px 13px; border-radius:12px; border:1px solid var(--border); background: rgba(5,18,25,0.9); color: var(--text); }
    textarea { min-height: 110px; resize: vertical; }
    .notice { min-height: 22px; margin-top: 10px; color: var(--accent); }
    .public-tabs { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:10px; margin:26px 0 18px; }
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
    .integration-actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:14px; }
    .appointment-status { display:inline-block; margin:4px 0 8px; padding:4px 8px; border:1px solid var(--border); border-radius:999px; color:var(--accent); font-size:11px; }
    .appointment-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
    .appointment-actions button { padding:7px 10px; font-size:12px; }
    .hours-table, .slots-table { width:100%; border-collapse:collapse; margin-top:12px; }
    .hours-table th, .hours-table td, .slots-table th, .slots-table td { padding:9px 7px; border-bottom:1px solid rgba(255,255,255,.08); text-align:left; }
    .hours-table input[type=\"time\"] { width:100%; min-width:105px; padding:8px; }
    .slots-table .slot-unavailable { color:var(--muted); text-decoration:line-through; opacity:.65; }
    .slots-table .slot-selected { outline:2px solid var(--accent); outline-offset:-2px; border-radius:8px; }
    .slot-select { padding:7px 10px; }
    .table-scroll { overflow-x:auto; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    @media (max-width: 980px) { .cards, .stats, .grid, .chat-layout, .meta-grid { grid-template-columns:1fr; } .case-grid, .steps, .plans { grid-template-columns:repeat(2,minmax(0,1fr)); } }
    @media (max-width: 640px) { .public-tabs, .stats, .cards, .case-grid, .steps, .plans { grid-template-columns:1fr; } .topbar, .company-header { flex-direction:column; align-items:flex-start; } .site-nav { justify-content:flex-start; } .chat-footer { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main class=\"shell\">
    <header class=\"topbar\">
      <div class=\"brand\">Nexora AI<strong>IA Empresarial</strong></div>
      <nav class=\"site-nav\" aria-label=\"Navegación principal\">
        <button class=\"js-scroll-target\" type=\"button\" data-target=\"industries\">Sectores</button>
        <button class=\"js-scroll-target\" type=\"button\" data-target=\"how-it-works\">Cómo funciona</button>
        <button class=\"js-scroll-target\" type=\"button\" data-target=\"pricing\">Planes</button>
        <button class=\"js-scroll-target\" type=\"button\" data-target=\"faq\">Preguntas</button>
        <button class=\"js-scroll-target\" type=\"button\" data-target=\"companyAccessSection\">Ingresar</button>
      </nav>
    </header>

    <section class=\"hero\">
      <div class=\"eyebrow\">Plataforma multiempresa</div>
      <h1>Atiende consultas y organiza tu negocio con IA.</h1>
      <p class=\"subtitle\">Responde consultas con información de tu negocio, recibe solicitudes de citas y organiza conversaciones desde un solo espacio.</p>
      <div class=\"actions\">
        <button class=\"primary-btn js-scroll-target\" type=\"button\" data-target=\"bookingSection\" data-scroll-target=\"demo-chat\">Probar el asistente</button>
        <button class=\"secondary-btn js-scroll-target\" type=\"button\" data-target=\"companyAccessSection\">Registrar empresa</button>
      </div>
      <div class=\"stats\">
        <div class=\"stat\"><strong>Chat IA</strong><span>Respuestas con contexto de tu empresa</span></div>
        <div class=\"stat\"><strong>Citas</strong><span>Solicitudes guardadas en tu panel</span></div>
        <div class=\"stat\"><strong>Clientes</strong><span>Conversaciones organizadas por empresa</span></div>
        <div class=\"stat\"><strong>Control</strong><span>Gestiona tu información y servicios</span></div>
      </div>
    </section>

    <section class=\"section\">
      <h2>Atención y seguimiento en un solo lugar</h2>
      <p>Una solución creada para operar con claridad, atender rápido y convertir más visitas en oportunidades reales.</p>
      <div class=\"cards\">
        <div class=\"card\"><h3>Reservas automáticas</h3><p>Agenda citas y reduce errores con un proceso más claro para cada cliente.</p></div>
        <div class=\"card\"><h3>Chat IA privado</h3><p>Responde con contexto y ayuda cada negocio sin mezclar información entre empresas.</p></div>
        <div class=\"card\"><h3>Clientes mejor atendidos</h3><p>Organiza historial, conversaciones y seguimiento por empresa para ofrecer atención más clara.</p></div>
        <div class=\"card\"><h3>Panel de empresa</h3><p>Gestiona clientes, conversaciones y la información de tu negocio desde tu cuenta.</p></div>
      </div>
    </section>

    <section class=\"section\" id=\"industries\">
      <h2>Una experiencia que se adapta a tu negocio</h2>
      <p>Configura el asistente con la información, servicios y forma de atención de tu empresa.</p>
      <div class=\"case-grid\">
        <article class=\"case-card\"><span class=\"case-tag\">Salud y bienestar</span><h3>Clínicas y estética</h3><p>Resuelve preguntas frecuentes sobre servicios y recibe solicitudes de citas para que el equipo les dé seguimiento.</p></article>
        <article class=\"case-card\"><span class=\"case-tag\">Servicios</span><h3>Profesionales y consultoras</h3><p>Comparte información sobre tus servicios y organiza las consultas de potenciales clientes.</p></article>
        <article class=\"case-card\"><span class=\"case-tag\">Comercio y educación</span><h3>Tiendas y academias</h3><p>Orienta a las personas sobre productos, cursos, horarios y próximos pasos usando la información que agregues.</p></article>
      </div>
    </section>

    <section class=\"section\" id=\"how-it-works\">
      <h2>De la primera pregunta al seguimiento</h2>
      <p>Un flujo sencillo para atender y mantener cada solicitud en contexto.</p>
      <div class=\"steps\">
        <article class=\"step-card\"><span class=\"step-number\">01 · Configura</span><h3>Agrega lo que la IA debe saber</h3><p>Registra la descripción de tu empresa, servicios y respuestas útiles desde tu cuenta.</p></article>
        <article class=\"step-card\"><span class=\"step-number\">02 · Atiende</span><h3>Responde y recibe solicitudes</h3><p>El asistente conversa usando el contexto guardado y los clientes pueden solicitar una cita.</p></article>
        <article class=\"step-card\"><span class=\"step-number\">03 · Da seguimiento</span><h3>Revisa todo desde tu panel</h3><p>Consulta conversaciones, clientes y solicitudes de citas asociadas a tu empresa.</p></article>
      </div>
    </section>

    <section class=\"section\" id=\"pricing\">
      <h2>Planes claros para comenzar</h2>
      <p>Todos incluyen chat web con IA, solicitudes de citas, panel de empresa y conexión con Google Calendar. Elige el volumen mensual de respuestas que necesitas.</p>
      <div class=\"plans\">
        <article class=\"plan-card\"><span class=\"case-tag\">Para empezar</span><h3>Starter</h3><p class=\"plan-price\">$39.900 <small>COP / mes</small></p><p>Hasta 100 respuestas del asistente IA al mes.</p><button class=\"secondary-btn js-plan-target\" type=\"button\" data-plan=\"starter\">Elegir Starter</button></article>
        <article class=\"plan-card featured\"><span class=\"case-tag\">Más elegido</span><h3>Professional</h3><p class=\"plan-price\">$79.900 <small>COP / mes</small></p><p>Hasta 500 respuestas del asistente IA al mes.</p><button class=\"primary-btn js-plan-target\" type=\"button\" data-plan=\"professional\">Elegir Professional</button></article>
        <article class=\"plan-card\"><span class=\"case-tag\">Mayor volumen</span><h3>Enterprise</h3><p class=\"plan-price\">$139.900 <small>COP / mes</small></p><p>Hasta 2.000 respuestas del asistente IA al mes.</p><button class=\"secondary-btn js-plan-target\" type=\"button\" data-plan=\"enterprise\">Elegir Enterprise</button></article>
      </div>
      <p class=\"demo-note\">El límite se renueva al inicio de cada mes y cuenta las respuestas de Nexora IA. Las solicitudes de citas no consumen respuestas. El registro no procesa pagos. WhatsApp todavía no está incluido.</p>
    </section>

    <section class=\"section\" id=\"faq\">
      <h2>Preguntas frecuentes</h2>
      <div class=\"faq-list\">
        <details><summary>¿Cómo aprende el asistente sobre mi negocio?</summary><p>Desde el panel puedes añadir la descripción de tu empresa y una lista de servicios o conocimientos. El asistente usa esa información como contexto para responder.</p></details>
        <details><summary>¿Puedo probar el chat antes de registrarme?</summary><p>Sí. En la sección de prueba escribe el código de una empresa activa para iniciar una conversación con su asistente.</p></details>
        <details><summary>¿Las citas quedan guardadas?</summary><p>Las solicitudes se asocian al código de la empresa y aparecen en su panel para que el equipo les dé seguimiento.</p></details>
        <details><summary>¿Cómo se cuentan las respuestas del plan?</summary><p>Cada respuesta generada por el asistente de Nexora consume una unidad del límite mensual. Los mensajes humanos y las solicitudes de cita no cuentan, y el consumo se reinicia al comienzo de cada mes.</p></details>
        <details><summary>¿Nexora ya se conecta con WhatsApp o Google Calendar?</summary><p>Google Calendar se conecta desde el panel de empresa cuando se configuran las credenciales de Google. La conexión con WhatsApp aún no está disponible.</p></details>
      </div>
    </section>

    <nav class=\"public-tabs\" aria-label=\"Secciones principales\">
      <button class=\"public-tab active\" type=\"button\" data-target=\"bookingSection\">Solicitar cita</button>
      <button class=\"public-tab\" type=\"button\" data-target=\"directorySection\">Buscar empresa</button>
      <button class=\"public-tab\" type=\"button\" data-target=\"companyAccessSection\">Cuenta de empresa</button>
      <button class=\"public-tab\" type=\"button\" data-target=\"adminAccessSection\">Administrador</button>
    </nav>

    <section class=\"panel public-section\" id=\"directorySection\">
      <h2>Encuentra una empresa</h2>
      <p class=\"subtitle\">Explora las empresas activas de Nexora por sector o búscalas por nombre.</p>
      <div class=\"grid\" style=\"margin-top:16px;\">
        <div class=\"field\"><label for=\"directorySector\">Sector</label><select id=\"directorySector\">
          <option value=\"\">Todos los sectores</option>
          <option value=\"gastronomico\">Gastronómico</option>
          <option value=\"estetico\">Estético</option>
          <option value=\"hoteleria\">Hotelería</option>
          <option value=\"turismo\">Turismo</option>
          <option value=\"salud\">Salud</option>
          <option value=\"educacion\">Educación</option>
          <option value=\"comercio\">Comercio y tiendas</option>
          <option value=\"servicios_profesionales\">Servicios profesionales</option>
          <option value=\"mascotas\">Mascotas y veterinaria</option>
          <option value=\"automotriz\">Automotriz</option>
          <option value=\"entretenimiento\">Entretenimiento y eventos</option>
          <option value=\"inmobiliario\">Inmobiliario y construcción</option>
          <option value=\"tecnologia\">Tecnología</option>
          <option value=\"otro\">Otro</option>
        </select></div>
        <div class=\"field\"><label for=\"directorySearch\">Nombre de la empresa</label><input id=\"directorySearch\" type=\"search\" placeholder=\"Ej. Café Central\"></div>
      </div>
      <div id=\"directoryStatus\" class=\"notice\" role=\"status\">Cargando empresas...</div>
      <div id=\"directoryResults\" class=\"directory-grid\" aria-live=\"polite\"></div>
    </section>

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
          <span style=\"padding:7px 10px;border-radius:999px;border:1px solid rgba(89,247,211,0.2);background:rgba(5,17,24,0.8);color:var(--text);font-size:12px;\">2. Envía solicitud</span>
          <span style=\"padding:7px 10px;border-radius:999px;border:1px solid rgba(89,247,211,0.2);background:rgba(5,17,24,0.8);color:var(--text);font-size:12px;\">3. El negocio te contacta</span>
        </div>
        <p id=\"bookingPreviewText\" style=\"margin:0;color:var(--muted);line-height:1.7;\">Envía tu solicitud para que el negocio pueda revisarla y ponerse en contacto contigo.</p>
      </div>

      <div class=\"grid\">
        <div class=\"field\"><label>Código de la empresa</label><input id=\"bookCompany\" type=\"text\"></div>
        <div class=\"field\"><label>Nombre</label><input id=\"bookName\" type=\"text\"></div>
        <div class=\"field\"><label>Teléfono</label><input id=\"bookPhone\" type=\"text\"></div>
        <div class=\"field\"><label>Fecha</label><input id=\"bookDate\" type=\"date\"></div>
        <div class=\"field\" style=\"grid-column:1 / -1;\">
          <label>Horarios disponibles</label>
          <div id=\"availabilityMessage\" class=\"notice\" role=\"status\">Ingresa el código de la empresa y una fecha para consultar sus horarios.</div>
          <div class=\"table-scroll\"><table class=\"slots-table\" aria-label=\"Horarios disponibles\"><thead><tr><th>Hora</th><th>Disponibilidad</th><th></th></tr></thead><tbody id=\"availabilitySlots\"><tr><td colspan=\"3\">Selecciona una empresa y fecha.</td></tr></tbody></table></div>
          <input id=\"bookTime\" type=\"hidden\">
        </div>
        <div class=\"field\" style=\"grid-column:1 / -1;\"><label>Motivo</label><input id=\"bookReason\" type=\"text\"></div>

        <div class=\"booking-chat\" id=\"demo-chat\" style=\"grid-column:1 / -1;scroll-margin-top:20px;\">
          <div class=\"booking-chat-header\">Habla con la empresa</div>
          <div class=\"field\" style=\"padding: 14px 14px 0;\"><label>Código de la empresa destinataria</label><input id=\"chatCompanyCode\" type=\"text\" placeholder=\"Pide el código a la empresa\"></div>
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
        <div id=\"signupForm\" class=\"field\"><label>Código único</label><input id=\"signupId\" type=\"text\"></div>
        <div class=\"field\"><label>Nombre de la empresa</label><input id=\"signupName\" type=\"text\"></div>
        <div class=\"field\"><label for=\"signupSector\">Sector</label><select id=\"signupSector\" required>
          <option value=\"\" selected disabled>Selecciona el sector de tu empresa</option>
          <option value=\"gastronomico\">Gastronómico</option>
          <option value=\"estetico\">Estético</option>
          <option value=\"hoteleria\">Hotelería</option>
          <option value=\"turismo\">Turismo</option>
          <option value=\"salud\">Salud</option>
          <option value=\"educacion\">Educación</option>
          <option value=\"comercio\">Comercio y tiendas</option>
          <option value=\"servicios_profesionales\">Servicios profesionales</option>
          <option value=\"mascotas\">Mascotas y veterinaria</option>
          <option value=\"automotriz\">Automotriz</option>
          <option value=\"entretenimiento\">Entretenimiento y eventos</option>
          <option value=\"inmobiliario\">Inmobiliario y construcción</option>
          <option value=\"tecnologia\">Tecnología</option>
          <option value=\"otro\">Otro</option>
        </select></div>
        <div class=\"field\"><label>Plan</label><select id=\"signupPlan\"><option value=\"starter\">Starter · $39.900 COP / mes · 100 respuestas IA</option><option value=\"professional\">Professional · $79.900 COP / mes · 500 respuestas IA</option><option value=\"enterprise\">Enterprise · $139.900 COP / mes · 2.000 respuestas IA</option></select></div>
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
      <div class=\"mini-panel\" style=\"margin-bottom:18px;\">
        <h3>Integración con Google Calendar</h3>
        <p id=\"calendarStatusText\" role=\"status\">Consultando estado de conexión...</p>
        <div class=\"integration-actions\">
          <button id=\"calendarConnectBtn\" class=\"primary-btn\" type=\"button\">Conectar Google Calendar</button>
          <button id=\"calendarDisconnectBtn\" class=\"secondary-btn\" type=\"button\" hidden>Desconectar calendario</button>
        </div>
      </div>
      <p class=\"notice\" id=\"aiUsageStatus\" role=\"status\"></p>
      <div class=\"mini-panel\" style=\"margin-bottom:18px;\">
        <h3>Horarios de atención y reservas</h3>
        <p>Configura los días y horas en que aceptas solicitudes. El horario inicial es de lunes a viernes, de 9:00 a. m. a 5:00 p. m.</p>
        <div class=\"table-scroll\">
          <table class=\"hours-table\" aria-label=\"Horario semanal de atención\">
            <thead><tr><th>Día</th><th>Abierto</th><th>Apertura</th><th>Cierre</th></tr></thead>
            <tbody id=\"weeklyHoursRows\">
              <tr data-day=\"monday\"><td>Lunes</td><td><input type=\"checkbox\" aria-label=\"Abrir lunes\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura lunes\"></td><td><input type=\"time\" value=\"17:00\" aria-label=\"Cierre lunes\"></td></tr>
              <tr data-day=\"tuesday\"><td>Martes</td><td><input type=\"checkbox\" aria-label=\"Abrir martes\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura martes\"></td><td><input type=\"time\" value=\"17:00\" aria-label=\"Cierre martes\"></td></tr>
              <tr data-day=\"wednesday\"><td>Miércoles</td><td><input type=\"checkbox\" aria-label=\"Abrir miércoles\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura miércoles\"></td><td><input type=\"time\" value=\"17:00\" aria-label=\"Cierre miércoles\"></td></tr>
              <tr data-day=\"thursday\"><td>Jueves</td><td><input type=\"checkbox\" aria-label=\"Abrir jueves\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura jueves\"></td><td><input type=\"time\" value=\"17:00\" aria-label=\"Cierre jueves\"></td></tr>
              <tr data-day=\"friday\"><td>Viernes</td><td><input type=\"checkbox\" aria-label=\"Abrir viernes\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura viernes\"></td><td><input type=\"time\" value=\"17:00\" aria-label=\"Cierre viernes\"></td></tr>
              <tr data-day=\"saturday\"><td>Sábado</td><td><input type=\"checkbox\" aria-label=\"Abrir sábado\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura sábado\"></td><td><input type=\"time\" value=\"13:00\" aria-label=\"Cierre sábado\"></td></tr>
              <tr data-day=\"sunday\"><td>Domingo</td><td><input type=\"checkbox\" aria-label=\"Abrir domingo\"></td><td><input type=\"time\" value=\"09:00\" aria-label=\"Apertura domingo\"></td><td><input type=\"time\" value=\"13:00\" aria-label=\"Cierre domingo\"></td></tr>
            </tbody>
          </table>
        </div>
        <div class=\"field\" style=\"margin-top:14px;\"><label for=\"appointmentDuration\">Duración de cada cita</label><select id=\"appointmentDuration\"><option value=\"15\">15 minutos</option><option value=\"30\">30 minutos</option><option value=\"45\">45 minutos</option><option value=\"60\">60 minutos</option><option value=\"90\">90 minutos</option><option value=\"120\">120 minutos</option></select></div>
        <button id=\"hoursSave\" class=\"primary-btn\" type=\"button\" style=\"margin-top:14px;\">Guardar horarios</button>
        <div id=\"hoursStatus\" class=\"notice\" role=\"status\"></div>
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
        <div class=\"mini-panel\"><h3>Solicitudes de cita</h3><p id=\"appointmentActionStatus\" class=\"notice\" role=\"status\"></p><div id=\"appointmentList\" class=\"list\"></div></div>
      </div>
    </section>
  </main>

  <script>
    let companyToken = '';
    let adminKey = '';
    let currentAvailabilitySlots = [];

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
      if (preview) preview.textContent = `${name} puede enviar una solicitud de cita para ${reason}. El negocio podrá revisar la solicitud y ponerse en contacto usando ${phone}.`;
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

    function renderAppointments(items) {
      const container = document.getElementById('appointmentList');
      if (!container) return;
      container.replaceChildren();
      if (!items.length) {
        const empty = document.createElement('div');
        empty.className = 'list-item';
        empty.textContent = 'Sin solicitudes de cita.';
        container.appendChild(empty);
        return;
      }
      const labels = { pending: 'Pendiente', confirmed: 'Confirmada', cancelled: 'Cancelada' };
      items.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'list-item';
        const title = document.createElement('strong');
        title.textContent = item.client_name || 'Cita';
        const date = document.createElement('div');
        const parsedDate = new Date(item.starts_at);
        date.textContent = Number.isNaN(parsedDate.getTime()) ? item.starts_at : parsedDate.toLocaleString();
        const reason = document.createElement('div');
        reason.textContent = item.reason || 'Sin motivo indicado';
        const status = document.createElement('span');
        status.className = 'appointment-status';
        status.textContent = labels[item.status] || 'Pendiente';
        row.append(title, date, reason, status);
        if (item.calendar_event_link && item.status === 'confirmed') {
          const eventLink = document.createElement('a');
          eventLink.href = item.calendar_event_link;
          eventLink.target = '_blank';
          eventLink.rel = 'noopener noreferrer';
          eventLink.textContent = 'Abrir en Google Calendar';
          row.appendChild(eventLink);
        }
        if (item.status === 'pending' || item.status === 'confirmed') {
          const actions = document.createElement('div');
          actions.className = 'appointment-actions';
          if (item.status === 'pending') {
            const confirm = document.createElement('button');
            confirm.type = 'button';
            confirm.className = 'primary-btn';
            confirm.dataset.appointmentStatus = `${item.id}|confirmed`;
            confirm.textContent = 'Confirmar y agregar al calendario';
            actions.appendChild(confirm);
          }
          const cancel = document.createElement('button');
          cancel.type = 'button';
          cancel.className = 'secondary-btn';
          cancel.dataset.appointmentStatus = `${item.id}|cancelled`;
          cancel.textContent = 'Cancelar solicitud';
          actions.appendChild(cancel);
          row.appendChild(actions);
        }
        container.appendChild(row);
      });
    }

    async function loadCalendarStatus() {
      const status = document.getElementById('calendarStatusText');
      const connect = document.getElementById('calendarConnectBtn');
      const disconnect = document.getElementById('calendarDisconnectBtn');
      try {
        const response = await fetch('/my-calendar', {
          headers: { Authorization: 'Bearer ' + companyToken }
        });
        const data = await response.json();
        if (!response.ok) {
          status.textContent = errorMessage(data, 'No se pudo consultar Google Calendar.');
          connect.disabled = true;
          return;
        }
        connect.disabled = !data.configured;
        disconnect.hidden = !data.connected;
        if (data.connected) {
          status.textContent = data.account_email
            ? `Conectado a ${data.account_email}.`
            : 'Google Calendar está conectado.';
        } else if (data.configured) {
          status.textContent = 'Conecta tu calendario para crear eventos al confirmar solicitudes.';
        } else {
          status.textContent = 'Falta configurar Google OAuth y la clave de cifrado en el servidor.';
        }
      } catch {
        status.textContent = 'No fue posible consultar el estado de Google Calendar.';
        connect.disabled = true;
      }
    }

    async function loadDashboard() {
      const headers = { Authorization: 'Bearer ' + companyToken };
      const [clientsRes, appointmentsRes, chatRes, infoRes] = await Promise.all([
        fetch('/my-clients', { headers }),
        fetch('/my-appointments', { headers }),
        fetch('/my-chat', { headers }),
        fetch('/my-knowledge', { headers })
      ]);
      await loadCalendarStatus();
      if (clientsRes.ok) {
        const clients = await clientsRes.json();
        renderList('clientList', clients, (item) => `<div class="list-item"><strong>${item.name || 'Cliente'}</strong>${item.phone || 'Sin teléfono'}</div>`);
      }
      if (appointmentsRes.ok) {
        const appointments = await appointmentsRes.json();
        renderAppointments(appointments);
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
        setWeeklyHours(info.weekly_hours || {});
        document.getElementById('appointmentDuration').value = String(info.appointment_duration_minutes || 60);
        document.getElementById('aiUsageStatus').textContent =
          `Respuestas IA este mes: ${info.ai_replies_used} de ${info.ai_replies_limit}.`;
      }
    }

    function setWeeklyHours(schedule) {
      document.querySelectorAll('#weeklyHoursRows tr').forEach((row) => {
        const hours = schedule[row.dataset.day];
        const checkbox = row.querySelector('input[type="checkbox"]');
        const fields = row.querySelectorAll('input[type="time"]');
        checkbox.checked = Boolean(hours);
        if (hours) {
          fields[0].value = hours.open;
          fields[1].value = hours.close;
        }
        fields.forEach((field) => { field.disabled = !checkbox.checked; });
      });
    }

    function readWeeklyHours() {
      const schedule = {};
      let valid = true;
      document.querySelectorAll('#weeklyHoursRows tr').forEach((row) => {
        const checkbox = row.querySelector('input[type="checkbox"]');
        const fields = row.querySelectorAll('input[type="time"]');
        if (!checkbox.checked) {
          schedule[row.dataset.day] = null;
        } else if (!fields[0].value || !fields[1].value || fields[0].value >= fields[1].value) {
          valid = false;
        } else {
          schedule[row.dataset.day] = { open: fields[0].value, close: fields[1].value };
        }
      });
      if (!Object.values(schedule).some(Boolean)) valid = false;
      return { schedule, valid };
    }

    async function saveWeeklyHours() {
      const { schedule, valid } = readWeeklyHours();
      const status = document.getElementById('hoursStatus');
      if (!valid) {
        status.textContent = 'Activa al menos un día y verifica que el cierre sea posterior a la apertura.';
        return;
      }
      const response = await fetch('/my-knowledge', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + companyToken },
        body: JSON.stringify({
          weekly_hours: schedule,
          appointment_duration_minutes: Number(document.getElementById('appointmentDuration').value)
        })
      });
      const data = await response.json();
      status.textContent = response.ok ? 'Horarios guardados.' : errorMessage(data, 'No se pudieron guardar los horarios.');
    }

    function renderAvailability(slots) {
      currentAvailabilitySlots = slots;
      const body = document.getElementById('availabilitySlots');
      const selected = document.getElementById('bookTime').value;
      body.replaceChildren();
      if (!slots.length) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 3;
        cell.textContent = 'No hay horarios disponibles para esta fecha.';
        return;
      }
      slots.forEach((slot) => {
        const row = body.insertRow();
        const timeCell = row.insertCell();
        timeCell.textContent = slot.starts_at.slice(11, 16);
        const stateCell = row.insertCell();
        const actionCell = row.insertCell();
        if (slot.available) {
          stateCell.textContent = 'Libre';
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'secondary-btn slot-select';
          button.dataset.slotTime = slot.starts_at;
          button.textContent = selected === slot.starts_at ? 'Seleccionada' : 'Elegir';
          if (selected === slot.starts_at) row.classList.add('slot-selected');
          actionCell.appendChild(button);
        } else {
          row.classList.add('slot-unavailable');
          stateCell.textContent = 'Ocupada';
          const crossed = document.createElement('del');
          crossed.textContent = 'No disponible';
          actionCell.appendChild(crossed);
        }
      });
    }

    async function loadAvailability() {
      const companyId = document.getElementById('bookCompany').value.trim();
      const bookingDate = document.getElementById('bookDate').value;
      const status = document.getElementById('availabilityMessage');
      document.getElementById('bookTime').value = '';
      if (!companyId || !bookingDate) {
        status.textContent = 'Ingresa el código de la empresa y una fecha para consultar sus horarios.';
        renderAvailability([]);
        return;
      }
      status.textContent = 'Consultando horarios...';
      const response = await fetch(`/companies/${encodeURIComponent(companyId)}/availability?date=${encodeURIComponent(bookingDate)}`);
      const data = await response.json();
      if (!response.ok) {
        status.textContent = errorMessage(data, 'No se pudieron consultar los horarios.');
        renderAvailability([]);
        return;
      }
      status.textContent = `Citas de ${data.duration_minutes} minutos. Selecciona un horario libre.`;
      renderAvailability(data.slots);
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

    async function loadCompanyDirectory() {
      const status = document.getElementById('directoryStatus');
      const results = document.getElementById('directoryResults');
      const params = new URLSearchParams();
      const sector = document.getElementById('directorySector').value;
      const search = document.getElementById('directorySearch').value.trim();
      if (sector) params.set('sector', sector);
      if (search) params.set('q', search);
      status.textContent = 'Buscando empresas...';
      try {
        const response = await fetch('/companies?' + params.toString());
        const data = await response.json();
        if (!response.ok) {
          status.textContent = errorMessage(data, 'No se pudieron cargar las empresas.');
          results.replaceChildren();
          return;
        }
        results.replaceChildren();
        if (!data.length) {
          status.textContent = 'No encontramos empresas activas con esos filtros.';
          return;
        }
        status.textContent = `${data.length} empresa${data.length === 1 ? '' : 's'} encontrada${data.length === 1 ? '' : 's'}.`;
        data.forEach((company) => {
          const card = document.createElement('article');
          card.className = 'directory-card';
          const sectorTag = document.createElement('span');
          sectorTag.className = 'case-tag';
          sectorTag.textContent = company.sector_label;
          const title = document.createElement('h3');
          title.textContent = company.name;
          const description = document.createElement('p');
          description.textContent = company.description || 'Esta empresa aún no ha agregado una descripción.';
          const select = document.createElement('button');
          select.type = 'button';
          select.className = 'primary-btn';
          select.dataset.directoryCompany = company.company_id;
          select.textContent = 'Elegir esta empresa';
          card.append(sectorTag, title, description, select);
          results.appendChild(card);
        });
      } catch {
        status.textContent = 'No fue posible conectarse para buscar empresas.';
        results.replaceChildren();
      }
    }

    async function companySignup() {
      const companyId = document.getElementById('signupId').value.trim();
      const companyName = document.getElementById('signupName').value.trim();
      const sector = document.getElementById('signupSector').value;
      const email = document.getElementById('signupEmail').value.trim();
      const password = document.getElementById('signupPassword').value;
      if (companyId.length < 3 || companyName.length < 2 || !sector || !email.includes('@') || password.length < 6) {
        document.getElementById('signupMsg').textContent = 'Completa código, nombre, sector y correo válidos. La contraseña debe tener al menos 6 caracteres.';
        return;
      }
      const payload = {
        company_id: companyId,
        name: companyName,
        sector,
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

    async function connectGoogleCalendar() {
      const popup = window.open('about:blank', 'nexora-google-calendar', 'popup,width=560,height=720');
      const status = document.getElementById('calendarStatusText');
      if (!popup) {
        status.textContent = 'Permite las ventanas emergentes para conectar Google Calendar.';
        return;
      }
      try {
        const response = await fetch('/my-calendar/connect', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + companyToken }
        });
        const data = await response.json();
        if (!response.ok) {
          popup.close();
          status.textContent = errorMessage(data, 'No fue posible iniciar la conexión con Google.');
          return;
        }
        popup.location = data.authorization_url;
        status.textContent = 'Completa la autorización de Google en la ventana emergente.';
      } catch {
        popup.close();
        status.textContent = 'No fue posible iniciar la conexión con Google Calendar.';
      }
    }

    async function disconnectGoogleCalendar() {
      const status = document.getElementById('calendarStatusText');
      try {
        const response = await fetch('/my-calendar', {
          method: 'DELETE',
          headers: { Authorization: 'Bearer ' + companyToken }
        });
        const data = await response.json();
        status.textContent = response.ok
          ? 'Google Calendar se desconectó. Los eventos creados previamente no se eliminan.'
          : errorMessage(data, 'No se pudo desconectar Google Calendar.');
        if (response.ok) await loadCalendarStatus();
      } catch {
        status.textContent = 'No fue posible desconectar Google Calendar.';
      }
    }

    async function updateAppointmentStatus(appointmentId, nextStatus) {
      const notice = document.getElementById('appointmentActionStatus');
      try {
        const response = await fetch(`/my-appointments/${encodeURIComponent(appointmentId)}/status`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + companyToken
          },
          body: JSON.stringify({ status: nextStatus })
        });
        const data = await response.json();
        notice.textContent = response.ok
          ? nextStatus === 'confirmed'
            ? 'Cita confirmada y agregada a Google Calendar.'
            : 'Solicitud cancelada.'
          : errorMessage(data, 'No se pudo actualizar la solicitud.');
        if (response.ok) await loadDashboard();
      } catch {
        notice.textContent = 'No fue posible actualizar la solicitud de cita.';
      }
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
      const startsAt = document.getElementById('bookTime').value;
      if (!companyId || !clientName || !startsAt) {
        document.getElementById('bookMsg').textContent = 'Completa tus datos y selecciona un horario disponible de la tabla.';
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
      document.getElementById('bookMsg').textContent = response.ok ? 'Solicitud enviada. La empresa revisará y confirmará la cita.' : errorMessage(data, 'No se pudo registrar la cita.');
      if (response.ok) await loadAvailability();
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
      const directoryCompanyId = target.dataset.directoryCompany;
      if (directoryCompanyId) {
        document.getElementById('bookCompany').value = directoryCompanyId;
        document.getElementById('chatCompanyCode').value = directoryCompanyId;
        document.getElementById('bookMsg').textContent = 'Empresa seleccionada. Ya puedes consultar horarios, reservar o escribir por el chat.';
        await loadPublicCompanyProfile(directoryCompanyId);
        showSection('bookingSection');
        document.getElementById('bookingSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
        await loadAvailability();
        return;
      }
      const selectedSlot = target.dataset.slotTime;
      if (selectedSlot) {
        document.getElementById('bookTime').value = selectedSlot;
        renderAvailability(currentAvailabilitySlots);
        return;
      }
      const appointmentAction = target.dataset.appointmentStatus;
      if (appointmentAction) {
        const [appointmentId, nextStatus] = appointmentAction.split('|');
        if (appointmentId && nextStatus) await updateAppointmentStatus(appointmentId, nextStatus);
        return;
      }
      const targetSection = target.dataset.target;
      if (targetSection) {
        if (target.classList.contains('public-tab')) {
          showSection(targetSection);
          return;
        }
        if (target.classList.contains('js-scroll-target')) {
          showSection(targetSection);
          const el = document.getElementById(target.dataset.scrollTarget || targetSection);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
          return;
        }
      }
      if (target.dataset.plan) {
        document.getElementById('signupPlan').value = target.dataset.plan;
        showSection('companyAccessSection');
        document.getElementById('signupForm').scrollIntoView({ behavior: 'smooth', block: 'center' });
        return;
      }
      const action = target.getAttribute('data-status-action');
      if (action) {
        const [companyId, status] = action.split('|');
        if (companyId && status) await toggleStatus(companyId, status);
      }
    });

    window.addEventListener('message', async (event) => {
      if (event.origin !== window.location.origin || event.data?.type !== 'nexora-calendar-connect') return;
      const status = document.getElementById('calendarStatusText');
      status.textContent = event.data.message || 'Respuesta recibida de Google Calendar.';
      if (event.data.connected) await loadDashboard();
    });

    document.getElementById('loginSubmit').onclick = companyLogin;
    document.getElementById('signupSubmit').onclick = companySignup;
    document.getElementById('adminSubmit').onclick = adminLogin;
    document.getElementById('bookSubmit').onclick = bookAppointment;
    document.getElementById('calendarConnectBtn').onclick = connectGoogleCalendar;
    document.getElementById('calendarDisconnectBtn').onclick = disconnectGoogleCalendar;
    document.getElementById('publicChatSend').onclick = sendPublicChat;
    document.getElementById('chatSend').onclick = sendManualReply;
    document.getElementById('infoSave').onclick = saveCompanyInfo;
    document.getElementById('hoursSave').onclick = saveWeeklyHours;
    document.getElementById('logoutCompanyBtn').onclick = logoutCompany;
    document.getElementById('directorySector').addEventListener('change', loadCompanyDirectory);
    document.getElementById('directorySearch').addEventListener('input', loadCompanyDirectory);
    document.querySelectorAll('.public-tab').forEach((tab) => tab.addEventListener('click', () => showSection(tab.dataset.target)));
    document.querySelectorAll('.js-scroll-target').forEach((node) => node.addEventListener('click', () => showSection(node.dataset.target)));
    ['bookName', 'bookPhone', 'bookReason'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', updatePreview);
    });
    const companyCodeInput = document.getElementById('bookCompany');
    if (companyCodeInput) companyCodeInput.addEventListener('input', () => loadPublicCompanyProfile(companyCodeInput.value.trim()));
    if (companyCodeInput) companyCodeInput.addEventListener('change', loadAvailability);
    document.getElementById('bookDate').addEventListener('change', loadAvailability);
    const today = new Date();
    document.getElementById('bookDate').min = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    document.querySelectorAll('#weeklyHoursRows input[type="checkbox"]').forEach((checkbox) => {
      checkbox.addEventListener('change', () => {
        checkbox.closest('tr').querySelectorAll('input[type="time"]').forEach((field) => {
          field.disabled = !checkbox.checked;
        });
      });
    });
    const publicChatCodeInput = document.getElementById('chatCompanyCode');
    if (publicChatCodeInput) publicChatCodeInput.addEventListener('input', () => loadPublicCompanyProfile(publicChatCodeInput.value.trim()));
    loadCompanyDirectory();
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
            "INSERT INTO companies (company_id, name, sector, email, password_hash, plan_id, description, about, profile_photo_url, status, weekly_hours) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)",
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
                json.dumps(DEFAULT_WEEKLY_HOURS),
            ),
        )
        conn.commit()
        conn.close()
    amount = PLAN_PRICES_COP[payload.plan_id]
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
        "weekly_hours": company_weekly_hours(company),
        "appointment_duration_minutes": int(company.get("appointment_duration_minutes") or 60),
        "plan": company["plan_id"],
        **company_ai_usage(company),
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
    weekly_hours = (
        validate_weekly_hours(payload.weekly_hours)
        if payload.weekly_hours is not None
        else company_weekly_hours(dict(row))
    )
    appointment_duration = (
        payload.appointment_duration_minutes
        if payload.appointment_duration_minutes is not None
        else int(row["appointment_duration_minutes"] or 60)
    )
    conn.execute(
        """
        UPDATE companies SET about = ?, description = ?, profile_photo_url = ?, knowledge = ?,
            weekly_hours = ?, appointment_duration_minutes = ? WHERE company_id = ?
        """,
        (
            payload.about if payload.about is not None else row["about"],
            payload.description if payload.description is not None else row["description"],
            payload.profile_photo_url if payload.profile_photo_url is not None else row["profile_photo_url"],
            json.dumps(knowledge),
            json.dumps(weekly_hours),
            appointment_duration,
            company_id,
        ),
    )
    conn.commit(); conn.close()
    return {
        "updated": True,
        "weekly_hours": weekly_hours,
        "appointment_duration_minutes": appointment_duration,
    }


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
    rows = conn.execute(
        """
        SELECT id, client_name, phone, reason, starts_at, duration_minutes, status, calendar_event_link
        FROM appointments WHERE company_id = ? ORDER BY starts_at DESC
        """,
        (company_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/my-calendar")
def my_calendar(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    row = conn.execute(
        "SELECT account_email FROM calendar_connections WHERE company_id = ?",
        (company_id,),
    ).fetchone()
    conn.close()
    return {
        "configured": calendar_configuration_ready(),
        "connected": row is not None,
        "account_email": row["account_email"] if row else "",
    }


@app.post("/my-calendar/connect")
def start_calendar_connection(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    client_id, _, redirect_uri = google_oauth_config()
    calendar_fernet()
    state = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute("DELETE FROM calendar_oauth_states WHERE created_at < datetime('now', '-15 minutes')")
    conn.execute(
        "INSERT INTO calendar_oauth_states (state_hash, company_id, session_token_hash) VALUES (?, ?, ?)",
        (
            hashlib.sha256(state.encode("ascii")).hexdigest(),
            company_id,
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
        ),
    )
    conn.commit()
    conn.close()
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/calendar.events",
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
    )
    return {"authorization_url": f"https://accounts.google.com/o/oauth2/v2/auth?{query}"}


@app.get("/calendar/callback", response_class=HTMLResponse)
def calendar_callback(
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    if not state:
        return calendar_popup_response(False, "Falta el estado de seguridad de Google. Vuelve a intentarlo.")
    state_hash = hashlib.sha256(state.encode("utf-8")).hexdigest()
    conn = get_db()
    oauth_state = conn.execute(
        """
        SELECT company_id, session_token_hash FROM calendar_oauth_states
        WHERE state_hash = ? AND created_at >= datetime('now', '-15 minutes')
        """,
        (state_hash,),
    ).fetchone()
    conn.execute("DELETE FROM calendar_oauth_states WHERE state_hash = ?", (state_hash,))
    conn.commit()
    if not oauth_state:
        conn.close()
        return calendar_popup_response(False, "La autorización venció o ya fue utilizada. Inténtalo otra vez.")
    sessions = conn.execute(
        "SELECT token FROM sessions WHERE company_id = ?",
        (oauth_state["company_id"],),
    ).fetchall()
    company = conn.execute(
        "SELECT status FROM companies WHERE company_id = ?",
        (oauth_state["company_id"],),
    ).fetchone()
    conn.close()
    valid_session = any(
        hmac.compare_digest(
            hashlib.sha256(row["token"].encode("utf-8")).hexdigest(),
            oauth_state["session_token_hash"],
        )
        for row in sessions
    )
    if not valid_session or not company or company["status"] != "active":
        return calendar_popup_response(False, "Tu sesión ya no está activa. Inicia sesión e inténtalo otra vez.")
    if error or not code:
        return calendar_popup_response(False, "No se autorizó Google Calendar. Puedes volver a intentarlo.")
    try:
        _, _, redirect_uri = google_oauth_config()
        tokens = google_token_request(
            {
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            }
        )
        if not isinstance(tokens.get("refresh_token"), str) or not tokens["refresh_token"]:
            return calendar_popup_response(False, "Google no entregó permiso de renovación. Vuelve a autorizar y acepta el acceso sin conexión.")
        expiration = int(dt.datetime.now(dt.timezone.utc).timestamp()) + int(tokens.get("expires_in", 3600))
        save_calendar_tokens(oauth_state["company_id"], tokens, expiration)
    except HTTPException as exc:
        return calendar_popup_response(False, str(exc.detail))
    return calendar_popup_response(True, "Google Calendar quedó conectado a Nexora.")


@app.delete("/my-calendar")
def disconnect_calendar(authorization: Annotated[str | None, Header()] = None) -> dict[str, bool]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    conn = get_db()
    conn.execute("DELETE FROM calendar_connections WHERE company_id = ?", (company_id,))
    conn.commit()
    conn.close()
    return {"disconnected": True}


@app.post("/my-appointments/{appointment_id}/status")
def update_appointment_status(
    appointment_id: int,
    payload: AppointmentStatusUpdate,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ") if authorization else None
    company_id = company_from_token(token)
    with database_lock:
        conn = get_db()
        appointment_row = conn.execute(
            "SELECT * FROM appointments WHERE id = ? AND company_id = ?",
            (appointment_id, company_id),
        ).fetchone()
        if not appointment_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Solicitud de cita no encontrada.")
        appointment = dict(appointment_row)
        if appointment["status"] == payload.status:
            conn.close()
            return {
                "id": appointment_id,
                "status": appointment["status"],
                "calendar_event_link": appointment["calendar_event_link"],
            }
        if appointment["status"] == "cancelled":
            conn.close()
            raise HTTPException(status_code=409, detail="Una solicitud cancelada no se puede reactivar.")
        if payload.status == "confirmed":
            conn.close()
            event = create_calendar_event(company_id, appointment)
            conn = get_db()
            conn.execute(
                """
                UPDATE appointments SET status = 'confirmed', calendar_event_id = ?,
                    calendar_event_link = ? WHERE id = ? AND company_id = ?
                """,
                (event["id"], event["link"], appointment_id, company_id),
            )
        else:
            conn.close()
            if appointment["status"] == "confirmed" and appointment["calendar_event_id"]:
                google_calendar_request(
                    company_id,
                    "DELETE",
                    f"calendars/primary/events/{quote(appointment['calendar_event_id'], safe='')}",
                    ignore_missing=True,
                )
            conn = get_db()
            conn.execute(
                "UPDATE appointments SET status = 'cancelled' WHERE id = ? AND company_id = ?",
                (appointment_id, company_id),
            )
        conn.commit()
        conn.close()
    return {
        "id": appointment_id,
        "status": payload.status,
        "calendar_event_link": event["link"] if payload.status == "confirmed" else "",
    }


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
    if company["status"] != "active":
        raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    starts_at = local_datetime(payload.starts_at)
    if starts_at.second or starts_at.microsecond:
        raise HTTPException(status_code=400, detail="Selecciona una hora exacta de la tabla de disponibilidad.")
    normalized_start = starts_at.isoformat(timespec="minutes")
    with database_lock:
        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            current_company_row = conn.execute(
                "SELECT * FROM companies WHERE company_id = ?", (company_id,)
            ).fetchone()
            if not current_company_row:
                raise HTTPException(status_code=404, detail="Empresa no encontrada.")
            current_company = dict(current_company_row)
            if current_company["status"] != "active":
                raise HTTPException(status_code=403, detail="La empresa está desactivada.")
            slots = available_slots(current_company, starts_at.date(), conn)
            if not any(slot["starts_at"] == normalized_start and slot["available"] for slot in slots):
                raise HTTPException(
                    status_code=409,
                    detail="Ese horario ya no está disponible. Selecciona otro horario libre.",
                )
            duration = int(current_company.get("appointment_duration_minutes") or 60)
            cursor = conn.execute(
                """
                INSERT INTO appointments
                    (company_id, client_name, phone, reason, starts_at, duration_minutes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (company_id, payload.client_name, payload.phone, payload.reason, normalized_start, duration),
            )
            conn.execute(
                "INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'client', ?)",
                (company_id, payload.client_name, f"Solicitud de cita: {payload.reason} para {normalized_start}"),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    return {"status": "ok", "company_id": company_id, "appointment_id": cursor.lastrowid}


@app.post("/assistant")
def assistant(payload: MessageRequest, x_company_id: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    company_id = x_company_id
    if not company_id:
        raise HTTPException(status_code=400, detail="Falta el código de la empresa.")
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    if company["status"] != "active":
      raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    reply_limit = plan_ai_reply_limit(company["plan_id"])
    if monthly_ai_reply_count(company_id) >= reply_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Este plan llegó a sus {reply_limit} respuestas IA del mes. El límite se renueva el próximo mes; contacta a Nexora si necesitas cambiar de plan.",
        )
    reply = generate_ai_reply(company, payload.message)
    with database_lock:
        conn = get_db()
        conn.execute("BEGIN IMMEDIATE")
        used = conn.execute(
            """
            SELECT COUNT(*) AS reply_count FROM conversations
            WHERE company_id = ? AND role = 'ai'
              AND created_at >= strftime('%Y-%m-01 00:00:00', 'now')
            """,
            (company_id,),
        ).fetchone()["reply_count"]
        if used >= reply_limit:
            conn.rollback()
            conn.close()
            raise HTTPException(
                status_code=429,
                detail=f"Este plan llegó a sus {reply_limit} respuestas IA del mes. El límite se renueva el próximo mes; contacta a Nexora si necesitas cambiar de plan.",
            )
        conn.execute(
            "INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'client', ?)",
            (company_id, "cliente", payload.message),
        )
        conn.execute(
            "INSERT INTO conversations (company_id, sender, role, message) VALUES (?, ?, 'ai', ?)",
            (company_id, "ia", reply),
        )
        conn.commit()
        conn.close()
    return {
        "reply": reply,
        "company": company["name"],
        "ai_replies_used": used + 1,
        "ai_replies_limit": reply_limit,
    }


@app.get("/companies/{company_id}/public")
def public_company(company_id: str) -> dict[str, Any]:
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    if company["status"] == "disabled":
        raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    return public_company_payload(company)


@app.get("/companies")
def public_companies(sector: str | None = None, q: str = "") -> list[dict[str, Any]]:
    if sector and sector not in COMPANY_SECTORS:
        raise HTTPException(status_code=422, detail="El sector seleccionado no es válido.")
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT company_id, name, sector, description, about, profile_photo_url FROM companies WHERE status = 'active' ORDER BY name COLLATE NOCASE"
        ).fetchall()
    finally:
        conn.close()
    search = q.strip().casefold()
    companies: list[dict[str, Any]] = []
    for row in rows:
        company = dict(row)
        listing = public_company_listing(company)
        if sector and listing["sector"] != sector:
            continue
        if search and search not in listing["name"].casefold():
            continue
        companies.append(listing)
    return companies


@app.get("/companies/{company_id}/availability", response_model=AvailabilityResponse)
def company_availability(company_id: str, date: str) -> dict[str, Any]:
    company = company_record(company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Empresa no encontrada.")
    if company["status"] != "active":
        raise HTTPException(status_code=403, detail="La empresa está desactivada.")
    try:
        booking_date = dt.date.fromisoformat(date)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="La fecha debe tener formato AAAA-MM-DD.") from exc
    conn = get_db()
    try:
        slots = available_slots(company, booking_date, conn)
    finally:
        conn.close()
    return {
        "date": booking_date.isoformat(),
        "duration_minutes": int(company.get("appointment_duration_minutes") or 60),
        "slots": slots,
    }


@app.get("/admin")
def admin_root() -> dict[str, str]:
    return {"status": "ok", "email": ADMIN_EMAIL}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hola:app", host="0.0.0.0", port=8000, reload=False)
