import os
import sqlite3
import tempfile
import unittest
import datetime as dt
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet

_import_db = tempfile.TemporaryDirectory()
_previous_db = os.environ.pop("VIRTUAL_EMPLOYEE_DATABASE", None)
_previous_nexora_db = os.environ.get("NEXORA_DB_PATH")
os.environ["NEXORA_DB_PATH"] = str(Path(_import_db.name) / "import.db")
import hola
if _previous_db is not None:
    os.environ["VIRTUAL_EMPLOYEE_DATABASE"] = _previous_db
else:
    os.environ.pop("VIRTUAL_EMPLOYEE_DATABASE", None)
if _previous_nexora_db is None:
    os.environ.pop("NEXORA_DB_PATH", None)
else:
    os.environ["NEXORA_DB_PATH"] = _previous_nexora_db


class CalendarIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        hola.DB_PATH = str(Path(self.temp_dir.name) / "test.db")
        hola.initialize_db()
        self.previous_env = {
            name: os.environ.get(name)
            for name in (
                "GOOGLE_CLIENT_ID",
                "GOOGLE_CLIENT_SECRET",
                "GOOGLE_REDIRECT_URI",
                "NEXORA_TOKEN_ENCRYPTION_KEY",
            )
        }
        os.environ["GOOGLE_CLIENT_ID"] = "test-client"
        os.environ["GOOGLE_CLIENT_SECRET"] = "test-secret"
        os.environ["GOOGLE_REDIRECT_URI"] = "http://localhost:8000/calendar/callback"
        os.environ["NEXORA_TOKEN_ENCRYPTION_KEY"] = Fernet.generate_key().decode("ascii")
        conn = hola.get_db()
        conn.execute(
            """
            INSERT INTO companies (company_id, name, email, password_hash, status, paid_through)
            VALUES ('empresa-uno', 'Empresa Uno', 'uno@example.com', 'test-hash', 'active', ?)
            """,
            ((hola.bogota_today() + dt.timedelta(days=60)).isoformat(),),
        )
        conn.execute(
            "INSERT INTO sessions (token, company_id, email) VALUES ('session-token', 'empresa-uno', 'uno@example.com')"
        )
        conn.execute(
            """
            INSERT INTO appointments (company_id, client_name, phone, reason, starts_at)
            VALUES ('empresa-uno', 'Ana', '3001234567', 'Consulta', '2026-11-08T10:00')
            """
        )
        conn.commit()
        self.appointment_id = conn.execute("SELECT id FROM appointments").fetchone()["id"]
        conn.close()

    def tearDown(self) -> None:
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.temp_dir.cleanup()

    def test_calendar_tokens_are_encrypted_at_rest(self) -> None:
        tokens = {"access_token": "access-secret", "refresh_token": "refresh-secret"}
        hola.save_calendar_tokens("empresa-uno", tokens, 1234567890, "uno@example.com")
        conn = hola.get_db()
        stored = conn.execute(
            "SELECT encrypted_token FROM calendar_connections WHERE company_id = 'empresa-uno'"
        ).fetchone()["encrypted_token"]
        conn.close()
        self.assertNotIn("access-secret", stored)
        self.assertNotIn("refresh-secret", stored)
        self.assertEqual(hola.read_calendar_tokens("empresa-uno")[0], tokens)

    def test_oauth_state_is_single_use_and_connection_is_saved_encrypted(self) -> None:
        response = hola.start_calendar_connection("Bearer session-token")
        query = parse_qs(urlparse(response["authorization_url"]).query)
        state = query["state"][0]
        self.assertEqual(query["scope"], ["https://www.googleapis.com/auth/calendar.events"])
        with patch("hola.google_token_request", return_value={
            "access_token": "oauth-access-secret",
            "refresh_token": "oauth-refresh-secret",
            "expires_in": 3600,
        }):
            callback = hola.calendar_callback(state=state, code="test-code")
        self.assertIn('"connected": true', callback.body.decode("utf-8"))
        repeated_callback = hola.calendar_callback(state=state, code="test-code")
        repeated_body = repeated_callback.body.decode("utf-8")
        self.assertIn('"connected": false', repeated_body)
        self.assertIn("ya fue utilizada", repeated_body)
        conn = hola.get_db()
        stored = conn.execute(
            "SELECT encrypted_token FROM calendar_connections WHERE company_id = 'empresa-uno'"
        ).fetchone()["encrypted_token"]
        conn.close()
        self.assertNotIn("oauth-access-secret", stored)
        self.assertNotIn("oauth-refresh-secret", stored)
        self.assertEqual(hola.read_calendar_tokens("empresa-uno")[0]["refresh_token"], "oauth-refresh-secret")

    def test_confirming_and_cancelling_syncs_google_calendar(self) -> None:
        hola.save_calendar_tokens(
            "empresa-uno",
            {"access_token": "access", "refresh_token": "refresh"},
            4_000_000_000,
        )
        auth = "Bearer session-token"
        with patch("hola.google_calendar_request", return_value={
            "id": "event-id",
            "htmlLink": "https://calendar.google.com/calendar/event?eid=test",
        }) as calendar_request:
            confirmed = hola.update_appointment_status(
                self.appointment_id,
                hola.AppointmentStatusUpdate(status="confirmed"),
                auth,
            )
            self.assertEqual(confirmed["status"], "confirmed")
            self.assertEqual(calendar_request.call_args.args[1], "POST")
        with patch("hola.google_calendar_request", return_value={}) as calendar_request:
            cancelled = hola.update_appointment_status(
                self.appointment_id,
                hola.AppointmentStatusUpdate(status="cancelled"),
                auth,
            )
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertEqual(calendar_request.call_args.args[1], "DELETE")
        conn = hola.get_db()
        status_value = conn.execute(
            "SELECT status FROM appointments WHERE id = ?", (self.appointment_id,)
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status_value, "cancelled")

    def test_company_cannot_manage_another_company_appointment(self) -> None:
        conn = hola.get_db()
        conn.execute(
            """
            INSERT INTO companies (company_id, name, email, password_hash, status, paid_through)
            VALUES ('empresa-dos', 'Empresa Dos', 'dos@example.com', 'test-hash', 'active', ?)
            """,
            ((hola.bogota_today() + dt.timedelta(days=60)).isoformat(),),
        )
        conn.execute(
            "INSERT INTO sessions (token, company_id, email) VALUES ('other-session', 'empresa-dos', 'dos@example.com')"
        )
        conn.commit()
        conn.close()
        with self.assertRaises(hola.HTTPException) as error:
            hola.update_appointment_status(
                self.appointment_id,
                hola.AppointmentStatusUpdate(status="confirmed"),
                "Bearer other-session",
            )
        self.assertEqual(error.exception.status_code, 404)

    def test_existing_appointment_database_is_migrated(self) -> None:
        legacy_db = Path(self.temp_dir.name) / "legacy.db"
        conn = sqlite3.connect(legacy_db)
        conn.execute(
            """
            CREATE TABLE appointments (
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
            INSERT INTO appointments (company_id, client_name, starts_at)
            VALUES ('empresa-uno', 'Ana', '2026-11-08T10:00')
            """
        )
        conn.commit()
        conn.close()
        current_db = hola.DB_PATH
        hola.DB_PATH = str(legacy_db)
        try:
            hola.initialize_db()
            conn = hola.get_db()
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(appointments)").fetchall()
            }
            appointment = conn.execute("SELECT status FROM appointments").fetchone()
            conn.close()
        finally:
            hola.DB_PATH = current_db
        self.assertTrue({"status", "calendar_event_id", "calendar_event_link"} <= columns)
        self.assertEqual(appointment["status"], "pending")

    def test_plan_prices_and_monthly_reply_limits(self) -> None:
        expected = {
            "starter": (39_900, 100),
            "professional": (79_900, 500),
            "enterprise": (139_900, 2_000),
        }
        page = hola.workspace_page()
        for plan_id, (price, reply_limit) in expected.items():
            with self.subTest(plan=plan_id):
                self.assertEqual(hola.PLAN_PRICES_COP[plan_id], price)
                self.assertEqual(hola.plan_ai_reply_limit(plan_id), reply_limit)
                self.assertIn(f"{price:,}".replace(",", "."), page)
                self.assertIn(f"{reply_limit:,}".replace(",", "."), page)

    def test_signup_price_and_plan_validation(self) -> None:
        for plan_id, price in hola.PLAN_PRICES_COP.items():
            with self.subTest(plan=plan_id):
                result = hola.signup(
                    hola.CompanySignup(
                        company_id=f"new-{plan_id}",
                        name=f"Company {plan_id}",
                        email=f"{plan_id}@example.test",
                        password="TestOnly123",
                        plan_id=plan_id,
                    )
                )
                self.assertEqual(result["amount_cop"], price)
                self.assertFalse(result["service_active"])
        with self.assertRaises(ValueError):
            hola.CompanySignup(
                company_id="invalid-plan",
                name="Invalid Plan",
                email="invalid@example.test",
                password="TestOnly123",
                plan_id="unknown",
            )

    def test_company_directory_filters_active_companies_by_sector_and_name(self) -> None:
        conn = hola.get_db()
        conn.executemany(
            """
            INSERT INTO companies (company_id, name, sector, email, password_hash, status, paid_through)
            VALUES (?, ?, ?, ?, 'test-hash', ?, ?)
            """,
            [
                ("cafe-central", "Café Central", "gastronomico", "cafe@example.test", "active", (hola.bogota_today() + dt.timedelta(days=60)).isoformat()),
                ("restaurante-antiguo", "Restaurante Antiguo", "Restaurante", "restaurante@example.test", "active", (hola.bogota_today() + dt.timedelta(days=60)).isoformat()),
                ("spa-uno", "Spa Uno", "estetico", "spa@example.test", "active", (hola.bogota_today() + dt.timedelta(days=60)).isoformat()),
                ("hotel-off", "Hotel Fuera", "hoteleria", "hotel@example.test", "disabled", (hola.bogota_today() + dt.timedelta(days=60)).isoformat()),
            ],
        )
        conn.commit()
        conn.close()

        gastronomic = hola.public_companies(sector="gastronomico")
        self.assertEqual(
            {company["company_id"] for company in gastronomic},
            {"cafe-central", "restaurante-antiguo"},
        )
        self.assertTrue(all(company["sector_label"] == "Gastronómico" for company in gastronomic))
        searched = hola.public_companies(sector="gastronomico", q="central")
        self.assertEqual([company["company_id"] for company in searched], ["cafe-central"])
        self.assertNotIn("email", searched[0])
        disabled = next(company for company in hola.public_companies() if company["company_id"] == "hotel-off")
        self.assertFalse(disabled["service_active"])

    def test_signup_requires_a_supported_sector(self) -> None:
        for sector in ("gastronomico", "estetico", "hoteleria", "turismo"):
            with self.subTest(sector=sector):
                payload = hola.CompanySignup(
                    company_id=f"sector-{sector}",
                    name=f"Company {sector}",
                    sector=sector,
                    email=f"{sector}@example.test",
                    password="test-pass",
                )
                hola.signup(payload)
        with self.assertRaises(ValueError):
            hola.CompanySignup(
                company_id="sector-invalid",
                name="Invalid Sector",
                sector="unknown-sector",
                email="sector-invalid@example.test",
                password="test-pass",
            )

    def test_directory_and_sector_selector_are_present(self) -> None:
        page = hola.workspace_page()
        booking_section = page.index('id="bookingSection"')
        self.assertIn('id="directoryResults"', page)
        self.assertIn('id="directorySector"', page)
        self.assertLess(booking_section, page.index('id="directorySector"'))
        self.assertNotIn('id="directorySection"', page)
        self.assertNotIn('data-target="directorySection"', page)
        self.assertIn('id="signupSector"', page)
        self.assertIn("document.getElementById('chatCompanyCode').value = directoryCompanyId", page)
        self.assertIn("document.getElementById('bookCompany').value = directoryCompanyId", page)
        self.assertIn("document.getElementById('demo-chat').scrollIntoView", page)
        for sector in hola.COMPANY_SECTORS:
            with self.subTest(sector=sector):
                self.assertIn(f'value="{sector}"', page)
                self.assertEqual(hola.canonical_sector(sector), sector)
        self.assertEqual(hola.canonical_sector("Servicios profesionales"), "servicios_profesionales")

    def test_company_registration_hides_after_login_and_returns_after_logout(self) -> None:
        page = hola.workspace_page()
        self.assertIn('id="companySignupSection"', page)
        self.assertIn(".company-signup-section.hidden { display:none; }", page)
        self.assertIn("document.getElementById('companySignupSection').classList.add('hidden')", page)
        self.assertIn("document.getElementById('companySignupSection').classList.remove('hidden')", page)

    def test_booking_page_refreshes_availability_for_other_clients(self) -> None:
        page = hola.workspace_page()
        self.assertIn("setInterval(() =>", page)
        self.assertIn("}, 10000);", page)
        self.assertIn("loadAvailability(true)", page)
        self.assertIn("Ese horario acaba de ser reservado por otro cliente", page)
        self.assertIn('id="bookingDays"', page)
        self.assertIn('id="availabilitySlots" class="booking-options"', page)
        self.assertIn("button.dataset.bookingDate = dateValue", page)
        self.assertIn('id="bookingPreviousMonth"', page)
        self.assertIn('id="bookingNextMonth"', page)
        self.assertIn("daysInMonth", page)
        self.assertIn("button.disabled = !isSelectable", page)
        self.assertIn("label.textContent = !isOpen", page)
        self.assertIn("'Cerrado'", page)
        self.assertIn("'Fuera del período pagado'", page)
        self.assertIn("target.closest('[data-booking-date]')?.dataset.bookingDate", page)
        self.assertIn("button.dataset.slotTime = slot.starts_at", page)
        self.assertIn("button.disabled = !slot.available", page)
        self.assertNotIn('class="slots-table"', page)
        self.assertIn("Registrar pago / renovar 1 mes", page)
        self.assertIn("/owner/payment/", page)

    def test_public_company_profile_exposes_hours_for_day_options(self) -> None:
        profile = hola.public_company("empresa-uno")
        self.assertEqual(profile["weekly_hours"]["monday"], {"open": "09:00", "close": "17:00"})
        self.assertIsNone(profile["weekly_hours"]["sunday"])

    def test_starter_limit_blocks_extra_replies_and_reports_usage(self) -> None:
        conn = hola.get_db()
        conn.executemany(
            "INSERT INTO conversations (company_id, sender, role, message) VALUES ('empresa-uno', 'ia', 'ai', 'respuesta')",
            [()] * 100,
        )
        conn.execute(
            """
            INSERT INTO conversations (company_id, sender, role, message, created_at)
            VALUES ('empresa-uno', 'ia', 'ai', 'respuesta anterior', datetime('now', '-1 month'))
            """
        )
        conn.commit()
        conn.close()
        with patch("hola.generate_ai_reply", return_value="Respuesta de prueba") as generate:
            with self.assertRaises(hola.HTTPException) as error:
                hola.assistant(hola.MessageRequest(message="Hola"), "empresa-uno")
        self.assertEqual(error.exception.status_code, 429)
        generate.assert_not_called()
        usage = hola.read_my_knowledge("Bearer session-token")
        self.assertEqual(usage["ai_replies_used"], 100)
        self.assertEqual(usage["ai_replies_limit"], 100)

    def test_assistant_counts_each_successful_reply(self) -> None:
        with patch("hola.generate_ai_reply", return_value="Respuesta de prueba"):
            result = hola.assistant(
                hola.MessageRequest(message="Hola"),
                "empresa-uno",
            )
        self.assertEqual(result["ai_replies_used"], 1)
        self.assertEqual(result["ai_replies_limit"], 100)
        self.assertEqual(hola.monthly_ai_reply_count("empresa-uno"), 1)

    def next_weekday(self, weekday: int) -> dt.date:
        today = dt.datetime.now(hola.ZoneInfo("America/Bogota")).date()
        days = (weekday - today.weekday()) % 7
        return today + dt.timedelta(days=days or 7)

    def test_availability_uses_opening_hours_and_marks_booked_slots(self) -> None:
        booking_date = self.next_weekday(0)
        response = hola.company_availability("empresa-uno", booking_date.isoformat())
        self.assertEqual(response["duration_minutes"], 60)
        self.assertEqual(response["slots"][0], {
            "starts_at": f"{booking_date.isoformat()}T09:00",
            "available": True,
        })

        hola.create_booking(
            hola.AppointmentRequest(
                client_name="Cliente",
                starts_at=f"{booking_date.isoformat()}T09:00",
            ),
            "empresa-uno",
        )
        updated = hola.company_availability("empresa-uno", booking_date.isoformat())
        self.assertEqual(updated["slots"][0]["available"], False)
        self.assertEqual(updated["slots"][1]["available"], True)
        self.assertIn("Los horarios se actualizan automáticamente", hola.workspace_page())
        with self.assertRaises(hola.HTTPException) as error:
            hola.create_booking(
                hola.AppointmentRequest(
                    client_name="Otro cliente",
                    starts_at=f"{booking_date.isoformat()}T09:00",
                ),
                "empresa-uno",
            )
        self.assertEqual(error.exception.status_code, 409)
        conn = hola.get_db()
        appointment_id = conn.execute(
            "SELECT id FROM appointments WHERE client_name = 'Cliente'"
        ).fetchone()["id"]
        conn.close()
        hola.update_appointment_status(
            appointment_id,
            hola.AppointmentStatusUpdate(status="cancelled"),
            "Bearer session-token",
        )
        released = hola.company_availability("empresa-uno", booking_date.isoformat())
        self.assertEqual(released["slots"][0]["available"], True)

    def test_expired_company_is_visible_but_cannot_be_contacted_or_booked(self) -> None:
        conn = hola.get_db()
        conn.execute(
            "UPDATE companies SET paid_through = ? WHERE company_id = 'empresa-uno'",
            ((hola.bogota_today() - dt.timedelta(days=1)).isoformat(),),
        )
        conn.commit()
        conn.close()
        profile = hola.public_company("empresa-uno")
        self.assertFalse(profile["service_active"])
        self.assertIn("Empresa inhabilitada", profile["status_message"])
        with self.assertRaises(hola.HTTPException) as availability_error:
            hola.company_availability("empresa-uno", hola.bogota_today().isoformat())
        self.assertEqual(availability_error.exception.status_code, 403)
        with self.assertRaises(hola.HTTPException) as booking_error:
            hola.create_booking(
                hola.AppointmentRequest(client_name="Cliente", starts_at="2026-11-09T09:00"),
                "empresa-uno",
            )
        self.assertEqual(booking_error.exception.status_code, 403)

    def test_manual_payment_extends_period_by_one_calendar_month(self) -> None:
        conn = hola.get_db()
        conn.execute("UPDATE companies SET paid_through = NULL WHERE company_id = 'empresa-uno'")
        conn.commit()
        conn.close()
        with patch.object(hola, "ADMIN_KEY", "admin-test"), patch.object(
            hola, "bogota_today", return_value=dt.date(2026, 11, 7)
        ):
            result = hola.owner_register_payment("empresa-uno", "admin-test")
        self.assertEqual(result["paid_through"], "2026-12-07")

    def test_calendar_month_end_uses_last_day_of_shorter_month(self) -> None:
        self.assertEqual(hola.add_calendar_month(dt.date(2026, 1, 31)), dt.date(2026, 2, 28))
        self.assertEqual(hola.add_calendar_month(dt.date(2028, 1, 31)), dt.date(2028, 2, 29))

    def test_closed_days_and_out_of_hours_cannot_be_booked(self) -> None:
        sunday = self.next_weekday(6)
        self.assertEqual(
            hola.company_availability("empresa-uno", sunday.isoformat())["slots"],
            [],
        )
        monday = self.next_weekday(0)
        with self.assertRaises(hola.HTTPException) as error:
            hola.create_booking(
                hola.AppointmentRequest(
                    client_name="Cliente",
                    starts_at=f"{monday.isoformat()}T08:00",
                ),
                "empresa-uno",
            )
        self.assertEqual(error.exception.status_code, 409)

    def test_custom_hours_and_duration_are_saved(self) -> None:
        hours = {
            day: ({"open": "10:00", "close": "14:00"} if day == "monday" else None)
            for day in hola.WEEKDAYS
        }
        result = hola.write_my_knowledge(
            hola.CompanyProfileUpdate(
                weekly_hours=hours,
                appointment_duration_minutes=30,
            ),
            "Bearer session-token",
        )
        self.assertEqual(result["appointment_duration_minutes"], 30)
        booking_date = self.next_weekday(0)
        slots = hola.company_availability("empresa-uno", booking_date.isoformat())["slots"]
        self.assertEqual(len(slots), 8)
        self.assertEqual(slots[0]["starts_at"], f"{booking_date.isoformat()}T10:00")
        self.assertEqual(slots[-1]["starts_at"], f"{booking_date.isoformat()}T13:30")

    def test_calendar_event_times_use_appointment_duration(self) -> None:
        starts, ends, _ = hola.calendar_event_times("2026-11-09T10:00", 45)
        start_datetime = dt.datetime.fromisoformat(starts)
        end_datetime = dt.datetime.fromisoformat(ends)
        self.assertEqual(end_datetime - start_datetime, dt.timedelta(minutes=45))


if __name__ == "__main__":
    unittest.main()
