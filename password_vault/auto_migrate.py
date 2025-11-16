from django.core.management import call_command
from django.db import connection

def run():
    try:
        # Check if any table exists — if not, run migrate
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM information_schema.tables LIMIT 1;")
        print("✔ Database already has tables, no auto-action.")
    except Exception:
        print("⚙ Running migrations...")
        call_command("migrate", interactive=False)
        print("✔ Migrations complete.")
