from django.core.management import call_command
from django.db import connection

def run():
    user_table_exists = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.vault_auth_user');")
            result = cursor.fetchone()
            user_table_exists = result and result[0] == 'vault_auth_user'
    except Exception:
        user_table_exists = False

    if not user_table_exists:
        print("⚙ User table missing — running migrations...")
        call_command("migrate", interactive=False)
        print("✔ Migration complete.")
    else:
        print("✔ User table exists — skipping migrations.")
