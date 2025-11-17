from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = "Create default superuser for production if not exists"

    def handle(self, *args, **kwargs):
        User = get_user_model()

        email = "teerdaveni@sriainfotech.com"
        username = "admin"
        password = "Admin@123"

        if not User.objects.filter(email__iexact=email).exists():
            User.objects.create_superuser(
                email=email,
                username=username,
                password=password
            )
            self.stdout.write(self.style.SUCCESS("✔ Superuser created successfully"))
        else:
            self.stdout.write(self.style.WARNING("✔ Superuser already exists"))
