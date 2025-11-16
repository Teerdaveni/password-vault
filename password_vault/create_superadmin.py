from django.contrib.auth import get_user_model

def run():
    User = get_user_model()
    email = "teerdaveni@sriainfotech.com"
    username = "admin"
    password = "Admin@123"

    if not User.objects.filter(email=email).exists():
        User.objects.create_superuser(
            email=email,
            username=username,
            password=password
        )
        print("✔ Superuser created successfully!")
    else:
        print("✔ Superuser already exists.")
