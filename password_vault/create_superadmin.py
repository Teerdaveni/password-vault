from django.contrib.auth import get_user_model

def run():
    User = get_user_model()
    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser(
            username='admin',
            email='teerdaveni@sriainfotech.com',
            password='Admin@123'
        )
        print("Superuser created successfully!")
    else:
        print("Superuser already exists.")
