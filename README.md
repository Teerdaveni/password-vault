# Password Vault - Secure Password Management System

A Django REST Framework-based secure password management system with administrator approval workflow for viewing stored passwords.

## Features

### 1. Password Storage and Security
- Store usernames, passwords, and emails for various applications
- Fernet encryption for all stored passwords
- JWT-based authentication for secure access control

### 2. Administrator Approval System
- Support for multiple administrator accounts
- OTP-based email verification for admin approval
- Password viewing request workflow with OTP verification
- Configurable decryption window (default: 1 hour) for approved requests
- Request status tracking (pending, otp_sent, approved, rejected, expired)

## Project Structure

```
password-vault/
├── vault_auth/              # Main authentication and password management app
│   ├── __init__.py
│   ├── models.py           # User, PasswordEntry, and PasswordRequest models
│   ├── serializers.py      # DRF serializers
│   ├── views.py            # API views and endpoints
│   ├── urls.py             # URL routing
│   ├── admin.py            # Django admin configuration
│   └── migrations/         # Database migrations
├── password_vault/         # Django project settings
│   ├── __init__.py
│   ├── settings.py         # Project settings
│   ├── urls.py            # Main URL configuration
│   ├── asgi.py           # ASGI configuration
│   └── wsgi.py           # WSGI configuration
├── manage.py
├── requirements.txt        # Project dependencies
└── README.md
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Teerdaveni2002/password-vault.git
cd password-vault
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (optional):
```bash
# Copy the example file and update with your keys
cp .env.example .env
# Edit .env and set your SECRET_KEY and ENCRYPTION_KEY
# You can generate keys using the commands in the .env.example file
```

4. Run migrations:
```bash
python manage.py migrate
```

5. Test the installation (optional):
```bash
python test_installation.py
```

6. Create a superuser (admin):
```bash
python manage.py createsuperuser
```

7. Run the development server:
```bash
python manage.py runserver
```

## API Endpoints

### Authentication

#### Register User
- **POST** `/api/auth/register/`
- Body: `{ "email": "user@example.com", "username": "username", "password": "password", "password2": "password", "is_admin": false }`
- Returns: User data and JWT tokens

#### Login
- **POST** `/api/auth/login/`
- Body: `{ "email": "user@example.com", "password": "password" }`
- Returns: User data and JWT tokens

#### Refresh Token
- **POST** `/api/auth/token/refresh/`
- Body: `{ "refresh": "refresh_token" }`
- Returns: New access token

#### User Profile
- **GET** `/api/auth/profile/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: Current user profile

### Password Management

#### List Password Entries
- **GET** `/api/passwords/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: List of user's password entries

#### Create Password Entry
- **POST** `/api/passwords/`
- Headers: `Authorization: Bearer <access_token>`
- Body: `{ "application_name": "Gmail", "username": "user", "email": "user@gmail.com", "password": "secret123" }`
- Returns: Created password entry

#### Update Password Entry
- **PUT** `/api/passwords/{id}/`
- Headers: `Authorization: Bearer <access_token>`
- Body: `{ "application_name": "Gmail", "username": "user", "email": "user@gmail.com", "password": "newsecret" }`
- Returns: Updated password entry

#### Delete Password Entry
- **DELETE** `/api/passwords/{id}/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: 204 No Content

#### View Decrypted Password
- **GET** `/api/passwords/{id}/view-password/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: Password entry with decrypted password
- Note: Only owner can view directly, others need approved request

### Password Request Workflow

#### Create Password Request
- **POST** `/api/requests/`
- Headers: `Authorization: Bearer <access_token>`
- Body: `{ "password_entry": 1, "reason": "Need to access for support" }`
- Returns: Created password request and sends OTP to all admin emails

#### List Password Requests
- **GET** `/api/requests/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: List of requests (all for admins, own for users)

#### Get Pending Requests
- **GET** `/api/requests/pending/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: List of pending requests

#### Check Request Status
- **GET** `/api/requests/{id}/check_status/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: Current status of request

#### Verify OTP and Approve (Admin Only)
- **POST** `/api/requests/{id}/verify_otp/`
- Headers: `Authorization: Bearer <access_token>`
- Body: `{ "otp": "123456", "decryption_window": 3600 }`
- Returns: Approved request
- Note: OTP is sent to admin email when request is created. Default window is 1 hour (3600 seconds)

#### Review Request (Admin Only)
- **POST** `/api/requests/{id}/review/`
- Headers: `Authorization: Bearer <access_token>`
- Body: `{ "action": "reject", "notes": "Not authorized" }` or `{ "action": "resend_otp" }`
- Returns: Updated request
- Note: Use to reject a request or resend OTP if expired

### Admin Endpoints

#### Admin Dashboard
- **GET** `/api/admin/dashboard/`
- Headers: `Authorization: Bearer <access_token>`
- Returns: Statistics (pending requests, total users, passwords, requests)

## Security Features

1. **JWT Authentication**: Secure token-based authentication
2. **Password Encryption**: Fernet symmetric encryption for stored passwords
3. **Role-Based Access Control**: Admin and regular user roles
4. **Temporary Decryption Window**: Approved requests expire after configurable time
5. **Request Workflow**: Multi-step approval process for sensitive operations

## Models

### User
- Custom user model with admin flag
- Email and username fields
- Standard Django authentication integration

### PasswordEntry
- Application name, username, email
- Encrypted password storage
- Linked to user owner

### PasswordRequest
- Request for password viewing
- Status tracking (pending, approved, rejected, expired)
- Expiration time for approved requests
- Admin review notes

## Development

### Running Tests
```bash
python manage.py test vault_auth
```

### Creating Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Accessing Admin Panel
Navigate to `http://localhost:8000/admin/` and login with superuser credentials.

## Environment Variables

- `SECRET_KEY`: Django secret key (auto-generated if not set)
- `ENCRYPTION_KEY`: Fernet encryption key (auto-generated if not set)
- `DEBUG`: Debug mode (default: True)
- `ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of CORS origins

## License

This project is provided as-is for educational purposes.
