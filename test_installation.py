#!/usr/bin/env python
"""
Quick test script to verify the password vault installation.
Run this after setting up the project to ensure everything is configured correctly.
"""

import os
import sys
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_vault.settings')
django.setup()

from vault_auth.models import User, PasswordEntry, PasswordRequest
from cryptography.fernet import Fernet
from django.conf import settings


def test_encryption():
    """Test that encryption is working."""
    print("Testing encryption...")
    try:
        key = settings.ENCRYPTION_KEY.encode()
        fernet = Fernet(key)
        test_data = b"test_password_123"
        encrypted = fernet.encrypt(test_data)
        decrypted = fernet.decrypt(encrypted)
        assert decrypted == test_data
        print("✓ Encryption working correctly")
        return True
    except Exception as e:
        print(f"✗ Encryption test failed: {e}")
        return False


def test_models():
    """Test that models can be imported."""
    print("\nTesting models...")
    try:
        print(f"✓ User model: {User.__name__}")
        print(f"✓ PasswordEntry model: {PasswordEntry.__name__}")
        print(f"✓ PasswordRequest model: {PasswordRequest.__name__}")
        return True
    except Exception as e:
        print(f"✗ Model test failed: {e}")
        return False


def test_database():
    """Test that database is accessible."""
    print("\nTesting database connection...")
    try:
        user_count = User.objects.count()
        print(f"✓ Database accessible. Users in database: {user_count}")
        return True
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        print("  Make sure you've run: python manage.py migrate")
        return False


def main():
    """Run all tests."""
    print("=" * 50)
    print("Password Vault Installation Test")
    print("=" * 50)
    
    results = [
        test_encryption(),
        test_models(),
        test_database(),
    ]
    
    print("\n" + "=" * 50)
    if all(results):
        print("✓ All tests passed! Installation is working correctly.")
        print("\nNext steps:")
        print("1. Create a superuser: python manage.py createsuperuser")
        print("2. Run the server: python manage.py runserver")
        print("3. Access the API at: http://localhost:8000/api/")
        sys.exit(0)
    else:
        print("✗ Some tests failed. Please check the errors above.")
        sys.exit(1)


if __name__ == '__main__':
    main()
