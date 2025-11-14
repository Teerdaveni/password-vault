from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.mail import send_mail
from cryptography.fernet import Fernet
from django.conf import settings
import random
import string


class UserManager(BaseUserManager):
    """Custom user manager for User model."""
    
    def create_user(self, email, username, password=None, **extra_fields):
        """Create and save a regular user."""
        if not email:
            raise ValueError('The Email field must be set')
        if not username:
            raise ValueError('The Username field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, username, password=None, **extra_fields):
        """Create and save a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model with admin flag."""
    
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return self.email


class PasswordEntry(models.Model):
    """Model for storing encrypted passwords."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_entries')
    application_name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    email = models.EmailField(blank=True, null=True)
    encrypted_password = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'password_entries'
        verbose_name = 'Password Entry'
        verbose_name_plural = 'Password Entries'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.application_name} - {self.username}"
    
    def set_password(self, plain_password):
        """Encrypt and store the password."""
        fernet = Fernet(settings.ENCRYPTION_KEY.encode())
        self.encrypted_password = fernet.encrypt(plain_password.encode()).decode()
    
    def get_password(self):
        """Decrypt and return the password."""
        fernet = Fernet(settings.ENCRYPTION_KEY.encode())
        return fernet.decrypt(self.encrypted_password.encode()).decode()


class PasswordRequest(models.Model):
    """Model for password viewing approval workflow."""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('otp_sent', 'OTP Sent'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    password_entry = models.ForeignKey(PasswordEntry, on_delete=models.CASCADE, related_name='requests')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_requests')
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requests')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(default=timezone.now)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True, null=True)
    admin_notes = models.TextField(blank=True, null=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'password_requests'
        verbose_name = 'Password Request'
        verbose_name_plural = 'Password Requests'
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"Request by {self.requester.username} for {self.password_entry.application_name}"
    
    def is_active(self):
        """Check if the request is still active (approved and not expired)."""
        if self.status == 'approved' and self.expires_at:
            return timezone.now() < self.expires_at
        return False
    
    def generate_otp(self):
        """Generate a 6-digit OTP and send it to admin email."""
        self.otp = ''.join(random.choices(string.digits, k=6))
        self.otp_expires_at = timezone.now() + timezone.timedelta(hours=1)
        self.status = 'otp_sent'
        self.save()
        
        # Send OTP email to all admins
        admin_users = User.objects.filter(is_admin=True)
        admin_emails = [admin.email for admin in admin_users if admin.email]
        
        if admin_emails:
            subject = f'Password Request OTP - {self.password_entry.application_name}'
            message = f"""
A password view request has been made:

User: {self.requester.username}
Application: {self.password_entry.application_name}
Reason: {self.reason or 'Not specified'}

Your OTP code is: {self.otp}

This OTP will expire in 1 hour.

To approve this request, use the OTP verification endpoint.
            """
            try:
                # Use Celery task to send emails asynchronously so request creation
                # is not blocked by mail delivery. The task will fall back to
                # Django's send_mail implementation running in the worker.
                from .tasks import send_otp_email

                send_otp_email(admin_emails, subject, message)
            except Exception as e:
                # If Celery is not configured or the task import fails, fall back
                # to synchronous send_mail but don't block failure of create.
                try:
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        admin_emails,
                        fail_silently=False,
                    )
                except Exception as e2:
                    # Log error but don't fail the request
                    print(f"Failed to send OTP email: {e2}")
        
        return self.otp
    
    def verify_otp(self, otp_code):
        """Verify the OTP code."""
        if not self.otp or not self.otp_expires_at:
            return False
        
        if timezone.now() > self.otp_expires_at:
            return False
        
        return self.otp == otp_code
    
    def approve(self, admin_user, decryption_window_seconds=3600):
        """Approve the request and set expiration time (default 1 hour)."""
        self.status = 'approved'
        self.admin = admin_user
        self.reviewed_at = timezone.now()
        self.expires_at = timezone.now() + timezone.timedelta(seconds=decryption_window_seconds)
        self.save()
    
    def reject(self, admin_user, notes=None):
        """Reject the request."""
        self.status = 'rejected'
        self.admin = admin_user
        self.reviewed_at = timezone.now()
        if notes:
            self.admin_notes = notes
        self.save()
    
    def check_expiration(self):
        """Check and update status if expired."""
        if self.status == 'approved' and self.expires_at and timezone.now() > self.expires_at:
            self.status = 'expired'
            self.save()
            return True
        return False


class PasswordViewLog(models.Model):
    """Audit log for decrypted password views."""

    password_entry = models.ForeignKey(PasswordEntry, on_delete=models.CASCADE, related_name='view_logs')
    viewer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='view_logs')
    viewed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'password_view_logs'
        verbose_name = 'Password View Log'
        verbose_name_plural = 'Password View Logs'
        ordering = ['-viewed_at']

    def __str__(self):
        return f"{self.viewer.username} viewed {self.password_entry.application_name} at {self.viewed_at}"
