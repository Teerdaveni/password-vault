from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PasswordEntry, PasswordRequest


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin interface for User model."""
    
    list_display = ('email', 'username', 'is_admin', 'is_active', 'date_joined')
    list_filter = ('is_admin', 'is_active', 'is_staff')
    search_fields = ('email', 'username')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_admin', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'is_admin'),
        }),
    )


@admin.register(PasswordEntry)
class PasswordEntryAdmin(admin.ModelAdmin):
    """Admin interface for PasswordEntry model."""
    
    list_display = ('application_name', 'username', 'email', 'user', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('application_name', 'username', 'email', 'user__username', 'user__email')
    readonly_fields = ('encrypted_password', 'created_at', 'updated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Application Details', {'fields': ('application_name', 'username', 'email')}),
        ('User', {'fields': ('user',)}),
        ('Password', {'fields': ('encrypted_password',)}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(PasswordRequest)
class PasswordRequestAdmin(admin.ModelAdmin):
    """Admin interface for PasswordRequest model."""
    
    list_display = ('password_entry', 'requester', 'admin', 'status', 'requested_at', 'reviewed_at')
    list_filter = ('status', 'requested_at', 'reviewed_at')
    search_fields = ('requester__username', 'admin__username', 'password_entry__application_name')
    readonly_fields = ('requested_at', 'reviewed_at', 'expires_at')
    ordering = ('-requested_at',)
    
    fieldsets = (
        ('Request Details', {'fields': ('password_entry', 'requester', 'reason')}),
        ('Review', {'fields': ('status', 'admin', 'admin_notes')}),
        ('Timestamps', {'fields': ('requested_at', 'reviewed_at', 'expires_at')}),
    )

# @admin.register(PasswordRequest)
# class PasswordRequestAdmin(admin.ModelAdmin):
#     """Admin interface for PasswordRequest model."""
    
#     list_display = ('password_entry', 'requester', 'admin', 'status', 'requested_at', 'reviewed_at')
#     list_filter = ('status', 'requested_at', 'reviewed_at')
#     search_fields = ('requester__username', 'admin__username', 'password_entry__application_name')
#     readonly_fields = ('requested_at', 'reviewed_at', 'expires_at')
#     ordering = ('-requested_at',)
    
#     fieldsets = (
#         ('Request Details', {'fields': ('password_entry', 'requester', 'reason')}),
#         ('Review', {'fields': ('status', 'admin', 'admin_notes')}),
#         ('Timestamps', {'fields': ('requested_at', 'reviewed_at', 'expires_at')}),
#     )