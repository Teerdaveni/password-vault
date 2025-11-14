from rest_framework import serializers
from .models import User, PasswordEntry, PasswordRequest
from django.contrib.auth.password_validation import validate_password


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password', 'password2', 'is_admin')
        read_only_fields = ('id',)
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user details."""
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'is_admin', 'is_active', 'date_joined')
        read_only_fields = ('id', 'date_joined')


class PasswordEntrySerializer(serializers.ModelSerializer):
    """Serializer for password entry (without decrypted password)."""
    
    password = serializers.CharField(write_only=True, required=True)
    owner_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = PasswordEntry
        fields = ('id', 'application_name', 'username', 'email', 'password', 'created_at', 'updated_at', 'owner_username')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        password_entry = PasswordEntry.objects.create(**validated_data)
        password_entry.set_password(password)
        password_entry.save()
        return password_entry
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class PasswordEntryDetailSerializer(serializers.ModelSerializer):
    """Serializer for password entry with decrypted password."""
    
    decrypted_password = serializers.SerializerMethodField()
    owner_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = PasswordEntry
        fields = ('id', 'application_name', 'username', 'email', 'decrypted_password', 'created_at', 'updated_at', 'owner_username')
        read_only_fields = ('id', 'created_at', 'updated_at', 'decrypted_password')
    
    def get_decrypted_password(self, obj):
        """Get decrypted password - only if authorized."""
        return obj.get_password()


class PasswordRequestSerializer(serializers.ModelSerializer):
    """Serializer for password requests."""
    
    requester_username = serializers.CharField(source='requester.username', read_only=True)
    admin_username = serializers.CharField(source='admin.username', read_only=True, allow_null=True)
    application_name = serializers.CharField(source='password_entry.application_name', read_only=True)
    is_active = serializers.SerializerMethodField()
    
    class Meta:
        model = PasswordRequest
        fields = (
            'id', 'password_entry', 'requester', 'requester_username', 
            'admin', 'admin_username', 'application_name', 'status', 
            'requested_at', 'reviewed_at', 'expires_at', 'reason', 
            'admin_notes', 'is_active', 'otp_expires_at'
        )
        read_only_fields = (
            'id', 'requester', 'admin', 'status', 'reviewed_at', 
            'expires_at', 'admin_notes', 'requester_username', 
            'admin_username', 'application_name', 'is_active', 'otp_expires_at'
        )
    
    def get_is_active(self, obj):
        """Check if request is still active."""
        return obj.is_active()


class PasswordRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating password requests.

    Convenience: accept either `password_entry` (PK), or `password_entry_id` (int),
    or `application_name` (string) as the identifying input. The serializer will
    resolve those into the required `password_entry` FK before creating the model.
    """

    password_entry_id = serializers.IntegerField(write_only=True, required=False)
    application_name = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = PasswordRequest
        fields = ('password_entry', 'reason', 'password_entry_id', 'application_name')

    def validate(self, attrs):
        request = self.context.get('request')

        # If password_entry already present (DRF may supply an object or pk), keep it.
        if 'password_entry' not in attrs:
            # Try numeric id alias
            pe_id = attrs.pop('password_entry_id', None)
            app_name = attrs.pop('application_name', None)
            if pe_id is not None:
                try:
                    pe = PasswordEntry.objects.get(pk=pe_id)
                except PasswordEntry.DoesNotExist:
                    raise serializers.ValidationError({'password_entry_id': 'Invalid password_entry_id'})
                attrs['password_entry'] = pe
            elif app_name:
                pe = PasswordEntry.objects.filter(application_name=app_name).first()
                if not pe:
                    raise serializers.ValidationError({'application_name': 'No PasswordEntry found with that application_name'})
                attrs['password_entry'] = pe
            else:
                raise serializers.ValidationError({'password_entry': 'This field is required.'})

        # attach requester
        if request is None or not hasattr(request, 'user'):
            raise serializers.ValidationError('Request context with user is required')
        attrs['requester'] = request.user
        return attrs

    def create(self, validated_data):
        # requester already set in validate
        return super().create(validated_data)


class PasswordRequestActionSerializer(serializers.Serializer):
    """Serializer for admin actions on password requests."""
    
    action = serializers.ChoiceField(choices=['reject', 'resend_otp'])
    notes = serializers.CharField(required=False, allow_blank=True)


class OTPVerificationSerializer(serializers.Serializer):
    """Serializer for OTP verification."""
    
    otp = serializers.CharField(max_length=6, min_length=6)
    decryption_window = serializers.IntegerField(default=3600, min_value=60, max_value=7200)  # 1 min to 2 hours
