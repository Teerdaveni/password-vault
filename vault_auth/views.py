from rest_framework import status, viewsets, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import User, PasswordEntry, PasswordRequest, PasswordViewLog
from .serializers import (
    UserRegistrationSerializer, UserSerializer,
    PasswordEntrySerializer, PasswordEntryDetailSerializer,
    PasswordRequestSerializer, PasswordRequestCreateSerializer,
    PasswordRequestActionSerializer
)


class IsAdmin(permissions.BasePermission):
    """Custom permission to only allow admins."""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin


class IsOwnerOrAdmin(permissions.BasePermission):
    """Custom permission to only allow owners or admins."""
    
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user'):
            return obj.user == request.user or request.user.is_admin
        return False


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """Register a new user."""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['POST'])
# @permission_classes([AllowAny])
# def login(request):
#     """Authenticate user and return JWT tokens."""
#     email = request.data.get('email')
#     password = request.data.get('password')
    
#     if not email or not password:
#         return Response(
#             {'error': 'Please provide both email and password'},
#             status=status.HTTP_400_BAD_REQUEST
#         )
    
#     user = authenticate(email=email, password=password)
    
#     if user is None:
#         return Response(
#             {'error': 'Invalid credentials'},
#             status=status.HTTP_401_UNAUTHORIZED
#         )
    
#     if not user.is_active:
#         return Response(
#             {'error': 'User account is disabled'},
#             status=status.HTTP_401_UNAUTHORIZED
#         )
    
#     refresh = RefreshToken.for_user(user)
    
#     return Response({
#         'user': UserSerializer(user).data,
#         'tokens': {
#             'refresh': str(refresh),
#             'access': str(refresh.access_token),
#         }
#     })

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        # 1️⃣ Missing email or password
        if not email or not password:
            return Response(
                {"error": "Please provide email and password"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2️⃣ Check if email exists
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid email"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3️⃣ Password incorrect
        if not user_obj.check_password(password):
            return Response(
                {"error": "Incorrect password"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4️⃣ Check if user is active
        if not user_obj.is_active:
            return Response(
                {"error": "User account is disabled"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # 5️⃣ Generate JWT tokens
        refresh = RefreshToken.for_user(user_obj)

        return Response({
            "user": UserSerializer(user_obj).data,
            "tokens": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """Get current user profile."""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

class LogoutAPIView(APIView):
    """Logout by blacklisting the provided refresh token.

    POST body: { "refresh": "<refresh_token>" }

    If the Simple JWT blacklist app is not configured, the view will
    return a message asking the client to delete tokens locally.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response(
            {
                "message": "Logout successful."
            },
            status=status.HTTP_200_OK
        )


    # def post(self, request):
    #     # Accept optional refresh token. If provided, attempt to blacklist it.
    #     # If not provided, return 200 instructing the client to delete tokens
    #     # locally (no server-side revocation available by default).
    #     refresh_token = request.data.get('refresh')
    #     if not refresh_token:
    #         return Response({
    #             'message': 'No refresh token provided. Client should delete access and refresh tokens locally.'
    #         }, status=status.HTTP_200_OK)

    #     try:
    #         token = RefreshToken(refresh_token)
    #         # Attempt to blacklist (requires simplejwt blacklist app)
    #         token.blacklist()
    #     except AttributeError:
    #         # blacklist() not available because blacklist app not installed
    #         return Response({
    #             'message': 'Logout: token received but server blacklist not configured. Client should delete tokens.'
    #         }, status=status.HTTP_200_OK)
    #     except TokenError:
    #         return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

    #     return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)


# class PasswordEntryViewSet(viewsets.ModelViewSet):
#     """ViewSet for managing password entries."""
    
#     permission_classes = [IsAuthenticated]
    
#     def get_queryset(self):
#         """Return password entries for the current user."""
#         # Admins should be able to see all password entries in the system.
#         # Regular users only see their own entries.
#         if self.request.user and getattr(self.request.user, 'is_admin', False):
#             return PasswordEntry.objects.all()
#         return PasswordEntry.objects.filter(user=self.request.user)
    
#     def get_serializer_class(self):
#         """Return appropriate serializer based on action."""
#         if self.action == 'retrieve_with_password':
#             return PasswordEntryDetailSerializer
#         return PasswordEntrySerializer
    
#     def perform_create(self, serializer):
#         """Create a password entry for the current user."""
#         serializer.save(user=self.request.user)
    
#     def get_permissions(self):
#         """Set permissions based on action."""
#         if self.action == 'retrieve_with_password':
#             # For viewing decrypted passwords we enforce explicit owner-only
#             # checks inside the view. Do not grant admin blanket access here
#             # so that only the requester/owner can view the decrypted value.
#             return [IsAuthenticated()]
#         return [IsAuthenticated()]


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.utils import timezone
from vault_auth.models import PasswordEntry, PasswordRequest, PasswordViewLog
from vault_auth.serializers import PasswordEntrySerializer, PasswordEntryDetailSerializer


class PasswordEntryAPIView(APIView):
    """
    Single APIView handling:
    - GET /api/passwords/ → list all password entries (all users can see)
    - POST /api/passwords/ → create a new entry (for current user)
    - GET /api/passwords/<pk>/ → view one entry (decrypted if approved)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """List all password entries OR retrieve one with access control."""
        user = request.user

        # ✅ CASE 1: Retrieve a single entry (with pk)
        if pk is not None:
            try:
                entry = PasswordEntry.objects.get(pk=pk)
            except PasswordEntry.DoesNotExist:
                return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

            # 🔒 Allow if owner or has approved request
            active_request = PasswordRequest.objects.filter(
                password_entry=entry,
                requester=user,
                status='approved',
                expires_at__gt=timezone.now()
            ).first()

            if not (entry.user_id == user.id or active_request or user.is_admin):
                return Response(
                    {'error': 'You do not have permission to view this password. Please request access.'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Log access attempt
            try:
                PasswordViewLog.objects.create(password_entry=entry, viewer=user)
            except Exception:
                pass

            serializer = PasswordEntryDetailSerializer(entry, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)

        # ✅ CASE 2: List all entries (everyone can see)
        entries = PasswordEntry.objects.all()
        serializer = PasswordEntrySerializer(entries, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request, pk=None):
        """Create a new password entry for the current user."""
        serializer = PasswordEntrySerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
    

"""
APIViews replacement for PasswordRequestViewSet actions.

Endpoints implemented here should be wired in urls.py. They provide the
same behavior as the previous ViewSet: list/create, verify_otp, review,
pending, and check_status.
"""

from rest_framework.views import APIView


class PasswordRequestListCreateAPIView(APIView):
    """List and create password requests.

    GET: list requests (admins see all, regular users see their own)
    POST: create a new request (same validation as previous viewset)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_admin:
            qs = PasswordRequest.objects.all()
        else:
            qs = PasswordRequest.objects.filter(requester=request.user)
        serializer = PasswordRequestSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = PasswordRequestCreateSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Check duplicate pending request
        password_entry_id = serializer.validated_data['password_entry'].id
        existing_request = PasswordRequest.objects.filter(
            password_entry_id=password_entry_id,
            requester=request.user,
            status='pending'
        ).first()
        if existing_request:
            return Response({'error': 'You already have a pending request for this password entry'}, status=status.HTTP_400_BAD_REQUEST)

        # create
        password_request = serializer.save()
        # Generate and send OTP to admins
        otp = password_request.generate_otp()

        return Response({**PasswordRequestSerializer(password_request).data, 'message': 'Request created. OTP has been sent to administrators.'}, status=status.HTTP_201_CREATED)



# class PasswordEntryViewPasswordAPIView(APIView):
#     """Allow either the owner or an approved requester to view decrypted password."""
#     permission_classes = [IsAuthenticated]

    # def get(self, request, pk):
    #     # Step 1 — Find password entry
    #     entry = PasswordEntry.objects.select_related('user').filter(pk=pk).first()
    #     if not entry:
    #         return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

    #     # Step 2 — Check if user is entry owner OR has an approved request
    #     active_request = PasswordRequest.objects.filter(
    #         password_entry=entry,
    #         requester=request.user,
    #         status='approved',
    #         expires_at__gt=timezone.now()
    #     ).first()

    #     if not (entry.user_id == request.user.id or active_request):
    #         return Response({'error': 'You do not have permission to view this password.'},
    #                         status=status.HTTP_403_FORBIDDEN)

    #     # Step 3 — Ensure approved request is still active (not expired)
    #     if active_request and active_request.expires_at <= timezone.now():
    #         active_request.status = 'expired'
    #         active_request.save(update_fields=['status'])
    #         return Response({'error': 'Your approval has expired.'}, status=status.HTTP_403_FORBIDDEN)

    #     # Step 4 — Log view for auditing
    #     try:
    #         PasswordViewLog.objects.create(password_entry=entry, viewer=request.user)
    #     except Exception:
    #         pass  # don’t block if logging fails

    #     # Step 5 — Return decrypted data
    #     serializer = PasswordEntryDetailSerializer(entry)
    #     return Response(serializer.data, status=status.HTTP_200_OK)
# from utils import decrypt_password



class PasswordEntryViewPasswordAPIView(APIView):
    """Allow either the owner or an approved requester to view decrypted password."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        # Step 1: Load password entry
        entry = PasswordEntry.objects.filter(pk=pk).first()
        if not entry:
            return Response({'error': 'Not found'}, status=404)

        # Step 2: Check approved request for THIS user only
        active_request = PasswordRequest.objects.filter(
            password_entry=entry,
            requester=request.user,
            status='approved',
            expires_at__gt=timezone.now()
        ).first()

        if not active_request:
            return Response(
                {'error': 'You are not authorized to view this password.'},
                status=403
            )

        # Step 3: Expired?
        if active_request.expires_at <= timezone.now():
            active_request.status = 'expired'
            active_request.save(update_fields=['status'])
            return Response({'error': 'Your approval has expired.'}, status=403)

        # Step 4: Decrypt password
        decrypted_password = decrypt_password(entry.encrypted_password)

        # Step 5: Return only required data
        return Response({
            "site": entry.site_name,
            "username": entry.username,
            "password": decrypted_password,
            "message": "Password access granted"
        }, status=200)

class PasswordRequestVerifyOTPAPIView(APIView):
    """
    Verify OTP sent to admin for a specific PasswordRequest.
    This is called by an admin after they receive the OTP email.
    """

    


    def post(self, request, pk):
        otp = request.data.get("otp")
        if not otp:
            return Response({'error': 'OTP is required'}, status=400)

        try:
            password_request = PasswordRequest.objects.get(pk=pk)
        except PasswordRequest.DoesNotExist:
            return Response({'error': 'Password request not found'}, status=404)

        # ❗ Only the requester can verify the OTP
        if password_request.requester != request.user:
            return Response(
                {'error': 'You are not allowed to verify this OTP.'},
                status=403
            )

        # Status must be otp_sent
        if password_request.status != 'otp_sent':
            return Response({'error': 'This request is not awaiting OTP verification'}, status=400)

        # OTP expiration
        if password_request.otp_expires_at and timezone.now() > password_request.otp_expires_at:
            password_request.status = 'expired'
            password_request.save(update_fields=['status'])
            return Response({'error': 'OTP has expired. Please request again.'}, status=400)

        # OTP match
        if password_request.otp != otp:
            return Response({'error': 'Invalid OTP'}, status=400)

        # APPROVE REQUEST
        password_request.status = 'approved'
        password_request.reviewed_at = timezone.now()
        password_request.expires_at = timezone.now() + timezone.timedelta(minutes=10)
        password_request.save(update_fields=['status', 'reviewed_at', 'expires_at'])

        return Response({
            'message': 'OTP verified successfully. Request approved.',
            'expires_at': password_request.expires_at
        }, status=200)



class PasswordRequestReviewAPIView(APIView):
    """Admin endpoint to reject a request or resend OTP."""
    permission_classes = [IsAdmin]

    def post(self, request, pk=None):
        try:
            password_request = PasswordRequest.objects.get(pk=pk)
        except PasswordRequest.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        if password_request.status not in ['pending', 'otp_sent']:
            return Response({'error': 'This request has already been reviewed'}, status=status.HTTP_400_BAD_REQUEST)

        action_type = request.data.get('action')
        if action_type == 'reject':
            notes = request.data.get('notes', '')
            password_request.reject(request.user, notes)
            message = 'Request rejected.'
        elif action_type == 'resend_otp':
            password_request.generate_otp()
            message = 'OTP has been resent to administrators.'
        else:
            return Response({'error': 'Invalid action. Use "reject" or "resend_otp"'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': message, 'request': PasswordRequestSerializer(password_request).data})


class PasswordRequestPendingAPIView(APIView):
    """Return pending requests (admins get all, users get their own)."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_admin:
            pending_requests = PasswordRequest.objects.filter(status='pending')
        else:
            pending_requests = PasswordRequest.objects.filter(requester=request.user, status='pending')
        serializer = PasswordRequestSerializer(pending_requests, many=True)
        return Response(serializer.data)


class PasswordRequestCheckStatusAPIView(APIView):
    """Check current status of a password request."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        try:
            password_request = PasswordRequest.objects.get(pk=pk)
        except PasswordRequest.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        # Update status if expired
        password_request.check_expiration()
        password_request.refresh_from_db()
        serializer = PasswordRequestSerializer(password_request)
        return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAdmin])
def admin_dashboard(request):
    """Get admin dashboard statistics."""
    pending_count = PasswordRequest.objects.filter(status='pending').count()
    total_users = User.objects.count()
    total_passwords = PasswordEntry.objects.count()
    total_requests = PasswordRequest.objects.count()
    
    return Response({
        'pending_requests': pending_count,
        'total_users': total_users,
        'total_passwords': total_passwords,
        'total_requests': total_requests,
    })
