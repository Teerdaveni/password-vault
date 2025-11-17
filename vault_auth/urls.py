from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
# from . import LoginAPIView
from . import views
from .views import LoginAPIView
from .views import TestEmail


router = DefaultRouter()
# router.register(r'passwords', views.PasswordEntryAPIView, basename='password')
# Requests are implemented as APIViews now (not a ViewSet)

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.register, name='register'),
    # path('auth/login/', views.login, name='login'),
    path('auth/login/', LoginAPIView.as_view(), name='login'),
    path('auth/logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/profile/', views.user_profile, name='user_profile'),
    
    # Admin endpoints
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),

    path('passwords/', views.PasswordEntryAPIView.as_view(), name='password-list-create'),
    path('passwords/<int:pk>/', views.PasswordEntryAPIView.as_view(), name='password-detail'),

    
    # Requests endpoints (explicit APIView routes)
    path('requests/', views.PasswordRequestListCreateAPIView.as_view(), name='requests_list_create'),
    path('requests/pending/', views.PasswordRequestPendingAPIView.as_view(), name='requests_pending'),
    path('requests/<int:pk>/verify_otp/', views.PasswordRequestVerifyOTPAPIView.as_view(), name='request_verify_otp'),
    path('requests/<int:pk>/review/', views.PasswordRequestReviewAPIView.as_view(), name='request_review'),
    path('requests/<int:pk>/check_status/', views.PasswordRequestCheckStatusAPIView.as_view(), name='request_check_status'),

    # Router endpoints (passwords and other router-registered resources)
    # Explicit route for the view-password action implemented as an APIView
    # (user requested APIViews instead of viewset actions). This ensures
    # the endpoint is available at /api/passwords/<pk>/view-password/.
    path('passwords/<int:pk>/view-password/', views.PasswordEntryViewPasswordAPIView.as_view(), name='password-view-password'),
    path('', include(router.urls)),
    path("test-email/", TestEmail),
     
]
