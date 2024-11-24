from unicodedata import name
from django.urls import path
from . import views

from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('gettoken/', TokenObtainPairView.as_view(), name='gettoken'),
    path('login/', views.LoginUserView.as_view(), name='login-user'),
    path('verify-email/', views.VerifyUserEmail.as_view(), name='verify'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/', views.PasswordResetRequestView.as_view(),
         name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         views.PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    path('logout/', views.LogoutApiView.as_view(), name='logout'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', views.ResendOtpView.as_view(), name='resend-otp'),
    path('set-new-password/', views.SetNewPasswordView.as_view(),
         name='set-new-password'),
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('update_user/<int:pk>/', views.UpdateUserView.as_view(), name='update_user'),
    path('user/<int:id>/', views.UserDetailView.as_view(), name='detail_user'),
    path('delete_user/<int:user_id>/',
         views.DeleteUserView.as_view(), name='delete_user'),
]
