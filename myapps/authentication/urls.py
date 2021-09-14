from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from myapps.authentication.views import SignUpApi, VerifyEmailApi, SocialLoginApi, EmailLoginApi, UserProfileApi, \
    GetOtpApi, OrganizationApi, UserLocationApi, StoreApi, VerifyOtpApi


urlpatterns = [
    path('register/', SignUpApi.as_view()),
    path('login/', EmailLoginApi.as_view()),
    path('social-login/', SocialLoginApi.as_view()),
    path('get-otp/', GetOtpApi.as_view()),
    path('verify-otp/', VerifyOtpApi.as_view()),
    path('user-profile/', UserProfileApi.as_view()),
    path('organization/', OrganizationApi.as_view()),
    path('store/', StoreApi.as_view()),
    path('user-location/', UserLocationApi.as_view()),
    path('verify-account/<uid>/<token>/', VerifyEmailApi.as_view()),
]
