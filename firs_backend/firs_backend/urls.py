"""
URL configuration for firs_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from api.views import (
    login_view, logout_view, bulk_import, IncidentViewSet,
    forgot_password, verify_otp, reset_password,
)

router = DefaultRouter()
router.register(r'incidents', IncidentViewSet, basename='incident')

urlpatterns = [
    path('admin/',                  admin.site.urls),
    path('api/login/',              login_view),
    path('api/logout/',             logout_view),
    path('api/incidents/bulk/',     bulk_import),
    path('api/',                    include(router.urls)),

    # Password reset OTP flow
    path('api/forgot-password/',    forgot_password),
    path('api/verify-otp/',         verify_otp),
    path('api/reset-password/',     reset_password),
]
