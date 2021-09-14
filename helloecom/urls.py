"""myecom URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
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
from helloecom.settings import STATIC_URL, STATIC_ROOT
from django.conf.urls.static import static
from utils.services.upload_service import UploadService

urlpatterns = [
                  path('api/admin/', admin.site.urls),
                  path('api/auth/', include('myapps.authentication.urls'), name='authentication'),
                  path('api/upload/', UploadService.as_view(), name='upload')
              ] + static(STATIC_URL, document_root=STATIC_ROOT)
