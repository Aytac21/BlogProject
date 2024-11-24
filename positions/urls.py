from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PositionViewSet

router = DefaultRouter()
router.register(r'', PositionViewSet, basename='position')

urlpatterns = [
    path('positions/', include(router.urls)),
]
