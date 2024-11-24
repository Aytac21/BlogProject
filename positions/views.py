from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Position
from .serializers import PositionSerializer
from departments.views import IsAdminOrReadOnly

class PositionViewSet(viewsets.ModelViewSet):
    queryset = Position.objects.all()
    serializer_class = PositionSerializer
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]
