from rest_framework import serializers
from .models import Position
from django.utils.translation import gettext_lazy as _

class PositionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Position
        fields = '__all__'