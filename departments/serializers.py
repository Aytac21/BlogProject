from rest_framework import serializers
from .models import Department
from django.utils.translation import gettext_lazy as _


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'