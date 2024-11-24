from rest_framework import serializers
from .models import Employee
from django.utils.translation import gettext_lazy as _


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = '__all__'