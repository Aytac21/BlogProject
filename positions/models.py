from django.db import models
from departments.models import Department

class Position(models.Model):
    name = models.CharField(max_length=255)
    salary = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    department = models.ForeignKey(
        Department, on_delete=models.CASCADE, related_name='positions')

    def __str__(self):
        return self.name