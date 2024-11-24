from .models import Employee
from modeltranslation.translator import TranslationOptions, register


@register(Employee)
class ProductTranslationOptions(TranslationOptions):
    fields = ('department', 'position', 'status')
