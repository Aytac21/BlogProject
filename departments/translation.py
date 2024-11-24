from .models import Department
from modeltranslation.translator import TranslationOptions,register

@register(Department)
class ProductTranslationOptions(TranslationOptions):
    field = ('name')