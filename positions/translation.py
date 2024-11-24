from .models import Position
from modeltranslation.translator import TranslationOptions, register


@register(Position)
class ProductTranslationOptions(TranslationOptions):
    fields = ('name')
