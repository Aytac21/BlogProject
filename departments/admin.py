from django.contrib import admin
from .models import Department
from modeltranslation.admin import TranslationAdmin
from embed_video.admin import AdminVideoMixin


@admin.register(Department)
class DepartmentAdmin(TranslationAdmin):
    list_display = ("name",)

    class Media:

        group_fieldsets = True

        js = (
            'http://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js',
            'http://ajax.googleapis.com/ajax/libs/jqueryui/1.10.2/jquery-ui.min.js',
            'modeltranslation/js/tabbed_translation_fields.js',
        )
        css = {
            'screen': ('modeltranslation/css/tabbed_translation_fields.css',),
        }
