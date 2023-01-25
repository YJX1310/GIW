from django.contrib import admin

# Register your models here.

# Mostrar las preguntas y las respuestas en la interfaz de administración (ver, crear, editar, borrar)
from .models import Pregunta, Respuesta


admin.site.register(Pregunta)
admin.site.register(Respuesta)