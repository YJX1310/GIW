from django.db import models
from django.conf import settings
from django.utils.html import escape

# Create your models here.
class Pregunta(models.Model):
    #Clave primaria
    id = models.BigAutoField(primary_key=True, null=False)

    #Titulo de maximo 250 caracteres
    titulo = models.CharField(max_length=250, null=False)

    #Texto de maximo 5000 caracteres
    texto = models.CharField(max_length=5000, null=False)

    #Al crear una pregunta se asigna la fecha actual
    fecha = models.DateTimeField(auto_now_add=True, null=False)

    #Referencia a un usuario del sistema. Si se elimina el usuario, todas las preguntas asociadas a dicho usuario se borran
    autor = models.ForeignKey(settings.AUTH_USER_MODEL, null=False, on_delete=models.CASCADE)

    def clean(self):
        '''Escapa datos'''
        self.titulo = escape(self.titulo)
        self.texto = escape(self.texto)
    
    #Devuelve el numero de respuestas de la pregunta
    def num_respuestas(self):
        return len(Respuesta.objects.filter(pregunta__exact=self))

    def __str__(self):
        """Para mostrar detalles en la interfaz admin"""
        return f"Pregunta (Titulo: {self.titulo}, Texto: {self.texto}, Autor: {self.autor})"

class Respuesta(models.Model):
    #Clave primaria
    id = models.BigAutoField(primary_key=True, null=False)

    #Texto de maximo 5000 caracteres
    texto = models.CharField(max_length=5000, null=False)

    #Al crear una pregunta se asigna la fecha actual
    fecha = models.DateTimeField(auto_now_add=True, null=False)

    #Referencia a un usuario del sistema. Si se elimina el usuario, todas las respuestas de ese usuario se borran
    autor = models.ForeignKey(settings.AUTH_USER_MODEL, null=False, on_delete=models.CASCADE)

    #Referencia a una pregunta. Si se elimina la pregunta, todas las respuestas de esa pregunta se borran
    pregunta = models.ForeignKey(Pregunta, null=False, on_delete=models.CASCADE)

    def clean(self):
        '''Escapa datos'''
        self.texto = escape(self.texto)

    def __str__(self):
        """Para mostrar detalles en la interfaz admin"""
        return f"Respuesta ({self.pregunta}, Respuesta de la pregunta: {self.texto}, Autor: {self.autor})"