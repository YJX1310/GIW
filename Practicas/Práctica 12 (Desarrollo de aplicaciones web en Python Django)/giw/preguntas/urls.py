from django.urls import path

from . import views

# Imprescindible dar un nombre para crear un namespace y poder referirse a estas rutas como
# opiniones:index, opiniones:login, etc.
app_name = "preguntas"

urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.loginfunct, name='login'),
    path('logout', views.logoutfunct, name='logout'),
    path('<int:id>', views.preguntasN, name='pregunta'),
    path('<int:id>/respuesta', views.respuestaN, name='respuesta')
]
