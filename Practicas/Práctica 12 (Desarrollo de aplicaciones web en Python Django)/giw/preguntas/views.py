from django.shortcuts import render, redirect, reverse, get_object_or_404
from django.http import HttpResponseBadRequest
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.core.exceptions import ValidationError

from .models import Pregunta, Respuesta
from .forms import LoginForm, NewQuestionForm, NewAnswerForm
# Create your views here.

@login_required(login_url='preguntas:login')
def indexPost(request):
    # Carga el formulario desde los datos de la petición y lo valida
    form = NewQuestionForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(f"Error en los datos del formulario: {form.errors}")
    
    #Toma los datos limpios del formulario
    titulo = form.cleaned_data['titulo']
    texto = form.cleaned_data['texto']

    #Crea un objeto ORM a partir de los datos limpios del formulario y lo salva en la BD
    p = Pregunta(titulo=titulo, texto=texto, autor=request.user)
    try:
        p.full_clean()
        p.save()
    except ValidationError as e:
        return HttpResponseBadRequest("Pregunta mal formada")
    return redirect(reverse('preguntas:index'))

@require_http_methods(["GET", "POST"])
def index(request):
    if request.method == "GET":
        #Muestra todas las preguntas de mas recientes a mas antiguas
        form = NewQuestionForm()
        preguntas = Pregunta.objects.order_by('-fecha')
        return render(request, "preguntas.html", {'preguntas':preguntas, 'NewQuestionForm':form})

    if request.method == "POST":
        #Añade una pregunta
        return indexPost(request)
        
@require_http_methods(["GET", "POST"])
def loginfunct(request):
    """Muestra el formulario (GET) o recibe los datos y realiza la autenticacion (POST)"""
    if request.method == "GET":
        form = LoginForm()
        return render(request, "login.html", {'login_form': form})

    form = LoginForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(f"Error en los datos del formulario: {form.errors}")

    #Toma los datos limpios del formulario
    username = form.cleaned_data['username']
    password = form.cleaned_data['password']

    #Realiza la autenticación
    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)  # Registra el usuario en la sesión
        return redirect(reverse('preguntas:index'))
    else:
        return render(request, "loginError.html")

@login_required(login_url='preguntas:login')
@require_GET
def logoutfunct(request):
    """Elimina al usuario de la sesión actual"""
    logout(request)  # Elimina el usuario de la sesión
    return redirect(reverse('preguntas:index'))

@login_required(login_url='preguntas:login')
@require_GET
def preguntasN(request, id):
    """Muestra la pregunta N y sus respuestas"""
    form = NewAnswerForm()

    #Obtener la pregunta N, en caso de que no exista genera un error 404
    pregunta = get_object_or_404(Pregunta, pk=id)

    #Ordenar la respuestas de lo mas reciente a lo mas antiguo
    respuestas = Respuesta.objects.filter(pregunta__exact=pregunta).order_by('-fecha')
    return render(request, "pregunta.html", {'pregunta':pregunta, 'respuestas':respuestas, 'NewAnswerForm':form})

@login_required(login_url='preguntas:login')
@require_POST
def respuestaN(request, id):
    """Recibe datos del formulario y realiza la publicacion de una respuesta asociada a la pregunta N (POST)"""
    #Obtener la pregunta N, en caso de que no exista genera un error 404
    pregunta = get_object_or_404(Pregunta, pk=id)

    # Carga el formulario desde los datos de la petición y lo valida
    form = NewAnswerForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(f"Error en los datos del formulario: {form.errors}")

    #Toma los datos limpios del formulario
    texto = form.cleaned_data['texto']

    #Crea un objeto ORM a partir de los datos limpios del formulario y lo salva en la BD
    r = Respuesta(texto=texto, autor=request.user, pregunta=pregunta)
    try:
        r.full_clean()
        r.save()
    except ValidationError as e:
        return HttpResponseBadRequest("Respuesta mal formada")
    return redirect(reverse('preguntas:pregunta', args=(id,)))