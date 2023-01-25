from django import forms

class LoginForm(forms.Form):
    """Formulario para autenticar usuarios"""
    username = forms.CharField(label='Nombre de usuario', max_length=100)
    password = forms.CharField(label='Contraseña', max_length=100, widget=forms.PasswordInput)

class NewQuestionForm(forms.Form):
    """Formulario para añadir una pregunta"""
    titulo = forms.CharField(label='Título', max_length=250)
    texto = forms.CharField(label='Texto', widget=forms.Textarea, max_length=5000)

class NewAnswerForm(forms.Form):
    """Formulario para añadir una respuesta a una pregunta"""
    texto = forms.CharField(label='Respuesta', widget=forms.Textarea, max_length=5000)