# -*- coding: utf-8 -*-

#
# CABECERA AQUI
#
# GIW 2022-23
# Práctica sobre Autenticación y TOTP
# Grupo 04
# Autores: PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO VILLEGAS DE MIQUEL y YUEJIE XU
# 
# PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO 
# VILLEGAS DE MIQUEL y YUEJIE XU declaramos que esta solución es fruto exclusivamente
# de nuestro trabajo personal. No hemos sido ayudados por ninguna otra persona ni hemos
# obtenido la solución de fuentes externas, y tampoco hemos compartido nuestra solución
# con nadie. Declaramos además que no hemos realizado de manera deshonesta ninguna otra
# actividad que pueda mejorar nuestros resultados ni perjudicar los resultados de los demás.


from flask import Flask, request, session, render_template
from mongoengine import connect, Document, StringField, EmailField
# Resto de importaciones
from argon2 import PasswordHasher
import pyotp
import qrcode
import base64


app = Flask(__name__)
connect('giw_auth')


# Clase para almacenar usuarios usando mongoengine
class User(Document):
    user_id = StringField(primary_key=True)
    full_name = StringField(min_length=2, max_length=50, required=True)
    country = StringField(min_length=2, max_length=50, required=True)
    email = EmailField(required=True)
    passwd = StringField(required=True)
    totp_secret = StringField(required=False)

##############
# APARTADO 1 #
##############

# 
# Explicación detallada del mecanismo escogido para el almacenamiento de
# contraseñas, explicando razonadamente por qué es seguro
# 
# Hemos utilizado una funcion de derivacion de claves denominado Argon2, 
# a parte de cumplir los requerimientos de los algoritmos de Hash Criptograficos,
# es decir el hash se generan a partir de la sal,
# generan hashes resistentes a ataques con fuerza bruta centrada en un unico usuario.
# Ademas de la sal tiene la memoria requirida, el tiempo de ejecucion y el grado de paralelismo como parametros que fortalece la seguridad

@app.route('/signup', methods=['POST'])
def signup():
    #Obtener datos del formulario
    id = request.form['nickname']
    contraseña = request.form['password']
    contraseña2 = request.form['password2']

    #Comprobar si las contraseñas coinciden
    if contraseña != contraseña2:
        #Si las contraseñas son distintas, muestra -> Las contraseñas no coinciden
        return render_template('plantilla.html', mensaje="Las contraseñas no coinciden")
    
    #Comprobar si el id existe
    if User.objects(user_id=id).first() is not None:
        #Si el usuario ya existe, muestra -> El usuario ya existe
        return render_template('plantilla.html', mensaje="El usuario ya existe")

    #Crea y guarda el usuario con contraseña cifrada en la BD
    usuario = User(user_id=id, full_name=request.form['full_name'], country=request.form['country'], email=request.form['email'], passwd=PasswordHasher().hash(contraseña))
    usuario.save()

    #Muestra "Bienvenido usuario <name>"
    return render_template('saludos.html', name=usuario.full_name) 

@app.route('/change_password', methods=['POST'])
def change_password():
    #Obtener datos del formulario
    id = request.form['nickname']
    old = request.form['old_password']
    new = request.form['new_password']

    #Buscar un usuario con user_id igual a id
    usuario = User.objects(user_id=id).first()
    try:
        if usuario is None:
            #Si el usuario no existe, muestra "Usuario o contraseña incorrectos"
            return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")
        PasswordHasher().verify(usuario.passwd, old)
    except:
        #Si la contraseña es incorrecta, muestra "Usuario o contraseña incorrectos"
        return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")

    #Reemplaza la contraseña antigua por la nueva
    usuario.passwd = PasswordHasher().hash(new)
    usuario.save()

    #Muestra "La contraseña del usuario <nickname> ha sido modificada"
    return render_template('contraseñaModificada.html', nickname=id)
 
           
@app.route('/login', methods=['POST'])
def login():
    #Obtener datos del formulario
    id = request.form['nickname']
    contraseña = request.form['password']

    #Buscar User con user_id igual a id
    usuario = User.objects(user_id=id).first()
    try:
        if usuario is None:
            #Si el usuario no existe, muestra "Usuario o contraseña incorrectos"
            return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")
        PasswordHasher().verify(usuario.passwd, contraseña)
    except:
        #Si la contraseña es incorrecta, muestra "Usuario o contraseña incorrectos"
        return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")

    #Muestra "Bienvenido usuario <name>"
    return render_template('saludos.html', name=usuario.full_name) 

##############
# APARTADO 2 #
##############

# 
# Explicación detallada de cómo se genera la semilla aleatoria, cómo se construye
# la URL de registro en Google Authenticator y cómo se genera el código QR
# 
# 1.Generacion de la semilla aleatoria mediante una funcion denominada 'random_base32()' procedente de la biblioteca pyotp
# 2.Generacion de la URL de registro en Google Authenticator mediante la funcion 'pyotp.utils.build_uri' procedentes de la libreria pyotp.
#   Esta funcion requiere el secreto del usuario, un id del usuario y un emisor (GIW). Sin embargo hemos decidido utilizar el algoritmo SHA256
#   ya que el algoritmo por defecto SHA1 no es segura, se han encontrado formas de calcular colisiones.
# 3.Con 'pyotp.utils.build_uri' y 'qrcode.make' obtenemos el codigo QR que sera guardada localmente para posteriormente mostrarlo al usuario


@app.route('/signup_totp', methods=['POST'])
def signup_totp():
    #Obtener datos del formulario
    id = request.form['nickname']
    contraseña = request.form['password']
    contraseña2 = request.form['password2']

    #Comprobar si las contraseñas coinciden
    if contraseña != contraseña2:
        #Si las contraseñas son distintas, muestra -> Las contraseñas no coinciden
        return render_template('plantilla.html', mensaje="Las contraseñas no coinciden")
    
    #Comprobar si el id existe
    if User.objects(user_id=id).first() is not None:
        #Si el usuario ya existe, muestra -> El usuario ya existe
        return render_template('plantilla.html', mensaje="El usuario ya existe")

    #Crea y guarda el usuario con una contraseña cifrada y un secreto aleatorio en la BD
    usuario = User(user_id=id, full_name=request.form['full_name'], country=request.form['country'], email=request.form['email'], passwd=PasswordHasher().hash(contraseña), totp_secret=pyotp.random_base32())
    usuario.save()

    #Generacion y almacenamiento del QR
    img = qrcode.make(pyotp.utils.build_uri(secret=usuario.totp_secret, name=usuario.user_id, issuer="GIW", algorithm="SHA256"))
    img.save(usuario.user_id + ".png", "PNG")
    img = open(usuario.user_id + ".png", "rb")

    #Muestra el nombre, el secreto y el QR
    return render_template('qr.html', name=usuario.full_name, secret=usuario.totp_secret, qr="data:image/png;base64," + bytes.decode(base64.standard_b64encode(img.read())))
        

@app.route('/login_totp', methods=['POST'])
def login_totp():
    #Obtener datos del formulario
    id = request.form['nickname']
    contraseña = request.form['password']
    totp = request.form['totp']

    #Buscar un usuario con user_id igual a id
    usuario = User.objects(user_id=id).first()
    try:
        if usuario is None or not pyotp.TOTP(usuario.totp_secret).verify(totp):
            #Si el usuario no existe o que el totp es erroneo, muestra "Usuario o contraseña incorrectos"  
            return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")
        PasswordHasher().verify(usuario.passwd, contraseña)
    except:
        #Si la contraseña es incorrecta, muestra "Usuario o contraseña incorrectos"
        return render_template('plantilla.html', mensaje="Usuario o contraseña incorrectos")

    #Muestra "Bienvenido usuario <name>"
    return render_template('saludos.html', name=usuario.full_name) 

class FlaskConfig:
    """Configuración de Flask"""
    # Activa depurador y recarga automáticamente
    ENV = 'development'
    DEBUG = True
    TEST = True
    # Imprescindible para usar sesiones
    SECRET_KEY = 'la_asignatura_de_giw'
    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'


if __name__ == '__main__':
    app.config.from_object(FlaskConfig())
    app.run()
