# -*- coding: utf-8 -*-
#
# CABECERA AQUI
# GIW 2022-23
# Práctica Autenticacion delegada
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
# Resto de importaciones
import requests


app = Flask(__name__)


# Credenciales. 
# https://developers.google.com/identity/openid-connect/openid-connect#appsetup
# Copiar los valores adecuados.
CLIENT_ID = XXXXXX
CLIENT_SECRET = YYYYYY

REDIRECT_URI = 'http://localhost:5000/token'

# Fichero de descubrimiento para obtener el 'authorization endpoint' y el 
# 'token endpoint'
# https://developers.google.com/identity/openid-connect/openid-connect#authenticatingtheuser
DISCOVERY_DOC = 'https://accounts.google.com/.well-known/openid-configuration'

# token_info endpoint para extraer información de los tokens en depuracion, sin
# descifrar en local
# https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
TOKENINFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo'


@app.route('/login_google', methods=['GET'])
def login_google():
    #Un enlace HTML al punto de autorizacion de Google
    result = requests.get(DISCOVERY_DOC).json().get("authorization_endpoint") + "?client_id=" + CLIENT_ID + "&response_type=code&scope=openid%20email&redirect_uri=" + REDIRECT_URI
    return render_template('plantilla.html', enlace=result)


@app.route('/token', methods=['GET'])
def token():
    #Obtener los tokens
    url =  requests.get(DISCOVERY_DOC).json().get("token_endpoint")
    myobj = {'code': request.args.get("code"), 'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'redirect_uri':REDIRECT_URI, 'grant_type':'authorization_code'}
    x = requests.post(url, data = myobj)

    #Obtener datos del usuario mediante access_token
    access = x.json().get('access_token')
    url = requests.get(DISCOVERY_DOC).json().get("userinfo_endpoint")
    myobj = {'Authorization': 'Bearer ' + access}
    x = requests.post(url, headers = myobj)
    return render_template('hola.html', info=x.json().get('email'))

        
class FlaskConfig:
    '''Configuración de Flask'''
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
