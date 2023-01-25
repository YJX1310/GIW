"""
GIW 2022-23
Práctica API REST con Flask
Grupo 04
Autores: PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO VILLEGAS DE MIQUEL y YUEJIE XU

PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO 
VILLEGAS DE MIQUEL y YUEJIE XU declaramos que esta solución es fruto exclusivamente
de nuestro trabajo personal. No hemos sido ayudados por ninguna otra persona ni hemos
obtenido la solución de fuentes externas, y tampoco hemos compartido nuestra solución
con nadie. Declaramos además que no hemos realizado de manera deshonesta ninguna otra
actividad que pueda mejorar nuestros resultados ni perjudicar los resultados de los demás.
"""

from flask import Flask, request, session, render_template

app = Flask(__name__)

#En todos los momentos trabajamos con la lista de asignaturas
asignaturas = [{"id": 1, "nombre": "GIW", "numero_alumnos": 80, "horario": [{"dia": "lunes", "hora_inicio": 9, "hora_final" : 11}]},
               {"id": 2, "nombre": "ASOR", "numero_alumnos": 70, "horario": [{"dia": "martes", "hora_inicio": 9, "hora_final" : 11}]},
               {"id": 3, "nombre": "AC", "numero_alumnos": 75, "horario": [{"dia": "miercoles", "hora_inicio": 9, "hora_final" : 11}]}]

#Mostrar el id de cada asignatura
def mostrarID(lista):
    result = list()
    for i in lista:
        result.append("/asignaturas/" + str(i['id']))
    return result

#Realizar patch
def patch(request_data, pos):
    #Iterar sobre los keys de la asignatura
    for i in asignaturas[pos].keys():
        #Si la key es igual que el primer dato del request_data
        if i == list(request_data.keys())[0]:
            #Obtener el dato a reemplazar
            dato = request_data.get(i)

            #Si la key es nombre
            if(str(i) == "nombre"):
                #Comprobar si el formato es correcto
                if (dato is None) or (type(dato) is not str):
                    #Si es incorrecto, devuelve 400 BAD REQUEST
                    return '', 400

                #Reemplazar el nombre de la asignatura por el "dato"
                asignaturas[pos]['nombre'] = dato

            #Si la key es numero_alumnos
            elif(str(i) == "numero_alumnos"):
                #Comprobar si el formato es correcto
                if (dato is None) or (type(dato) is not int):
                    #Si es incorrecto, devuelve 400 BAD REQUEST
                    return '', 400

                #Reemplazar el numero de alumnos de la asignatura por el "dato"
                asignaturas[pos]['numero_alumnos'] = dato

            #Si la key es horario
            elif(str(i) == "horario"):
                #Comprobar si el formato es correcto
                if (dato is None) or (type(dato) is not list):
                    #Si es incorrecto, devuelve 400 BAD REQUEST
                    return '', 400
                else:
                    #Comprobar si el formato de todos los horarios es correcto
                    for i in dato:
                        dia = i.get('dia')
                        hora_inicio = i.get('hora_inicio')
                        hora_final = i.get('hora_final')
                        if (dia is None) or (type(dia) is not str) or (hora_inicio is None) or (type(hora_inicio) is not int) or (hora_final is None) or (type(hora_final) is not int):
                            #Si es incorrecto, devuelve 400 BAD REQUEST
                            return '', 400
                    
                    #Reemplazar el horario de la asignatura por el "dato"    
                    asignaturas[pos]['horario'] = dato

            #Si no es ninguno de los anteriores entonces no es valido. Asumimos que no se puede actualizar el id
            else:
                return '', 400
    
    #Es un JSON valido entonces devuelve 200 OK
    return "",200        

#Comprobar si alguno de las variables es nulo o que el tipo de la variable es incorrecto 
def comprobarFormatoAsig(size, nombre, numero_alumno, horario):
    if (size != 3) or (nombre is None) or (numero_alumno is None) or (horario is None) or (type(nombre) is not str) or (type(numero_alumno) is not int) or (type(horario) is not list):
        return False
    else:
        #Comprobar si el formato de todos los horarios es correcto
        for i in horario:
            dia = i.get('dia')
            hora_inicio = i.get('hora_inicio')
            hora_final = i.get('hora_final')
            if (dia is None) or (hora_inicio is None) or (hora_final is None) or (type(dia) is not str) or (type(hora_inicio) is not int) or (type(hora_final) is not int):
                return False
    return True

#Apartado 2.1
@app.route('/asignaturas', methods=['GET', 'DELETE', 'POST'])
def gestionAsignaturas():
    #Si el metodo es GET
    if request.method == 'GET':
        #Procesar los parametros de peticion
        page = request.args.get('page')
        per_page = request.args.get('per_page')
        num = request.args.get('alumnos_gte')

        #Si page y per_page no es nulo
        if (page is not None and per_page is not None):
            try:
                #Comprobar el formato
                page = int(page)
                per_page = int(per_page)
                
                #Calcular el inicio y el final del tramo
                inicio = (page - 1) * per_page
                fin = page * per_page
                lista = list()

                #Si alumnos_gte no es nulo
                if(num is not None):
                    #Comprobar el formato
                    num = int(num)

                    #Obtener aquellas asignaturas donde numero de alumnos es >= que alumnos_gte y obtener el tramo de las asignaturas segun inicio y fin
                    lista = list(filter(lambda elem: elem['numero_alumnos'] >= num, asignaturas))[inicio:fin]
                else:
                    #En caso contrario, obtener aquellas asignaturas desde 'inicio' hasta 'fin'
                    lista = asignaturas[inicio:fin]
                return {"asignaturas": mostrarID(lista)}, 200 if len(lista) == len(asignaturas) else 206
            except:
                #Si no es correcto, lanza 400 BAD REQUEST
                return '', 400

        #Si solo tiene alumnos_gte
        elif num is not None:
            try:
                #Comprobar el formato
                num = int(num)

                #Obtener aquellas asignaturas donde numero de alumnos es >= que alumnos_gte
                lista = list(filter(lambda elem: elem['numero_alumnos'] >= num, asignaturas))
                return {"asignaturas": mostrarID(lista)}, 200 if len(lista) == len(asignaturas) else 206
            except:
                #Si no es correcto, lanza 400 BAD REQUEST
                return '', 400

        #Si no tiene parametros de peticion
        elif (page is None and per_page is None and num is None):
            return {"asignaturas":mostrarID(asignaturas)}, 200
        
        #Si no es ninguno de los anteriores, devuelve 400 BAD REQUEST
        return '', 400

    #Si el metodo es POST
    elif request.method == 'POST':
        #Obtener los datos del POST
        request_data = request.get_json()
        nombre = request_data.get('nombre')
        numero_alumno = request_data.get('numero_alumnos')
        horario = request_data.get('horario')

        #Comprobar si el formato de la asignatura es correcta
        if comprobarFormatoAsig(len(request_data), nombre, numero_alumno, horario):
            #Asignar un id
            id = 1
            if len(asignaturas) > 0:
                id = asignaturas[-1].get('id') + 1

            #Añadir la asignatura  
            asignaturas.append({"id": id, "nombre": nombre, "numero_alumnos": numero_alumno, "horario": horario})
            return {"id": id}, 201
        else:
            #Si no es correcto, lanza 400 BAD REQUEST
            return '', 400

    #Si el metodo es DELETE
    elif request.method == 'DELETE':
        #Vaciar la lista de asignaturas
        asignaturas.clear()
        return '', 204

#Apartado 2.2
@app.route('/asignaturas/<int:num>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def asignaturaX(num):
    #Buscar la asignatura "num"
    k = 0
    for i in asignaturas:
        if i['id'] == num:
            #Si el metodo es GET
            if request.method == 'GET':
                return i, 200

            #Si el metodo es PUT
            elif request.method == 'PUT':
                #Obtener los datos del POST
                request_data = request.get_json()
                nombre = request_data.get('nombre')
                numero_alumno = request_data.get('numero_alumnos')
                horario = request_data.get('horario')

                #Comprobar si el formato de la asignatura es correcta
                if comprobarFormatoAsig(len(request_data), nombre, numero_alumno, horario):
                    #Reemplazar la asignatura
                    asignaturas[k] = {"id": asignaturas[k].get('id'), "nombre": nombre, "numero_alumnos": numero_alumno, "horario": horario}
                    return '', 200
                else:
                    #Si no es correcto, lanza 400 BAD REQUEST
                    return '', 400

            #Si el metodo es DELETE
            elif request.method == 'DELETE':
                #Elimina la asignatura y devuelve 204 NO CONTENT
                asignaturas.pop(k)
                return '', 204

            #Si el metodo es PATCH
            elif request.method == 'PATCH':
                #Reemplazar un campo de la asignatura
                return patch(request.get_json(), k)
        k += 1

    #Si no lo encuentra, devuelve 404 NOT FOUND
    return '', 404

#Apartado 2.3
@app.route('/asignaturas/<int:num>/horario', methods=['GET'])
def horarios(num):
    #Buscar la asignatura "num"
    k = 0
    for i in asignaturas:
        if i['id'] == num:
            #Si el metodo es GET
            if request.method == 'GET':
                #Devuelve el horario de la asignatura y 200 OK
                return {"horario":asignaturas[k].get('horario')}, 200
        k += 1
    #Si no lo encuentra, devuelve 404 NOT FOUND
    return '',404

class FlaskConfig:
    """Configuración de Flask"""
    # Activa depurador y recarga automáticamente
    ENV = 'development'
    DEBUG = True
    TEST = True
    # Imprescindible para usar sesiones
    SECRET_KEY = "giw_clave_secreta"
    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'


if __name__ == '__main__':
    app.config.from_object(FlaskConfig())
    app.run()

