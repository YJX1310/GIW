"""
GIW 2022-23
Práctica Persistencia (ODM)
Grupo 04
Autores: PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO VILLEGAS DE MIQUEL y YUEJIE XU

PETAR KONSTANTINOV IVANOV, JORGE SAN FRUTOS IGLESIAS, IGNACIO 
VILLEGAS DE MIQUEL y YUEJIE XU declaramos que esta solución es fruto exclusivamente
de nuestro trabajo personal. No hemos sido ayudados por ninguna otra persona ni hemos
obtenido la solución de fuentes externas, y tampoco hemos compartido nuestra solución
con nadie. Declaramos además que no hemos realizado de manera deshonesta ninguna otra
actividad que pueda mejorar nuestros resultados ni perjudicar los resultados de los demás.
"""

from mongoengine.document import *
from mongoengine.fields import *
from mongoengine.errors import *
from mongoengine import NULLIFY

class Producto(Document):
    codigo_barras = StringField(required = True, primary_key = True, regex = "^[0-9]{13}$")
    nombre = StringField(required = True, regex = "[A-z ]{2,}")
    categoria_principal = IntField(required = True, min_value = 0)
    categorias_secundarias = ListField(IntField(min_value = 0))

    #Fuente https://es.wikipedia.org/wiki/European_Article_Number#Python_3
    def ean_checksum(self, code):
        digits = [int(i) for i in reversed(code)]
        return (10 - (3 * sum(digits[0::2]) + (sum(digits[1::2])))) % 10

    def clean(self):
        self.validate(clean = False)

        #Comprobar el digito de control del codigo de barras
        if self.ean_checksum(self.codigo_barras[:12]) != int(self.codigo_barras[12]): 
            raise ValidationError("Producto: CODIGO_BARRAS -> DIGITO DE CONTROL ERRONEO")

        #Comprobar que el numero de la categoria principal es el primer numero de la lista de las categorias secundarias en caso de que existiese la lista
        if len(self.categorias_secundarias) > 0 and self.categorias_secundarias[0] != self.categoria_principal: 
            raise ValidationError("Producto: CATEGORIAS_SECUNDARIASA -> EL PRIMER ELEMENTO DE LA CATEGORIA SECUNDARIA NO ES LA CATEGORIA PRINCIPAL")

class Linea(EmbeddedDocument):
    num_items = IntField(required = True, min_value = 0)
    precio_item = FloatField(required = True, min_value = 0)
    nombre_item = StringField(required = True, regex = "[A-z ]{2,}")
    total = FloatField(required = True, min_value = 0)
    ref = ReferenceField(Producto, required = True)

    def clean(self):
        self.validate(clean = False)

        #Comprobar si el precio total de la linea coincide con la cantidad de productos comprados y su precio
        if self.total != (self.num_items * self.precio_item):
            raise ValidationError("Linea: TOTAL -> EL PRECIO TOTAL ESTA MAL CALCULADO")

        #Comprobar que el nombre de producto de la linea coincide con la referencia
        if self.nombre_item != self.ref.nombre:
            raise ValidationError("Linea: NOMBRE_ITEM -> EL NOMBRE ES DISTINTO")

class Pedido(Document):
    total = FloatField(min_value = 0, required = True)
    fecha = ComplexDateTimeField(required = True)
    lineas = ListField(EmbeddedDocumentField(Linea), required = True)

    def clean(self):
        self.validate(clean = False)
        suma = 0
        productos = list()

        #Recorrer todas las lineas del pedido
        for i in self.lineas:
            suma += i.total

            #Comprueba si hay dos lineas asociadas al mismo producto
            if i.ref not in productos:
                productos.append(i.ref)
            else:
                raise ValidationError("Pedido: LINEAS -> TIENE DOS LINEAS DIFERENTES QUE SE ASOCIA A UN MISMO PRODUCTO")
        
        #Comprueba si el precio total coincide con la suma total de todas sus lineas
        if self.total != suma:
            raise ValidationError("Pedido: TOTAL -> EL PRECIO TOTAL DE UN PEDIDO NO ES LA SUMA DE LOS PRECIOS DE TODAS SU LINEAS")

class Tarjeta(EmbeddedDocument):
    nombre = StringField(required = True, min_length = 2)
    numero = StringField(required = True, regex = "^[0-9]{16}$")
    mes = StringField(required = True, regex = "^[0-9]{2}$")
    año = StringField(required = True, regex = "^[0-9]{2}$")
    ccv = StringField(required = True, regex = "^[0-9]{3}$")

    def clean(self):
        self.validate(clean = False)
        try:
            #Comprueba si el mes tiene un formato correcto
            if int(self.mes) > 12 or int(self.mes) < 1:
                raise ValidationError("Tarjeta: EL MES TIENE QUE SER [1,12]")
        except:
            raise ValidationError("Tarjeta: MES -> TIENE QUE SER NUMEROS")

class Usuario(Document):
    dni = StringField(required = True, primary_key = True, regex = "[0-9]{8}[A-Z]")
    nombre = StringField(required = True, min_length = 2)
    apellido1 = StringField(required = True, min_length = 2)
    apellido2 = StringField()
    f_nac = DateTimeField(required = True, min_length = 10, max_length = 10)
    tarjetas = ListField(EmbeddedDocumentField(Tarjeta))
    pedidos = ListField(ReferenceField(Pedido, reverse_delete_rule=NULLIFY))

    def clean(self):
        self.validate(clean = False)
        digito_control = "TRWAGMYFPDXBNJZSQVHLCKE"
        
        #Comprueba si el formato de DNI es correcto
        if self.dni[8] != digito_control[int(self.dni[:8]) % 23]:
            raise ValidationError("Usuario: DNI -> DIGITO DE CONTROL ERRONEO")