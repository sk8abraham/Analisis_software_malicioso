#!/usr/bin/python
# -*- coding: utf-8 -*-
#UNAM-CERT
#Manzano Cruz Isaias Abraham

import optparse
import sys
import binascii
import time
from binascii import hexlify
from binascii import unhexlify
"""
def descifra(cadena, llave=None):
    print "archivo; ", cadena
    print "Longitud: ",len(cadena)
    print "llave: ", llave
    cad_nueva = ''
    for i in range(len(cadena)):
        cad_nueva += chr(llave ^ ord(cadena[i]))
    return cad_nueva
"""

def addOptions():
    '''
    Funcion que parsea los datos que se tomen de linea de comandos como opciones para ejecutar el programa
    Devuelve un objeto cuyos atributos son las opciones de ejecucion
    '''
    parser = optparse.OptionParser()
    parser.add_option('-e', '--cifra', dest='cifra', default=None, help='Indica el archivo a cifrar, siempre se debe indicar una llave para cifrar con la opcion -k')
    parser.add_option('-d', '--descifra', dest='descifra', default=None, help='Indica el archivo a descifrar, se puede o no indicar una llave para descifrar')
    parser.add_option('-k', '--key', dest='key', default=None, type = int, help='Indica la llave de 1 byte para cifrar o descifrar')
    opts,args = parser.parse_args()
    return opts


def printError(msg, exit = False):

    '''
    Esta funcion imprime en la salida de error estandar un mensaje
    Recibe:
	msg:	mensaje a imprimir y exit:  exit el cual indica si el el programa termina su ejecucion o no
	exit:	Si es True termina la ejecucion del programa
    '''
    sys.stderr.write('Error:\t%s\n' % msg)
    if exit:
        sys.exit(1)


def check_opts(opts):
    if opts.descifra != None and opts.key != None and opts.cifra == None:
        return 1
    elif opts.descifra != None and opts.key == None and opts.cifra == None:
        return 2
    elif opts.cifra != None and opts.key != None and opts.descifra == None:
        return 3
    else:
        printError('Operacion no valida\nPara ver el funcionamiento de la herramienta, correr con el parametro -h',True)


def lee_archivo(archivo):
    try:
        return open(archivo, 'rb').read()
    except Exception as e:
        printError(e,True)


def cifra_descifra(cadena, llave=None):
    cad_nueva = ''
    for i in range(len(cadena)):
        cad_nueva += chr(llave ^ ord(cadena[i]))
    return cad_nueva


def obtener_tipo(cadena):
	temp = cadena[4:100]
	inicio = temp.rfind("\\")
	temp = temp[inicio+1:]
	temp = temp[temp.find("."):]
	temp = filter(str.isalnum, temp)
	return temp


def obtener_hex(cadena):
    return hexlify(cadena).upper()


def archivo_original(cadena,tipo):
    cadena= (cadena[cadena.find("4D5A"):])
    cadena= cadena.replace("F6C6F4FFFF",'')
    cadena= cadena.replace("F6FFEFFFFF",'')
    return cadena


def archivo_binario(original):
    binario = bytes(original)
    binario = (binascii.unhexlify(binario))
    return binario


def escribe_binario(binario,nombre):
	malware = open(nombre+'.malware','w+b')
	malware.write(binario)
	malware.close()


def main():
    opts = addOptions()
    modo = check_opts(opts)
    tipo = obtener_tipo(lee_archivo(opts.descifra))
    if modo == 1:
        print 'Modo 1 descifrar con llave'
        txt_plano = cifra_descifra(lee_archivo(opts.descifra),opts.key)
        hexa = obtener_hex(txt_plano)
        original = archivo_original(hexa,tipo)
        binario = archivo_binario(original)
        escribe_binario(binario,opts.descifra)

    elif modo == 2:
        print 'Modo 2 descifrar sin llave, fuerza bruta'
        for x in range(256):
            txt_plano = cifra_descifra(lee_archivo(opts.descifra),x)
            hexa = obtener_hex(txt_plano)
            original = archivo_original(hexa,tipo)
        print txt_plano

    elif modo == 3:
        print 'Modo 3 cifrar con llave'
        txt_cifrado = cifra_descifra(lee_archivo(opts.cifra),opts.key)
        print txt_cifrado

if __name__ == '__main__':
    main()
