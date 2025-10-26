#!/usr/bin/env bash

set -e 

# 1. INICIALIZACIÓN DE LA BASE DE DATOS (PURGA Y CREACIÓN DE ESQUEMA)
echo "--- 1. Ejecutando inicialización de DB (init_db.py) ---"
python init_db.py

# 2. INICIAR EL SERVIDOR GUNICORN/FLASK
echo "--- 2. Iniciando Servidor Gunicorn/SocketIO ---"
# Llama a la instancia de Flask 'app' en el módulo 'app'
exec gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:$PORT app:app