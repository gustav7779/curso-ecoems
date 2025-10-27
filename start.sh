#!/usr/bin/env bash

# Salir inmediatamente si un comando falla
set -e 

# 1. Ejecutar la inicialización de la base de datos
echo "--- 1. Ejecutando inicialización de DB (init_db.py) ---"
python init_db.py

# 2. Iniciar el servidor Gunicorn/SOCKETIO
echo "--- 2. Iniciando Servidor Gunicorn ---"
exec gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:$PORT app:app