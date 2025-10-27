#!/usr/bin/env bash

# CLAVE: Ejecutar Eventlet Monkey Patching en el shell
# Esto asegura que Eventlet parchea todo el entorno de Python antes de que se cargue init_db.py
echo "--- Aplicando Eventlet Monkey Patching ---"
python -c "import eventlet; eventlet.monkey_patch()"

set -e 

# 1. Ejecutar el script de inicialización de la base de datos
echo "--- 1. Ejecutando inicialización de DB (init_db.py) ---"
python init_db.py

# 2. Iniciar el servidor Gunicorn/FLASK
echo "--- 2. Iniciando servidor Gunicorn ---"
# Llama a la instancia de Flask 'app' en el módulo 'app'
exec gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:$PORT app:app