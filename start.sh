#!/usr/bin/env bash

# Salir inmediatamente si un comando falla
set -e 

# 1. Ejecutar la inicialización de la base de datos
# NOTA: Ejecutamos init_db.py aquí, lo cual está bien si init_db.py NO usa el objeto 'app' de Flask/Werkzeug
echo "--- 1. Ejecutando inicialización de DB (init_db.py) ---"
python init_db.py

# 2. INICIAR EL SERVIDOR GUNICORN/SOCKETIO
# Usamos el comando 'python -m' para forzar que el parcheo suceda ANTES de que Gunicorn importe app.py.
echo "--- 2. Iniciando Servidor Gunicorn ---"
exec python -m eventlet.wsgi -s /usr/bin/python $(which gunicorn) --worker-class eventlet -w 1 -b 0.0.0.0:$PORT app:app

# O si la línea de arriba falla (más probable en Render):
# exec gunicorn --worker-class eventlet -w 1 --preload -b 0.0.0.0:$PORT 'app:app' 

# Vamos a mantener tu versión original (porque ya funciona con Gunicorn) pero eliminando el parche de shell.
# Si el error persiste, la solución más robusta es la siguiente.

# REVERTIR a la versión de start.sh antes del parcheo:
exec gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:$PORT app:app