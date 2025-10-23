#!/usr/bin/env bash

# Archivo de inicio para Render

echo "--- 1. INICIANDO SCRIPT DE INICIALIZACIÓN DE DB ---"

# Ejecutar la inicialización de la base de datos (crea tablas y el usuario admin:1234)
# Llamamos directamente al archivo Python de inicialización.
# Importante: el script init_db.py DEBE usar el app_context() internamente.
python init_db.py

# Verificar el código de salida de init_db.py
if [ $? -ne 0 ]; then
    echo "ERROR: La inicialización de la base de datos falló. Deteniendo el servicio."
    exit 1
fi

echo "--- 2. INICIANDO SERVIDOR GUNICORN ---"

# Iniciar el servidor Gunicorn/Eventlet.
exec gunicorn --worker-class eventlet -w 1 -b 0.0.0.0:${PORT} app:app
