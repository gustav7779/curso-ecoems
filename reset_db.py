from app import app, db
import os

print("--- INICIANDO RESET DE BASE DE DATOS ---")

# 1. Activamos el contexto de la aplicación
with app.app_context():
    # 2. Borramos todo lo viejo (Tablas)
    db.drop_all()
    print("🗑️  Tablas antiguas eliminadas.")
    
    # 3. Creamos todo nuevo (Con la columna time_spent)
    db.create_all()
    print("✨ Tablas nuevas creadas (Estructura corregida).")

print("--- ✅ PROCESO TERMINADO ---")
print("Ahora corre 'python app.py' y crea tu usuario de nuevo.")