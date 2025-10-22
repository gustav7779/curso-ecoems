import sys
import os
import logging
from app import app, db, User, generate_password_hash

# Configuración de Logging
LOG_FILE = 'db_init.log'
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'), 
        logging.StreamHandler()
    ]
)

def run_db_initialization():
    """Ejecuta la creación de tablas y el usuario admin si no existen."""
    with app.app_context():
        try:
            # Forzar la creación de todas las tablas (purge/create)
            logging.info("Attempting to drop and create all database tables...")
            db.drop_all()
            db.create_all()
            logging.info("Database tables created successfully.")

            # Creación de usuario 'admin' por defecto si no existe
            if not User.query.filter_by(username="admin").first():
                admin = User(
                    username="admin", 
                    password=generate_password_hash("1234", method="pbkdf2:sha256"), 
                    role="admin", 
                    is_active=True
                )
                db.session.add(admin)
                db.session.commit()
                logging.info("Default admin user created.")
            else:
                 logging.info("Admin user already exists. Skipping creation.")
        
        except Exception as e:
            logging.error(f"CRITICAL DB ERROR during initialization: {e}")
            db.session.rollback()
            # Forzamos la salida para que el deploy falle si la DB no se inicializa
            sys.exit(1)

if __name__ == '__main__':
    run_db_initialization()
