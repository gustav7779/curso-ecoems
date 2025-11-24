from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_babel import Babel, format_datetime
import datetime as dt # Importante para timedelta
import os
import pytz
import pyotp
import qrcode
import base64
from io import BytesIO
import time
import re
import logging
# Corrección en la línea 17 de app.py
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from sqlalchemy import func as db_func
from sqlalchemy import case
from sqlalchemy.exc import IntegrityError
from flask_socketio import SocketIO, emit, join_room, leave_room, ConnectionRefusedError
import csv 
import io  
import uuid # Para tokens de sesión
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import bleach
import filetype # Usamos filetype en lugar de magic

load_dotenv()

# --- CONFIGURACIÓN DE PRODUCCIÓN (CLAVE SECRETA Y DB) ---
try:
    SECRET_KEY = os.environ['SECRET_KEY']
    DATABASE_URL = os.environ['DATABASE_URL']
except KeyError as e:
    raise KeyError(f"Error: La variable de entorno {e} no está definida. Asegúrate de crear un archivo .env") from e

# --- Configuración básica de la aplicación ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURACIÓN DE COOKIES SEGURAS (SOLO PRODUCCIÓN) ---
if not app.debug:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- INICIALIZACIÓN DE CSRF ---
csrf = CSRFProtect(app)

# SEGURIDAD: Configuración de Sesión y Fuerza Bruta
app.config['PERMANENT_SESSION_LIFETIME'] = dt.timedelta(minutes=30) 
LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300 

# ======================================================================
# --- CONFIGURACIÓN DE LOGGING AVANZADA ---
# ======================================================================
app_log_handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5, encoding='utf-8')
app_log_handler.setLevel(logging.INFO)
app_log_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s: %(message)s [en %(pathname)s:%(lineno)d]'
))
security_log_handler = RotatingFileHandler('security.log', maxBytes=5000000, backupCount=3, encoding='utf-8')
security_log_handler.setLevel(logging.WARNING) 
security_log_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
app.logger.addHandler(app_log_handler)
app.logger.addHandler(security_log_handler)
app.logger.setLevel(logging.INFO) 
app.logger.propagate = False
logging.getLogger('werkzeug').propagate = False
logging.getLogger('socketio').propagate = False
logging.getLogger('engineio').propagate = False
app.logger.info("Iniciando aplicación y configurando loggers...")
# ======================================================================

# Inicialización de extensiones
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app) 
# --- 🔥 ¡MODIFICACIÓN 1! 🔥 ---
# Apuntamos a 'index' como la página de login oficial
login_manager.login_view = "index"
# --- 🔥 FIN DE MODIFICACIÓN 🔥 ---

# --- CONFIGURACIÓN DE RATE LIMITER ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"], 
    storage_uri="memory://" 
)

# INICIALIZACIÓN DE SOCKETIO
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*") 

# ======================================================================
# INTEGRACIÓN DE BABEL Y ZONA HORARIA
# ======================================================================
babel = Babel(app)
def get_locale_selector(): 
    if request and hasattr(request, 'accept_languages'):
        return request.accept_languages.best_match(['es', 'en'])
    return 'es'
def get_timezone_selector():
    return 'America/Mexico_City'
app.config['BABEL_DEFAULT_LOCALE'] = 'es'
app.config['BABEL_DEFAULT_TIMEZONE'] = 'America/Mexico_City'
app.jinja_env.globals.update(format_datetime=format_datetime)

# ======================================================================
# --- LISTAS BLANCAS DE SEGURIDAD (BLEACH Y FILETYPE) ---
# ======================================================================
ALLOWED_TAGS = [
    'b', 'strong', 'i', 'em', 'u', 'br', 'p', 'div', 'span',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote', 'pre',
    'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr'
]
ALLOWED_ATTRIBUTES = {
    '*': ['style', 'class'], # Permitir estilos (colores, fuentes) en todo
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'width', 'height', 'style'] # Permitir imágenes
}

ALLOWED_STYLES = [
    'color', 'background-color', 'font-family', 'font-weight', 
    'font-size', 'text-align', 'text-decoration', 'width', 'height', 
    'margin', 'padding', 'border'
]
ALLOWED_MIMETYPES = ['image/jpeg', 'image/png', 'image/gif']
# ======================================================================
# --- 🔥 NUEVA TABLA DE ASIGNACIONES (Muchos a Muchos) 🔥 ---
exam_assignments = db.Table('exam_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('exam_id', db.Integer, db.ForeignKey('exam.id'), primary_key=True)
)
# ======================================================================
# --- Modelos ---
# ======================================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="student")
    two_factor_secret = db.Column(db.String(32), nullable=True) 
    is_active = db.Column(db.Boolean, default=True) 
    phone_number = db.Column(db.String(20), nullable=True)
    current_session_token = db.Column(db.String(100), nullable=True, unique=True)
    results = db.relationship("ExamResult", backref="user", lazy=True) 
    violation_logs = db.relationship("ViolationLog", backref="user", lazy=True) 

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_datetime = db.Column(db.DateTime, nullable=True)
    end_datetime = db.Column(db.DateTime, nullable=True)
    is_cancelled = db.Column(db.Boolean, default=False)
    cancellation_reason = db.Column(db.Text, nullable=True)
    # 🔥 RELACIÓN CON ALUMNOS ASIGNADOS 🔥
    assigned_students = db.relationship('User', secondary=exam_assignments, lazy='subquery',
        backref=db.backref('assigned_exams', lazy=True))
    # --- 🔥 ¡NUEVA COLUMNA AÑADIDA! 🔥 ---
    # Esto controla si los alumnos pueden ver las respuestas correctas.
    answers_released = db.Column(db.Boolean, default=False, nullable=False)
    # --- 🔥 FIN DE NUEVA COLUMNA 🔥 ---

    questions = db.relationship("Question", backref="exam", cascade="all, delete-orphan")
    active_sessions = db.relationship("ActiveExamSession", backref="exam", cascade="all, delete-orphan") 
    violation_logs = db.relationship("ViolationLog", backref="exam", lazy=True, cascade="all, delete-orphan") 

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False) 
    option_a = db.Column(db.String(255), nullable=True)
    option_b = db.Column(db.String(255), nullable=True)
    option_c = db.Column(db.String(255), nullable=True)
    option_d = db.Column(db.String(255), nullable=True)
    correct_option = db.Column(db.String(10), nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(100), nullable=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    # --- 🔥 INICIO DE MODIFICACIÓN: SIMULADOR DE RENDIMIENTO 🔥 ---
    times_answered = db.Column(db.Integer, default=0, nullable=False)
    correct_answers = db.Column(db.Integer, default=0, nullable=False)
    difficulty_score = db.Column(db.Float, default=0.5, nullable=False)
    manual_difficulty = db.Column(db.String(20), default='Medium', nullable=False) # <--- NUEVO CAMPO MANUAL
    # --- 🔥 FIN DE MODIFICACIÓN: SIMULADOR DE RENDIMIENTO 🔥 ---

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    grade = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)

class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date_taken = db.Column(db.DateTime) 
    submission_type = db.Column(db.String(50), default='manual') 

    
    # --- 🔥 INICIO DE MODIFICACIÓN: RASTREO DE CALOR 🔥 ---
    proctoring_data = db.Column(db.Text, nullable=True) # Almacena JSON de timing y clicks
    session_recording = db.Column(db.Text, nullable=True) # Aquí guardamos el "video"
    # --- 🔥 FIN DE MODIFICACIÓN: RASTREO DE CALOR 🔥 ---


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_published = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    publisher = db.relationship('User', backref='announcements') 
    is_active = db.Column(db.Boolean, default=True) 

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='Abierto') 
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reporter = db.relationship('User', backref='reports') 
    admin_response = db.Column(db.Text, nullable=True)
    date_resolved = db.Column(db.DateTime, nullable=True) 

class AnnouncementReadStatus(db.Model):
    __tablename__ = 'announcement_read_status'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    announcement_id = db.Column(
        db.Integer, 
        db.ForeignKey('announcement.id', ondelete='CASCADE'), 
        primary_key=True
    )
    user = db.relationship('User', backref='read_announcements')
    announcement = db.relationship('Announcement', backref='read_by')

class ActiveExamSession(db.Model):
    __tablename__ = 'active_exam_session'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    time_added_sec = db.Column(db.Integer, default=0) 
    violation_count = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref=db.backref('active_session', uselist=False))

class ViolationLog(db.Model):
    __tablename__ = 'violation_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    violation_type = db.Column(db.String(100), nullable=False) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
# -------------------------------------------------------------------

# ======================================================================
# --- FUNCIÓN DE UTILIDAD: ENVÍO DE NOTIFICACIONES ---
# ======================================================================

def send_dummy_notification(to_number, body_message):
    app.logger.warning(f"DUMMY NOTIFICATION: Mensaje a {to_number} (Cuerpo: {body_message[:50]}...) NO ENVIADO. Twilio deshabilitado.")
    return False

# ======================================================================
# --- MANEJADORES DE SOCKETIO (CHAT EN VIVO Y SEGURIDAD) ---
# ======================================================================

@socketio.on('connect')
def handle_connect():
    app.logger.info("Socket CONNECTED. Attempting to get user context.")
    if current_user.is_authenticated:
        join_room(str(current_user.id))
        
        # 🔥 NUEVO: Unir admins a la sala de pulso
        if current_user.role in ['admin', 'ayudante']:
            join_room('admin_pulse_room')
            app.logger.info(f"Admin/Ayudante {current_user.username} unido a admin_pulse_room.")
        
        app.logger.info(f"Socket conectado y unido al room de usuario: User {current_user.username} (ID: {current_user.id})")


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(str(current_user.id))
        app.logger.info(f"Socket desconectado: User {current_user.username} (ID: {current_user.id})")


@socketio.on('join_room')
def on_join(data):
    if not current_user.is_authenticated or current_user.role != 'admin':
        app.logger.warning("SECURITY: Unauthorized user tried to join admin chat.")
        return

    target_user_id = str(data.get('user_id'))
    join_room(target_user_id)
    app.logger.info(f"ADMIN CHAT: Admin {current_user.username} joined room {target_user_id}.")
    
    emit('status_update', 
         {'msg': f'Conectado a la sala del alumno ID {target_user_id}.'}, 
         room=str(current_user.id)
    )

@socketio.on('send_message_to_student')
def handle_admin_message(data):
    if not current_user.is_authenticated or current_user.role != 'admin':
        app.logger.warning(f"SECURITY: Non-admin user {current_user.username} attempted to send chat message.")
        return 

    target_room = str(data.get('target_user_id'))
    message_content = data.get('message')

    if target_room and message_content:
        emit('chat_notification', 
             {
                 'sender': 'Admin', 
                 'message': message_content,
                 'timestamp': datetime.now().strftime("%H:%M:%S")
             }, 
             room=target_room,
             namespace='/'
        )
        app.logger.info(f"CHAT: Admin {current_user.username} sent message to User ID {target_room}: {message_content[:30]}...")
        
# ... (imports y config igual) ...

# --- 🔥 NUEVO EVENTO: FORZAR UNIÓN AL PULSO (Para asegurar notificaciones) 🔥 ---
@socketio.on('admin_join_pulse')
def on_admin_join_pulse():
    if current_user.is_authenticated and current_user.role in ['admin', 'ayudante']:
        join_room('admin_pulse_room')
        app.logger.info(f"Admin {current_user.username} forzó la unión a admin_pulse_room.")

# ... (handle_connect y disconnect igual) ...

@socketio.on('student_requests_chat')
def handle_student_help_request():
    if not current_user.is_authenticated or current_user.role != 'student':
        return
        
    # Notificar a TODOS los admins conectados al 'admin_pulse_room'
    socketio.emit('admin_notification_alert', {
        'title': '🆘 Solicitud de Ayuda',
        'message': f"El alumno {current_user.username} quiere hablar contigo.",
        'user_id': current_user.id,
        'type': 'warning' # Amarillo para llamar la atención
    }, room='admin_pulse_room')
    
    app.logger.info(f"HELP: Student {current_user.username} requested chat support.")

# ... (resto del archivo igual) ...

# --- 🔥🔥 INICIO DE MODIFICACIÓN: RASTREO DE CALOR (Nuevo Socket Handler) 🔥🔥 ---
@socketio.on('proctoring_update')
def handle_proctoring_update(data):
    """
    Recibe data de timing y clicks del cliente cada 30 segundos y la guarda en la sesión.
    """
    if not current_user.is_authenticated or current_user.role != 'student':
        return

    exam_id = data.get('exam_id')
    time_data = data.get('time_data', {}) 
    click_data = data.get('click_data', []) 
    is_final = data.get('is_final', False)
    
    session_key = f'proctoring_data_{exam_id}'
    
    # 1. Recuperar datos existentes de la sesión
    existing_data_json = session.get(session_key, '{}')
    
    try:
        if existing_data_json:
            existing_data = json.loads(existing_data_json)
        else:
            existing_data = {'time_data': {}, 'click_data': []}
    except json.JSONDecodeError:
        app.logger.error(f"[PROCTORING] Error al decodificar sesión JSON para {current_user.username}. Reiniciando data.")
        existing_data = {'time_data': {}, 'click_data': []}

    # 2. Agregar nueva data de tiempo (Agregación simple: q_id: total_time)
    for qid, time_spent in time_data.items():
        # Sumamos el tiempo reportado al total existente para esa pregunta
        existing_data['time_data'][qid] = existing_data['time_data'].get(qid, 0) + time_spent
        
    # 3. Agregar nueva data de clics (Añadir al array existente)
    # NOTA: En un entorno real, se debería sanear esta data.
    existing_data['click_data'].extend(click_data)

    # 4. Guardar data agregada en la sesión
    try:
        session[session_key] = json.dumps(existing_data)
        session.modified = True 
    except Exception as e:
        app.logger.error(f"[PROCTORING] Error al guardar data de sesión para {current_user.username}: {e}")
    
    if is_final:
        app.logger.info(f"[PROCTORING] Envío final completado para {current_user.username} (Exam {exam_id}).")
    else:
        app.logger.info(f"[PROCTORING] Data guardada para {current_user.username} (Exam {exam_id}). Times tracked: {len(existing_data['time_data'])}.")
        
# --- 🔥🔥 FIN DE MODIFICACIÓN: RASTREO DE CALOR (Nuevo Socket Handler) 🔥🔥 ---


@socketio.on('close_student_chat_remote')
def handle_close_chat(data):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return 
        
    target_room = str(data.get('target_user_id')) 
    admin_username = data.get('admin_username', 'Admin')

    if target_room:
        emit('close_chat_signal', 
             {'msg': f'El soporte ha finalizado por {admin_username}.'}, 
             room=target_room,
             namespace='/'
        )
        app.logger.info(f"CHAT: Admin {current_user.username} closed chat session for User ID {target_room}.")
        
# ... (código anterior)
# ... (otros handlers de socket) ...

# --- 🔥 NUEVO: SISTEMA DE REPARACIÓN REMOTA 🔥 ---

@socketio.on('admin_repair_command')
def handle_repair_command(data):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return

    target_user_id = str(data.get('target_user_id'))
    command = data.get('command')
    payload = data.get('payload')
    
    app.logger.info(f"REPAIR: Admin {current_user.username} sent command '{command}' to User {target_user_id}")

    # 🔥 LÓGICA DE DESBLOQUEO EN SERVIDOR (REVIVIR SESIÓN)
    if command == 'unlock':
        try:
            # 1. Buscar y borrar el resultado de "Cancelado" (-1.0)
            target_user_int = int(target_user_id)
            blocked_result = ExamResult.query.filter_by(user_id=target_user_int, score=-1.0).first()
            
            exam_id = None
            if blocked_result:
                exam_id = blocked_result.exam_id
                db.session.delete(blocked_result)
            
            # 2. Restaurar una sesión activa (si sabemos el examen)
            # Nota: Para no complicar, creamos una sesión nueva con el tiempo actual.
            # El frontend gestionará el tiempo visual restante real. Esto es solo para que el backend acepte respuestas.
            if exam_id:
                existing_session = ActiveExamSession.query.filter_by(user_id=target_user_int, exam_id=exam_id).first()
                if not existing_session:
                    # Restauramos la sesión para permitir guardar respuestas
                    revived_session = ActiveExamSession(
                        user_id=target_user_int,
                        exam_id=exam_id,
                        start_time=datetime.utcnow(), # Reiniciamos el reloj del servidor para evitar errores de "Tiempo Expirado" al enviar
                        time_added_sec=0
                    )
                    db.session.add(revived_session)
            
            db.session.commit()
            app.logger.info(f"REPAIR: Sesión del usuario {target_user_id} restaurada en DB.")

        except Exception as e:
            app.logger.error(f"Error al desbloquear usuario {target_user_id}: {e}")
            db.session.rollback()

    # Reenviar el comando al navegador del alumno
    emit('execute_repair', {'command': command, 'payload': payload}, room=target_user_id, namespace='/')
# --------------------------------------------------

@socketio.on('exam_violation')
def handle_exam_violation(data):
    if not current_user.is_authenticated or current_user.role != 'student':
        return
    
    exam_id = data.get('exam_id')
    user_id = current_user.id
    violation_type = data.get('type', 'Unknown Violation')
    screenshot_data = data.get('screenshot') 
    
    if not exam_id or not user_id:
        app.logger.error(f"Error al registrar violación: Missing exam_id or user_id in data: {data}")
        return

    try:
        current_time_utc = datetime.utcnow()
        utc_tz = pytz.utc
        mexico_tz = pytz.timezone('America/Mexico_City')
        aware_utc_time = utc_tz.localize(current_time_utc)
        mexico_time = aware_utc_time.astimezone(mexico_tz)

        active_session = ActiveExamSession.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        
        if not active_session:
            app.logger.error(f"SECURITY ALERT: Sesión activa no encontrada para el Usuario {user_id}. Ignorando violación.")
            return

        MAX_WARNINGS = 3
        
        # 🔥 CRÍTICO: Definir qué violaciones cuentan para el límite de cancelación (Strikes)
        CRITICAL_VIOLATIONS = ['WINDOW_BLUR', 'TAB_CHANGE', 'HERRAMIENTAS_DEV', 'COPIAR_PEGAR', 'INTENTO_IMPRESION', 'CLIC_DERECHO']
        
        if violation_type in CRITICAL_VIOLATIONS:
            active_session.violation_count += 1
            
        # 🔑 Si la violación es AI (Voz/Rostro), solo se registra, pero el contador no se incrementa.

        
        if active_session.violation_count >= MAX_WARNINGS:
            
            automatic_reason = "Por andar cambiando de ventana, cualquier reclamo haz un reporte y se te explicara todo a detalle"
            
            # --- MODIFICACIÓN: Guardar captura en el log de auto-cancelación ---
            details_message = f"Bloqueo automático: Se alcanzó el límite de {MAX_WARNINGS} advertencias. Motivo: {automatic_reason}"
            
            if screenshot_data:
                details_to_save = screenshot_data
            else:
                details_to_save = details_message
            # --- FIN DE MODIFICACIÓN ---

            new_log = ViolationLog(
                user_id=user_id,
                exam_id=exam_id,
                violation_type="EXAM_CANCELED_AUTO_BLOCK",
                details=details_to_save, # <-- ¡MODIFICADO!
                timestamp=current_time_utc 
            )
            db.session.add(new_log)
            
            existing_result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
            if not existing_result:
                cancelled_result = ExamResult(
                    user_id=user_id,
                    exam_id=exam_id,
                    score=-1.0, 
                    date_taken=current_time_utc,
                    submission_type='auto_cancel' 
                )
                db.session.add(cancelled_result)

            db.session.delete(active_session) 
            
            app.logger.critical(f"[USER_ID: {user_id} | USER: {current_user.username} | EXAM_ID: {exam_id}] EXAMEN CANCELADO AUTOMÁTICAMENTE. Límite de {MAX_WARNINGS} advertencias alcanzado.")
            
            socketio.emit('exam_cancelled_alert', {
                'exam_id': exam_id,
                'reason': automatic_reason 
            }, room=str(user_id)) 

            socketio.emit('admin_violation_alert', {
                'user_id': user_id,
                'username': current_user.username,
                'exam_id': exam_id,
                'type': "EXAM_CANCELED_AUTO_BLOCK",
                'timestamp': mexico_time.strftime('%H:%M:%S'), 
                'warning_count': active_session.violation_count
            }, room='1', namespace='/') 

            db.session.commit() 
            return 

        # --- MODIFICACIÓN: Guardar captura en el log de violación normal ---
        details_message = f"Violación de tipo: {violation_type}. Advertencia #{active_session.violation_count}"
        if screenshot_data:
            details_to_save = screenshot_data
        else:
            details_to_save = details_message
        # --- FIN DE MODIFICACIÓN ---

        new_log = ViolationLog(
            user_id=user_id,
            exam_id=exam_id,
            violation_type=violation_type,
            details=details_to_save, # <-- ¡MODIFICADO!
            timestamp=current_time_utc 
        )
        db.session.add(new_log)
        db.session.add(active_session) 
        db.session.commit() 
        
        app.logger.warning(f"[USER_ID: {user_id} | USER: {current_user.username} | EXAM_ID: {exam_id}] Violación detectada. TIPO: {violation_type}. CONTEO: {active_session.violation_count}")
        
        socketio.emit('admin_violation_alert', {
            'user_id': user_id,
            'username': current_user.username,
            'exam_id': exam_id,
            'type': violation_type,
            'timestamp': mexico_time.strftime('%H:%M:%S'), 
            'warning_count': active_session.violation_count 
        }, room='1', namespace='/') 

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error DB al registrar violación (User: {user_id}, Type: {violation_type}): {e}")

# ======================================================================
# --- HOOKS DE SEGURIDAD Y MANEJADORES ---
# ======================================================================

@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' 
    return response

@app.before_request
def before_request_hook():
    if current_user.is_authenticated:
        if not current_user.is_active:
            app.logger.warning(f"SECURITY: Active user {current_user.username} was deactivated. Forcing logout.")
            logout_user()
            flash("Tu cuenta ha sido desactivada por un administrador.", "danger")
            return redirect(url_for('login'))
            
        session.permanent = True 
        
        last_activity = session.get('last_activity')
        session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
        
        if last_activity:
            if isinstance(last_activity, str):
                try:
                    last_activity = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    try:
                        last_activity = datetime.strptime(last_activity.split('.')[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        last_activity = datetime.utcnow() - session_lifetime * 2 


            if (datetime.utcnow() - last_activity) > session_lifetime:
                logout_user()
                flash("Tu sesión ha expirado por inactividad. Vuelve a iniciar sesión.", "warning")
                return redirect(url_for('login'))
        
        if request.endpoint and request.endpoint not in ['logout']:
            if session.get('session_token') != current_user.current_session_token:
                
                app.logger.warning(f"[USER_ID: {current_user.id} | USER: {current_user.username}] Múltiples sesiones detectadas. Cerrando esta sesión.")
                logout_user()
                flash("Se ha iniciado sesión con tu cuenta en otra ubicación. Esta sesión ha sido cerrada.", "warning")
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================================================================
# --- RUTAS DE ACCESO PRINCIPAL (Index, Login, Logout, Dashboards) ---
# ======================================================================

@app.route("/logout")
@login_required
def logout():
    app.logger.info(f"AUDIT LOG: User {current_user.username} logged out.")
    logout_user()
    flash("Has cerrado sesión exitosamente.", "success")
    return redirect(url_for("index"))


# --- 🔥 ¡MODIFICADO! RUTA DEL PANEL DE GESTIÓN (SOLO MUESTRA MENÚS) 🔥 ---
@app.route("/admin")
@login_required
def admin_panel():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
        
    if session.pop('just_logged_in', False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")

    # --- Consultas de estadísticas movidas a '/admin/dashboard' ---
    
    exams = Exam.query.all()
    announcements_list = Announcement.query.order_by(Announcement.date_published.desc()).all() 
    active_exams_summary = [] # Esto se maneja en vivo, pero lo dejamos por si se usa en otro lado
    
    return render_template("admin.html", 
                           exams=exams, 
                           announcements_list=announcements_list,
                           active_exams_summary=active_exams_summary
                           # --- Variables de estadísticas ya no se pasan aquí ---
                           )
# --- 🔥 ¡FIN DE MODIFICACIÓN! 🔥 ---


# --- 🔥 ¡NUEVA RUTA! ESTA ES LA TORRE DE CONTROL 🔥 ---
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    # --- INICIO DE QUERIES DEL DASHBOARD ---
    
    # 1. Total de Alumnos
    total_students = User.query.filter_by(role='student').count()
    
    # 2. Exámenes Completados Hoy (en Zona Horaria de México)
    mexico_tz = pytz.timezone('America/Mexico_City')
    today_start_mexico = mexico_tz.localize(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0))
    today_end_mexico = today_start_mexico + dt.timedelta(days=1)
    # Convertir a UTC para comparar con la base de datos
    today_start_utc = today_start_mexico.astimezone(pytz.utc)
    today_end_utc = today_end_mexico.astimezone(pytz.utc)
    
    completados_hoy = ExamResult.query.filter(
        ExamResult.date_taken >= today_start_utc, 
        ExamResult.date_taken < today_end_utc, 
        ExamResult.score >= 0 # Ignorar cancelados
    ).count()

    # 3. Puntaje Promedio (Aciertos promedio, no porcentaje)
    avg_score_query = db.session.query(db_func.avg(ExamResult.score)).filter(ExamResult.score >= 0).scalar()
    avg_score = round(avg_score_query, 1) if avg_score_query else 0.0

    # --- FIN DE QUERIES DEL DASHBOARD ---

    return render_template("admin_dashboard.html",
                           total_students=total_students,
                           completados_hoy=completados_hoy,
                           avg_score=avg_score
                           )
# --- 🔥 FIN DE NUEVA RUTA 🔥 ---


# --- 🔥 ¡NUEVA RUTA DE API PARA LA GRÁFICA! 🔥 ---
@app.route("/admin/api/chart_data")
@login_required
def chart_data():
    if current_user.role not in ["admin", "ayudante"]:
        app.logger.warning(f"SECURITY: Usuario {current_user.username} intentó acceder a la API de admin sin permisos.")
        return jsonify({"error": "Acceso denegado"}), 403
    
    # Query: 5 Materias con más respuestas incorrectas
    materias_reprobadas_query = db.session.query(
        Question.subject, 
        db_func.count(Answer.id).label('incorrect_count')
    ).join(Answer, Answer.question_id == Question.id)\
     .filter(Answer.grade == 0.0, Question.subject != None)\
     .group_by(Question.subject)\
     .order_by(db_func.count(Answer.id).desc())\
     .limit(5).all()

    # Formatear para Chart.js
    chart_labels = [row.subject for row in materias_reprobadas_query]
    chart_data = [row.incorrect_count for row in materias_reprobadas_query]
    
    return jsonify(labels=chart_labels, data=chart_data)
# --- 🔥 FIN DE NUEVA RUTA 🔥 ---

# --- 🔥 NUEVA RUTA DE API PARA EL SIMULADOR DE RENDIMIENTO 🔥 ---
@app.route("/admin/api/exam_performance/<int:exam_id>")
@login_required
def api_exam_performance(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return jsonify({"error": "Acceso denegado"}), 403

    exam = Exam.query.get_or_404(exam_id)
    
    # Cargar todas las preguntas del examen
    questions_data = Question.query.filter_by(exam_id=exam_id).all()
    
    # 1. Determinar si hay datos estadísticos reales
    total_analyzed = Question.query.filter_by(exam_id=exam_id).filter(Question.times_answered > 0).count()
    
    # --- 🔥 COMPENSACIÓN POR FALTA DE DATOS HISTÓRICOS 🔥 ---
    if total_analyzed == 0:
        # Fallback: Calcular distribución basada en Tags Manuales
        difficulty_counts = db.session.query(
            Question.manual_difficulty,
            db_func.count(Question.id)
        ).filter_by(exam_id=exam_id)\
         .group_by(Question.manual_difficulty)\
         .all()
         
        # El frontend usará el campo 'is_fallback' para mostrar esta data
        return jsonify({
            "exam_title": exam.title,
            "total_questions": len(questions_data),
            "total_analyzed": 0,
            "predicted_score": 0,
            "is_fallback": True, 
            "difficulty_distribution": [{
                "subject": d[0],
                "count": d[1]
            } for d in difficulty_counts]
        })
    # --- 🔥 FIN DE COMPENSACIÓN ---
    
    # Si hay datos estadísticos, proceder con el cálculo normal:
    questions_with_data = Question.query.filter_by(exam_id=exam_id).filter(Question.times_answered > 0).all()
    
    total_difficulty = 0
    red_flag_questions = []
    
    # 2. Recopilar datos y calcular la dificultad promedio
    for q in questions_with_data:
        total_difficulty += q.difficulty_score
        
        # Banderas Rojas: dificultad < 0.3 (menos del 30% de aciertos)
        if q.difficulty_score < 0.3:
            red_flag_questions.append({
                'id': q.id,
                'text': q.text,
                'score': round(q.difficulty_score * 100, 1)
            })

    avg_difficulty = (total_difficulty / len(questions_with_data)) * 100
    predicted_score = round(avg_difficulty, 1)
    
    return jsonify({
        "exam_title": exam.title,
        "total_questions": len(questions_data),
        "total_analyzed": len(questions_with_data),
        "predicted_score": predicted_score,
        "average_difficulty_percent": predicted_score,
        "red_flag_questions": red_flag_questions,
        "difficulty_distribution": [{
            "id": q.id,
            "subject": q.subject,
            "difficulty": round(q.difficulty_score * 100, 1) # Porcentaje de acierto
        } for q in questions_with_data]
    })


@app.route("/admin/exam_simulator/<int:exam_id>")
@login_required
def exam_simulator_view(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    
    return render_template("exam_simulator.html", exam=exam)
# --- 🔥 FIN DE NUEVAS RUTAS 🔥 ---


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    if session.pop('just_logged_in', False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")
        
    total_announcements = Announcement.query.count()
    read_count = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).count()
    unread_count = total_announcements - read_count
    
    last_result = ExamResult.query.filter_by(user_id=current_user.id)\
                                  .order_by(ExamResult.date_taken.desc()).first()
                                  
    last_exam_questions_count = 0
    if last_result:
        exam = Exam.query.get(last_result.exam_id)
        if exam:
            last_exam_questions_count = len(exam.questions)

    correct_count_expr = case((Answer.grade == 1, 1), else_=0)
    
    materias_a_reforzar = db.session.query(
        Question.subject, 
        db_func.avg(Answer.grade).label('avg_score'), 
        db_func.sum(correct_count_expr).label('correct_count'), 
        db_func.count(Answer.id).label('total_answered') 
    ).join(Question, Answer.question_id == Question.id)\
     .filter(Answer.user_id == current_user.id, Question.subject != None, Answer.grade != None)\
     .group_by(Question.subject)\
     .order_by(db_func.avg(Answer.grade).asc())\
     .limit(3)\
     .all()
    
    weak_subjects = []
    for subject, avg_score, correct_count, total_answered in materias_a_reforzar:
        if total_answered > 0:
            weak_subjects.append({
                'subject': subject,
                'avg_score': f"{avg_score*100:.1f}%", 
                'correct_count': correct_count,
                'total_answered': total_answered
            })
    
    latest_reports = Report.query.filter_by(user_id=current_user.id)\
                                 .order_by(Report.date_submitted.desc())\
                                 .limit(3).all()
    
    for report in latest_reports:
        if report.admin_response and report.date_resolved:
            session_key = f'report_seen_{report.id}_{report.date_resolved.strftime("%Y%m%d%H%M")}'
            
            if session.get(session_key) is None:
                flash(f"🔔 El Admin ha respondido tu reporte #{report.id} ({report.title}).", "info")
                break 

    
    return render_template(
        "dashboard.html", 
        username=current_user.username, 
        unread_count=unread_count,
        last_result=last_result,
        last_exam_questions_count=last_exam_questions_count,
        weak_subjects=weak_subjects,
        Exam=Exam,
        latest_reports=latest_reports
    ) 


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
            
    # --- 🔥 ¡MODIFICACIÓN! Apunta a la página de login. ---
    return redirect(url_for("login"))

@app.route("/privacy")
def privacy_notice():
    return render_template("privacy.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute") 
def login():
    if current_user.is_authenticated:
        if current_user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
            
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not re.match(r'^[a-zA-Z0-9_]{3,150}$', username):
            app.logger.warning(f"SECURITY: Invalid username format attempted: {username}")
            flash("Formato de usuario inválido. Solo se permiten letras, números y '_'.", "danger")
            return redirect(url_for('login')) 
        
        lockout_end_time = session.get('lockout_end_time', 0)
        current_time = time.time()
        
        if current_time < lockout_end_time:
            remaining_time = int(lockout_end_time - current_time)
            app.logger.warning(f"SECURITY: Login attempt blocked for user {username} (Lockout active)")
            flash(f"Demasiados intentos fallidos. Intenta de nuevo en {remaining_time} segundos.", "danger")
            return redirect(url_for('login')) 
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not check_password_hash(user.password, password):
            
            failed_attempts = session.get('failed_attempts', 0) + 1
            session['failed_attempts'] = failed_attempts
            
            app.logger.warning(f"[IP: {get_remote_address()} | USER_ATTEMPT: {username}] Intento de inicio de sesión fallido.")
            
            if failed_attempts >= LOGIN_ATTEMPTS:
                session['lockout_end_time'] = current_time + LOCKOUT_TIME
                session['failed_attempts'] = 0 
                app.logger.critical(f"[IP: {get_remote_address()} | USER_ATTEMPT: {username}] CUENTA BLOQUEADA por {LOCKOUT_TIME} segundos.")
                flash(f"Demasiados intentos. Tu cuenta ha sido bloqueada por {LOCKOUT_TIME} segundos.", "danger")
            else:
                flash("Usuario o contraseña incorrectos", "danger")
            
            return redirect(url_for("login")) 
            
        if not user.is_active:
            app.logger.warning(f"SECURITY ALERT: Blocked inactive user {username} login attempt.")
            flash("Tu cuenta está inactiva. Contacta al administrador.", "danger")
            return redirect(url_for("login")) 
            
        session.pop('failed_attempts', None)
        session.pop('lockout_end_time', None)
        
        if user.two_factor_secret:
            session['temp_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
            
        login_user(user)
        session.permanent = True 
        session['last_activity'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        session['just_logged_in'] = True 
        
        token = str(uuid.uuid4()) 
        user.current_session_token = token
        db.session.commit()
        session['session_token'] = token 
        
        app.logger.info(f"AUDIT LOG: User {user.username} logged in successfully.")
        
        # 🔥 NUEVO: Emitir evento de inicio de sesión
        socketio.emit('new_activity', {
            'msg': f"El alumno 🔑 {user.username} ha iniciado sesión.",
            'type': 'info'
        }, room='admin_pulse_room')

        if user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
            
    # --- 🔥 MODIFICACIÓN 2! 🔥 ---
    # Renderiza index.html aquí, ya que es tu página de login
    return render_template("index.html")
# --- 🔥 FIN DE MODIFICACIÓN 🔥 ---


# ======================================================================
# --- RUTAS DE SEGURIDAD (2FA) ---
# ======================================================================

@app.route("/verify_2fa", methods=["GET", "POST"])
@limiter.limit("20 per minute") 
def verify_2fa():
    user_id = session.get('temp_user_id')
    
    if not user_id:
        flash("Debes ingresar la contraseña primero.", "danger")
        return redirect(url_for('login'))
        
    user = User.query.get(user_id)
    
    if not user or not user.two_factor_secret:
        session.pop('temp_user_id', None)
        return redirect(url_for('login'))

    if request.method == "POST":
        totp_code = request.form.get("totp_code")
        secret = user.two_factor_secret
            
        totp = pyotp.TOTP(secret)

        if totp.verify(totp_code, valid_window=1): 
            session.pop('temp_user_id', None)
            login_user(user)
            session.permanent = True 
            session['last_activity'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
            session['just_logged_in'] = True 
            app.logger.info(f"AUDIT LOG: User {user.username} verified 2FA successfully.")
            flash("Verificación 2FA exitosa. Bienvenido.", "success")
            
            token = str(uuid.uuid4()) 
            user.current_session_token = token
            db.session.commit()
            session['session_token'] = token

            if user.role in ["admin", "ayudante"]:
                return redirect(url_for("admin_panel"))
            else:
                return redirect(url_for("dashboard"))
        else:
            app.logger.warning(f"SECURITY ALERT: Failed 2FA code entered for user: {user.username}")
            flash("Código de verificación 2FA incorrecto.", "danger")

    return render_template('verify_2fa.html')

@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
        
    user = current_user
    
    if request.method == "POST":
        totp_code = request.form.get("totp_code")
        secret = session.get('new_2fa_secret')
        
        if not secret:
            flash("Error de sesión. Intenta configurar de nuevo.", "danger")
            return redirect(url_for('setup_2fa'))

        totp = pyotp.TOTP(secret)

        if totp.verify(totp_code, valid_window=1): 
            user.two_factor_secret = secret
            db.session.commit()
            session.pop('new_2fa_secret', None)
            app.logger.info(f"AUDIT LOG: Admin user {current_user.username} activated 2FA successfully.")
            flash("✅ Autenticación de Dos Factores activada correctamente.", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Código de verificación incorrecto. Intenta escanear el código QR y vuelve a intentarlo.", "danger")

    if not user.two_factor_secret:
        new_secret = pyotp.random_base32()
        session['new_2fa_secret'] = new_secret
        
        service_name = "ECOMS_Admin" 
        uri = pyotp.totp.TOTP(new_secret).provisioning_uri(
            name=user.username,
            issuer_name=service_name
        )
        
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, format='PNG') 
        buf.seek(0)
        qr_base64 = base64.b64encode(buf.read()).decode('utf-8')
        
        return render_template(
            "setup_2fa.html", 
            qr_base64=qr_base64, 
            secret=new_secret, 
            uri=uri,
            username=user.username
        )
        
    flash("El 2FA ya está configurado para este usuario.", "info")
    return redirect(url_for('admin_panel'))

@app.route("/disable_2fa", methods=["POST"])
@login_required
def disable_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    current_user.two_factor_secret = None
    db.session.commit()
    app.logger.info(f"AUDIT LOG: Admin user {current_user.username} disabled 2FA.")
    flash("✅ Autenticación de Dos Factores (2FA) ha sido desactivada.", "success")
    return redirect(url_for('admin_panel'))


# ======================================================================
# --- RUTAS DE ADMINISTRACIÓN Y GESTIÓN ---
# ======================================================================

@app.route("/admin/chat/<int:user_id>")
@login_required
def admin_chat(user_id):
    if current_user.role != "admin":
        flash("Acceso denegado. Solo los administradores principales pueden iniciar el chat de soporte.", "danger")
        return redirect(url_for("dashboard"))
        
    target_user = User.query.get_or_404(user_id)
    
    return render_template("admin_chat.html", target_user=target_user)


@app.route("/admin/exams/monitor/<int:exam_id>")
@login_required
def admin_exam_monitor_detail(exam_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    exam = Exam.query.get_or_404(exam_id)
    
    all_students = User.query.filter_by(role='student', is_active=True).all()
    
    active_sessions_map = {
        session.user_id: session 
        for session in ActiveExamSession.query.filter_by(exam_id=exam_id).all()
    }
    
    monitoring_data = []
    
    # 🔥 ZONAS HORARIAS PARA LOCALIZAR EL TIMESTAMP 🔥
    utc_tz = pytz.utc
    mexico_tz = pytz.timezone('America/Mexico_City')
    
    for student in all_students:
        user_id = student.id
        
        is_active_session = active_sessions_map.get(user_id) 
        is_finished = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        
        status = 'No Ha Iniciado'
        violation_count = 0 
        
        if is_active_session:
            status = 'Haciendo Examen'
            violation_count = is_active_session.violation_count
        elif is_finished:
            if is_finished.score == -1.0:
                status = 'Cancelado (Bloqueado)'
            else:
                status = 'Examen Terminado'
        
        last_violation_log = ViolationLog.query.filter_by(
            user_id=user_id, 
            exam_id=exam_id
        ).order_by(ViolationLog.timestamp.desc()).first()

        # 🔥 CORRECCIÓN: Localizar a CDMX para el Jinja
        if last_violation_log and last_violation_log.timestamp:
            aware_utc_time = utc_tz.localize(last_violation_log.timestamp)
            last_violation_log.timestamp = aware_utc_time.astimezone(mexico_tz)
        # 🔥 FIN DE CORRECCIÓN

        monitoring_data.append({
            'user_id': user_id,
            'username': student.username,
            'status': status,
            'violation_count': violation_count, 
            'is_active': is_active_session is not None,
            'last_violation': last_violation_log 
        })
        
    return render_template("admin_exam_monitor.html", 
                           exam=exam, 
                           monitoring_data=monitoring_data,
                           student=current_user) # <--- Esto es lo importante para que no falle el HTML


@app.route('/admin/adjust_exam_time', methods=['POST'])
@login_required
def admin_adjust_exam_time():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403

    try:
        data = request.get_json()
        student_id = int(data.get('student_id'))
        time_to_adjust_sec = int(data.get('time_sec')) 
        
        session_db = ActiveExamSession.query.filter_by(user_id=student_id).first() 

        if not session_db:
            return jsonify({'success': False, 'message': 'Sesión de examen activa no encontrada.'}), 404

        session_db.time_added_sec += time_to_adjust_sec
        db.session.commit()
        
        action_msg = "añadieron" if time_to_adjust_sec >= 0 else "restaron"
        
        socketio.emit('time_update', 
                      {'extra_time_sec': session_db.time_added_sec}, 
                      room=str(student_id)) 

        return jsonify({'success': True, 
                        'message': f'Se {action_msg} {abs(time_to_adjust_sec)/60} minutos al alumno {student_id}.',
                        'new_total_extra_sec': session_db.time_added_sec})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al ajustar tiempo: {e}")
        return jsonify({'success': False, 'message': f'Error interno: {str(e)}'}), 500


@app.route('/admin/cancel_exam', methods=['POST'])
@login_required
def admin_cancel_exam():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403

    try:
        data = request.get_json()
        student_id = int(data.get('student_id'))
        exam_id = int(data.get('exam_id'))
        reason = data.get('reason', 'Sin motivo especificado por el administrador.')
        
        exam = Exam.query.get_or_404(exam_id)
        student = User.query.get_or_404(student_id)

        if not exam or not student:
            return jsonify({'success': False, 'message': 'Examen o alumno no encontrado.'}), 404

        exam.cancellation_reason = f"Cancelación para {student.username}: {reason}"
        
        existing_result = ExamResult.query.filter_by(user_id=student_id, exam_id=exam_id).first()
        if not existing_result:
            cancelled_result = ExamResult(
                user_id=student_id, 
                exam_id=exam_id, 
                score=-1.0, 
                date_taken=datetime.utcnow(),
                submission_type='manual_cancel' 
            )
            db.session.add(cancelled_result)

        active_session = ActiveExamSession.query.filter_by(
            user_id=student_id,
            exam_id=exam_id
        ).first()

        if active_session:
             db.session.delete(active_session)

        session_key = f'exam_start_time_{exam_id}'
        session.pop(session_key, None) 
        
        app.logger.warning(f"[ADMIN_ACTION] Admin '{current_user.username}' canceló manualmente el examen {exam_id} para el usuario '{student.username}'. Motivo: {reason}")
        db.session.commit()

        socketio.emit('exam_cancelled_alert', 
                      {'exam_id': exam_id, 'reason': reason}, 
                      room=str(student_id)) 

        return jsonify({'success': True, 
                        'message': f'Examen {exam.title} CANCELADO para el alumno {student.username}. Notificación enviada.',
                        'reason': reason})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al cancelar examen: {e}")
        return jsonify({'success': False, 'message': f'Error interno: {str(e)}'}), 500


@app.route("/admin/monitor/logs/<int:exam_id>/<int:user_id>")
@login_required
def view_violation_logs(exam_id, user_id):
    if current_user.role != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("dashboard"))
        
    student = User.query.get_or_404(user_id)
    exam = Exam.query.get_or_404(exam_id)
    
    utc_tz = pytz.utc
    mexico_tz = pytz.timezone('America/Mexico_City')
    logs = ViolationLog.query.filter_by(
        user_id=user_id, 
        exam_id=exam_id
    ).order_by(ViolationLog.timestamp.desc()).all()

    for log in logs:
        if log.timestamp:
            aware_utc_time = utc_tz.localize(log.timestamp)
            mexico_time = aware_utc_time.astimezone(mexico_tz)
            log.timestamp = mexico_time
    
    return render_template("admin_violation_logs.html", 
                           student=student, 
                           exam=exam, 
                           logs=logs)


@app.route("/admin/announcements/new", methods=["GET", "POST"])
@login_required
def new_announcement():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = request.form["title"]
        
        unsafe_content = request.form["content"]
        
        # 🔥 LIMPIEZA ACTUALIZADA QUE PERMITE ESTILOS 🔥
        # Se agrega el argumento styles=ALLOWED_STYLES para soportar el formato de CKEditor
        content = bleach.clean(unsafe_content, 
                               tags=ALLOWED_TAGS, 
                               attributes=ALLOWED_ATTRIBUTES,
                               styles=ALLOWED_STYLES) 

        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(url_for("new_announcement"))

        current_time_utc = datetime.utcnow()

        announcement = Announcement(
            title=title,
            content=content, 
            admin_id=current_user.id, 
            date_published=current_time_utc 
        )
        db.session.add(announcement)
        db.session.commit()

        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} created new announcement '{title}'.")
        
        all_students = User.query.filter_by(role='student', is_active=True).all()
        notification_body = f"Nuevo Anuncio Crítico: '{title}'. Revisa la plataforma para leer el mensaje completo."
        
        for student in all_students:
            if student.phone_number:
                send_dummy_notification(student.phone_number, notification_body)
                
        # 🔥 NUEVO: Emitir evento de nuevo reporte
        socketio.emit('new_activity', {
            'msg': f"📢 Admin publicó nuevo anuncio: {title}",
            'type': 'info'
        }, room='admin_pulse_room')

        flash("Anuncio creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_announcement.html")

@app.route("/admin/announcements/edit/<int:announcement_id>", methods=["GET", "POST"])
@login_required
def edit_announcement(announcement_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    announcement = Announcement.query.get_or_404(announcement_id)

    if request.method == "POST":
        title = request.form["title"]
        
        unsafe_content = request.form["content"]
        
        # 🔥 LIMPIEZA ACTUALIZADA QUE PERMITE ESTILOS 🔥
        content = bleach.clean(unsafe_content, 
                               tags=ALLOWED_TAGS, 
                               attributes=ALLOWED_ATTRIBUTES,
                               styles=ALLOWED_STYLES) # <-- AGREGADO: Permite CSS en línea
        
        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(url_for("edit_announcement", announcement_id=announcement_id))
            
        announcement.title = title
        announcement.content = content 
        announcement.is_active = 'is_active' in request.form 
        
        db.session.commit()
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} edited announcement ID {announcement_id}.")
        flash("Anuncio actualizado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("edit_announcement.html", announcement=announcement)

@app.route("/admin/announcements/delete/<int:announcement_id>", methods=["POST"])
@login_required
def delete_announcement(announcement_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    announcement_to_delete = Announcement.query.get_or_404(announcement_id)
    
    try:
        db.session.delete(announcement_to_delete)
        db.session.commit()
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} deleted announcement '{announcement_to_delete.title}' (ID: {announcement_id}).")
        flash(f"Anuncio '{announcement_to_delete.title}' ha sido eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el anuncio: {e}", "danger")

    return redirect(url_for("admin_panel"))


@app.route("/admin/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@login_required
def edit_exam(exam_id):
    # ... (código inicial de verificación de rol y obtención de exam/students) ...
    exam = Exam.query.get_or_404(exam_id)
    students = User.query.filter(User.role.notin_(['admin', 'ayudante'])).order_by(User.username).all()

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")
        
        # Inicializa las variables para evitar el error si no hay fechas
        start_dt = None
        end_dt = None
        
        # 🔥 CÓDIGO FALTANTE: CONVERTIR STRING A DATETIME 🔥
        try:
            if start_date_str:
                # El formato '%Y-%m-%dT%H:%M' es el que usan los inputs HTML type="datetime-local"
                start_dt = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Formato de fecha y hora inválido. Usa el formato AAAA-MM-DD HH:MM.", "danger")
            # Redirige para no seguir con un error
            return redirect(url_for("edit_exam", exam_id=exam_id))
        
        # --- AHORA PUEDES USAR start_dt y end_dt ---
        
        exam.title = title
        exam.description = description
        exam.start_datetime = start_dt  # ¡Aquí ya está definida!
        exam.end_datetime = end_dt      # ¡Aquí ya está definida!

        # ... (Resto del código para actualizar assigned_students) ...

        # 🔥 ACTUALIZAR LISTA DE ALUMNOS 🔥
        selected_student_ids = request.form.getlist("assigned_students")
        
        # Limpiar lista anterior y agregar los nuevos
        exam.assigned_students = [] 
        for student_id in selected_student_ids:
            student = User.query.get(int(student_id))
            if student:
                exam.assigned_students.append(student)

        db.session.commit()
        
        app.logger.info(f"User {current_user.username} edited exam '{title}' (ID: {exam.id}).")

        flash("Examen actualizado correctamente.", "success")
        return redirect(url_for("admin_panel"))

    def format_datetime_local(dt_obj):
        if dt_obj:
            return dt_obj.strftime('%Y-%m-%dT%H:%M')
        return ''

    return render_template(
        "edit_exam.html", 
        exam=exam, 
        students=students, # <-- Pasar lista completa
        start_date_str=format_datetime_local(exam.start_datetime),
        end_date_str=format_datetime_local(exam.end_datetime)
    )
    
@app.route("/admin/exams/new", methods=["GET", "POST"])
@login_required
def new_exam():
    # 1. Verificación de permisos
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop('just_logged_in', None)
    
    # 2. Obtener lista de estudiantes para mostrar en el formulario
    students = User.query.filter(
        User.role.notin_(['admin', 'ayudante'])
    ).order_by(User.username).all()

    # 3. Procesar el formulario (POST)
    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")
        
        start_dt = None
        end_dt = None
        
        # Validación de fechas
        try:
            if start_date_str:
                start_dt = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Formato de fecha y hora inválido. Usa el formato YYYY-MM-DD HH:MM.", "danger")
            return redirect(url_for("new_exam"))
        
        # Validación de título
        if len(title.strip()) == 0:
            flash("El título del examen no puede estar vacío.", "danger")
            return redirect(url_for("new_exam"))
        
        # Crear objeto Examen
        exam = Exam(
            title=title, 
            description=description,
            start_datetime=start_dt, 
            end_datetime=end_dt
        )
        
        # 🔥 RECOGER ALUMNOS SELECCIONADOS 🔥
        selected_student_ids = request.form.getlist("assigned_students")
        
        # Asignar los alumnos al objeto examen
        for student_id in selected_student_ids:
            student = User.query.get(int(student_id))
            if student:
                exam.assigned_students.append(student)

        # Guardar en base de datos
        db.session.add(exam)
        db.session.commit()
        
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} created new exam '{title}'.")

        flash("Examen creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    # 4. Renderizar plantilla (GET)
    return render_template("new_exam.html", students=students)


@app.route("/admin/exams/duplicate/<int:exam_id>", methods=["POST"])
@login_required
def duplicate_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    original_exam = Exam.query.get_or_404(exam_id)
    
    try:
        new_exam = Exam(
            title=f"{original_exam.title} (Copia - {datetime.now().strftime('%Y%m%d%H%M%S')})",
            description=original_exam.description,
            start_datetime=original_exam.start_datetime,
            end_datetime=original_exam.end_datetime,
            is_cancelled=False,
            cancellation_reason=None
        )
        db.session.add(new_exam)
        db.session.flush()

        for question in original_exam.questions:
            new_question = Question(
                text=question.text,
                option_a=question.option_a,
                option_b=question.option_b,
                option_c=question.option_c,
                option_d=question.option_d,
                correct_option=question.correct_option,
                image_filename=question.image_filename,
                subject=question.subject,
                exam_id=new_exam.id,
                # 🔥 COPIAR CAMPOS DE RENDIMIENTO MANUAL 🔥
                times_answered=question.times_answered,
                correct_answers=question.correct_answers,
                difficulty_score=question.difficulty_score,
                manual_difficulty=question.manual_difficulty
            )
            db.session.add(new_question)
            
        db.session.commit()
        
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} duplicated exam '{original_exam.title}' to '{new_exam.title}'.")
        flash(f"Examen '{original_exam.title}' duplicado correctamente a '{new_exam.title}'.", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error al duplicar el examen: {e}", "danger")

    return redirect(url_for("admin_panel"))


@app.route("/admin/exams/<int:exam_id>/questions", methods=["GET", "POST"])
@login_required
def add_question(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop('just_logged_in', None) 
        
    exam = Exam.query.get_or_404(exam_id)

    if request.method == "POST":
        
        text = request.form["text"]
        subject = request.form.get("subject")
        option_a = request.form.get("option_a")
        option_b = request.form.get("option_b")
        option_c = request.form.get("option_c")
        option_d = request.form.get("option_d")
        correct_option = request.form.get("correct_option")
        manual_difficulty = request.form.get("manual_difficulty") # <-- NUEVO CAMPO
        
        if not text or not correct_option:
            flash("El texto de la pregunta y la opción correcta son obligatorios.", "danger")
            return redirect(url_for("add_question", exam_id=exam_id))

        image_filename = None

        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename:
                
                # --- 🔥 ¡INICIO DE VALIDACIÓN DE ARCHIVO! (Usando filetype) 🔥 ---
                try:
                    header = file.read(2048) 
                    file.stream.seek(0) 
                    
                    kind = filetype.guess(header)
                    if kind is None or kind.mime not in ALLOWED_MIMETYPES:
                        file_mime = kind.mime if kind else 'unknown'
                        app.logger.warning(f"SECURITY: {current_user.username} intentó subir un archivo no permitido ({file_mime}) en add_question.")
                        flash(f"Error: Tipo de archivo no permitido ({file_mime}). Solo se aceptan JPEG, PNG o GIF.", "danger")
                        return redirect(url_for('add_question', exam_id=exam_id))

                except Exception as e:
                    app.logger.error(f"Error con 'filetype' al validar archivo: {e}")
                    flash("Error al validar el tipo de archivo.", "danger")
                    return redirect(url_for('add_question', exam_id=exam_id))
                # --- 🔥 FIN DE VALIDACIÓN DE ARCHIVO! 🔥 ---

                image_filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'images')
                os.makedirs(upload_folder, exist_ok=True)
                file.save(os.path.join(upload_folder, image_filename))

        question = Question(
            text=text,
            subject=subject,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_option=correct_option,
            image_filename=image_filename,
            exam_id=exam_id,
            manual_difficulty=manual_difficulty # <-- NUEVO CAMPO
        )
        db.session.add(question)
        db.session.commit()
        
        flash("Pregunta agregada correctamente", "success")

    questions = Question.query.filter_by(exam_id=exam_id).all()
    return render_template("add_question.html", exam=exam, questions=questions)


@app.route("/admin/exam/<int:exam_id>/import_csv", methods=["POST"])
@login_required
@limiter.limit("10 per hour") 
def import_csv(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    
    if 'csv_file' not in request.files:
        flash("No se encontró ningún archivo en la solicitud.", "danger")
        return redirect(url_for('add_question', exam_id=exam_id))

    file = request.files['csv_file']

    if file.filename == '':
        flash("No se seleccionó ningún archivo.", "warning")
        return redirect(url_for('add_question', exam_id=exam_id))

    if not file.filename.endswith('.csv'):
        flash("Error: El archivo debe tener la extensión .csv", "danger")
        return redirect(url_for('add_question', exam_id=exam_id))

    questions_added = 0
    errors = []

    try:
        file.stream.seek(0)
        data = io.TextIOWrapper(file.stream, encoding='utf-8-sig')
        reader = csv.reader(data)
        
        try:
            header = next(reader)
        except StopIteration:
            flash("Error: El archivo CSV está vacío.", "danger")
            return redirect(url_for('add_question', exam_id=exam_id))
        
        for i, row in enumerate(reader):
            row_num = i + 2 
            try:
                if len(row) != 7:
                    errors.append(f"Fila {row_num}: Se esperaban 7 columnas, pero se encontraron {len(row)}.")
                    continue
                
                subject = row[0].strip()
                text = row[1].strip()
                option_a = row[2].strip()
                option_b = row[3].strip()
                option_c = row[4].strip()
                option_d = row[5].strip()
                correct_option = row[6].strip().upper()
                
                # NO hay campo de dificultad manual en el CSV, usamos el valor por defecto ('Medium')

                if not all([subject, text, option_a, option_b, correct_option]):
                    errors.append(f"Fila {row_num}: Faltan datos obligatorios (Materia, Texto, Opción A, Opción B, Respuesta Correcta).")
                    continue
                
                if correct_option not in ['A', 'B', 'C', 'D']:
                    errors.append(f"Fila {row_num}: La respuesta correcta '{correct_option}' no es válida (debe ser A, B, C, o D).")
                    continue

                new_question = Question(
                    exam_id=exam.id,
                    subject=subject,
                    text=text,
                    option_a=option_a,
                    option_b=option_b,
                    option_c=option_c if option_c else None,
                    option_d=option_d if option_d else None,
                    correct_option=correct_option,
                    manual_difficulty='Medium' # <-- Usar valor por defecto
                )
                db.session.add(new_question)
                questions_added += 1

            except Exception as e:
                errors.append(f"Fila {row_num}: Error inesperado - {e}")

        if questions_added > 0:
            db.session.commit()
            flash(f"¡Éxito! Se importaron {questions_added} preguntas.", "success")
        
        if errors:
            for error in errors:
                flash(error, "danger")
        
        if questions_added == 0 and not errors:
             flash("El archivo estaba vacío o no contenía datos válidos.", "warning")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al importar CSV para examen {exam_id}: {e}")
        flash(f"Error crítico al procesar el archivo: {e}", "danger")

    return redirect(url_for('add_question', exam_id=exam_id))


@app.route("/admin/questions/edit/<int:question_id>", methods=["GET", "POST"])
@login_required
def edit_question(question_id):
    # ... (verificación de rol) ...
    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id

    if request.method == "POST":
        question.text = request.form["text"]
        # ... (actualizar subject, options, correct_option, manual_difficulty...) ...

        # 🔥 LÓGICA PARA ACTUALIZAR IMAGEN 🔥
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename:
                # (Tu validación de filetype aquí si la usas)
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, 'static/images', filename))
                question.image_filename = filename # Actualizar nombre en DB

        db.session.commit()
        flash("Pregunta actualizada correctamente", "success")
        return redirect(url_for("add_question", exam_id=exam_id))

    return render_template("edit_question.html", question=question, exam_id=exam_id)

@app.route("/admin/questions/move/<int:question_id>/<direction>")
@login_required
def move_question(question_id, direction):
    if current_user.role not in ["admin", "ayudante"]:
        return jsonify({'success': False}), 403

    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id
    current_order = question.order_index

    if direction == 'up':
        # Buscar la pregunta que está justo antes (orden menor)
        swap_target = Question.query.filter(
            Question.exam_id == exam_id, 
            Question.order_index < current_order
        ).order_by(Question.order_index.desc()).first()
    else: # down
        # Buscar la pregunta que está justo después (orden mayor)
        swap_target = Question.query.filter(
            Question.exam_id == exam_id, 
            Question.order_index > current_order
        ).order_by(Question.order_index.asc()).first()

    if swap_target:
        # Intercambiar los índices de orden
        question.order_index, swap_target.order_index = swap_target.order_index, question.order_index
        db.session.commit()
    
    return redirect(url_for('add_question', exam_id=exam_id))

@app.route("/admin/questions/delete/<int:question_id>", methods=["POST"])
@login_required
def delete_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    question_to_delete = Question.query.get_or_404(question_id)
    exam_id = question_to_delete.exam_id
    
    try:
        db.session.delete(question_to_delete)
        db.session.commit()
        app.logger.info(f"AUDIT LOG: User {current_user.username} deleted question ID {question_id} from Exam ID {exam_id}.")
        flash("Pregunta eliminada correctamente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar la pregunta: {e}", "danger")

    return redirect(url_for("add_question", exam_id=exam_id))


@app.route("/admin/exams/delete/<int:exam_id>", methods=["POST"])
@login_required
def delete_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    exam_to_delete = Exam.query.get_or_404(exam_id)
    
    try:
        db.session.delete(exam_to_delete)
        db.session.commit()
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} deleted exam '{exam_to_delete.title}' (ID: {exam_id}).")
        flash(f"Examen '{exam_to_delete.title}' y todos sus datos han sido eliminados.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el examen: {e}", "danger")

    return redirect(url_for("admin_panel"))

@app.route("/admin/export/results")
@login_required
def export_results():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    all_results = db.session.query(
        User.username,
        Exam.title,
        ExamResult.score,
        ExamResult.date_taken
    ).join(Exam, ExamResult.exam_id == Exam.id
    ).join(User, ExamResult.user_id == User.id
    ).order_by(ExamResult.date_taken.desc()
    ).all()

    csv_content = "Alumno,Examen,Puntuacion Final,Fecha de Presentacion\n"
    
    for username, title, score, date_taken in all_results:
        date_str = date_taken.strftime("%Y-%m-%d %H:%M:%S")
        csv_content += f'"{username}","{title}",{score:.2f},"{date_str}"\n'

    response = Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=Reporte_Calificaciones_ECOMS.csv",
            "Content-type": "text/csv; charset=utf-8"
        }
    )
    return response

@app.route("/admin/exams/<int:exam_id>/answers")
@login_required
def view_answers(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
        
    session.pop('just_logged_in', None) 
    
    exam = Exam.query.get_or_404(exam_id)

    results = db.session.query(
        User.username, 
        ExamResult.score,
        ExamResult.date_taken,
        User.id.label('user_id'),
        ExamResult.submission_type 
    ).join(ExamResult, User.id == ExamResult.user_id
    ).filter(ExamResult.exam_id == exam_id
    ).order_by(ExamResult.date_taken.desc()
    ).all()
    
    return render_template("review_results.html", exam=exam, results=results)


@app.route("/admin/exams/<int:exam_id>/review/<int:user_id>")
@login_required
def review_student_exam(exam_id, user_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    exam = Exam.query.get_or_404(exam_id)
    student = User.query.get_or_404(user_id)
    
    result = ExamResult.query.filter_by(
        user_id=user_id,
        exam_id=exam_id
    ).first()
    
    review_data_query = db.session.query(
        Question, 
        Answer
    ).outerjoin(Answer, (Answer.question_id == Question.id) & (Answer.user_id == user_id))\
     .filter(Question.exam_id == exam_id)\
     .order_by(Question.id)\
     .all()
    
    return render_template(
        "review_detail.html", 
        exam=exam, 
        student=student, 
        review_data=review_data_query,
        result=result 
    )


@app.route("/admin/exams/<int:exam_id>/reset_attempt/<int:user_id>", methods=["POST"])
@login_required
def reset_exam_attempt(exam_id, user_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    exam = Exam.query.get_or_404(exam_id)
    student = User.query.get_or_404(user_id)
    
    question_ids = [q.id for q in exam.questions]
    
    answers_to_delete = Answer.query.filter(
        Answer.user_id == user_id,
        Answer.question_id.in_(question_ids)
    ).all()

    for answer in answers_to_delete:
        db.session.delete(answer)

    result_to_delete = ExamResult.query.filter_by(
        user_id=user_id,
        exam_id=exam_id
    ).first()

    if result_to_delete:
        db.session.delete(result_to_delete)
        
    session_key = f'exam_start_time_{exam_id}'
    session.pop(session_key, None) 
    
    db.session.commit()
    
    app.logger.warning(f"[ADMIN_ACTION] Admin '{current_user.username}' reinició el intento del examen '{exam.title}' (ID: {exam_id}) para el usuario '{student.username}' (ID: {user_id}).")
    
    flash(f"El intento de examen de '{exam.title}' para el alumno '{student.username}' ha sido reiniciado. Puede presentarlo de nuevo.", "success")
    return redirect(url_for('view_answers', exam_id=exam_id))

# --- 🔥 ¡INICIO DE NUEVA RUTA! 🔥 ---
@app.route("/admin/exams/release_answers/<int:exam_id>", methods=["POST"])
@login_required
def release_answers(exam_id):
    """
    Permite a un admin "liberar" las respuestas de un examen,
    haciendo que las revisiones de los alumnos muestren las respuestas correctas.
    """
    if current_user.role != "admin":
        app.logger.warning(f"SECURITY: Usuario no admin {current_user.username} intentó liberar respuestas.")
        flash("Acceso denegado.", "danger")
        return redirect(url_for("dashboard"))
    
    exam = Exam.query.get_or_404(exam_id)
    
    if not exam.answers_released:
        exam.answers_released = True
        db.session.commit()
        app.logger.warning(f"[ADMIN_ACTION] Admin '{current_user.username}' liberó las respuestas para el examen '{exam.title}' (ID: {exam_id}).")
        flash(f"¡Éxito! Las respuestas para '{exam.title}' ahora son visibles para todos los alumnos que lo presentaron.", "success")
    else:
        flash("Las respuestas para este examen ya habían sido liberadas.", "info")

    return redirect(url_for('view_answers', exam_id=exam_id))
# --- 🔥 ¡FIN DE NUEVA RUTA! 🔥 ---


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop('just_logged_in', None) 
    
    show_inactive = request.args.get('show_inactive', '0') == '1'
    
    query = User.query.order_by(User.username)
    
    if not show_inactive:
        query = query.filter_by(is_active=True) 

    users = query.all()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "student")
        
        phone_number = request.form.get("phone_number")
        
        if not username or not password:
            flash("El nombre de usuario y la contraseña son obligatorios.", "danger")
            return redirect(url_for("manage_users"))
        
        if not re.match(r'^[a-zA-Z0-9_]{3,150}$', username):
            flash("El nombre de usuario debe tener entre 3 y 150 caracteres y solo contener letras, números y '_'.", "danger")
            return redirect(url_for("manage_users"))
        
        if phone_number and not re.match(r'^\+[1-9]\d{7,14}$', phone_number):
            flash("Formato de número de teléfono inválido. Debe incluir el código de país (ej: +52XXXXXXXXXX).", "danger")
            return redirect(url_for("manage_users"))
        
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(
            username=username, 
            password=hashed_password, 
            role=role, 
            is_active=True,
            phone_number=phone_number if phone_number else None
        )
        db.session.add(new_user)
        
        try:
            db.session.commit()
            
            app.logger.info(f"AUDIT LOG: Admin user {current_user.username} created new user '{username}' ({role}).")

            flash(f"Usuario {username} ({role}) creado exitosamente.", "success")
            
        except IntegrityError:
            db.session.rollback()
            flash(f"Error: El usuario '{username}' ya existe. Por favor, elige otro nombre.", "danger")
        
        except Exception as e:
            db.session.rollback()
            flash(f"Error desconocido al crear el usuario: {e}", "danger")


        return redirect(url_for("manage_users"))

    return render_template("manage_users.html", users=users, show_inactive=show_inactive)


@app.route("/admin/users/toggle_status/<int:user_id>", methods=["POST"])
@login_required
def toggle_user_status(user_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    user_to_toggle = User.query.get_or_404(user_id)
    
    if user_to_toggle.username == "Gus": 
        flash("No puedes desactivar/eliminar al usuario administrador principal.", "danger")
    else:
        new_status = not user_to_toggle.is_active
        user_to_toggle.is_active = new_status
        db.session.commit()
        
        action = "activado" if new_status else "desactivado"
        
        app.logger.info(f"AUDIT LOG: Admin user {current_user.username} {action} user '{user_to_toggle.username}' (ID: {user_id}).")
        
        flash(f"Usuario {user_to_toggle.username} ha sido {action}.", "success")
        
        if user_to_toggle.id == current_user.id and not new_status:
             logout_user()
             flash("Tu propia cuenta ha sido desactivada. Debes volver a iniciar sesión.", "warning")
             return redirect(url_for('login'))
        
    return redirect(url_for("manage_users"))


@app.route('/admin/users/delete/<int:user_id>', methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Acceso denegado. Solo administradores pueden eliminar usuarios.', 'danger')
        return redirect(url_for('admin_panel'))
    
    user = db.session.get(User, user_id)
    
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('manage_users'))

    if user.username == 'Gus': 
        flash('No se puede eliminar el usuario administrador principal.', 'danger')
        return redirect(url_for('manage_users'))
        
    try:
        ExamResult.query.filter_by(user_id=user_id).delete()
        Answer.query.filter_by(user_id=user_id).delete()
        Report.query.filter_by(user_id=user_id).delete()
        AnnouncementReadStatus.query.filter_by(user_id=user_id).delete()
        ActiveExamSession.query.filter_by(user_id=user_id).delete()
        ViolationLog.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        app.logger.info(f'AUDIT LOG: Admin {current_user.username} permanently deleted user {user.username} (ID: {user_id}).')
        flash(f'Usuario {user.username} (ID: {user_id}) eliminado permanentemente junto con todos sus datos.', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error al eliminar usuario {user_id}: {e}')
        flash(f'Error crítico al eliminar el usuario: {e}', 'danger')
        
    return redirect(url_for('manage_users'))


@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    reports = Report.query.join(User, Report.user_id == User.id).order_by(Report.date_submitted.desc()).all()
    
    return render_template("admin_reports.html", reports=reports)


@app.route("/admin/reports/<int:report_id>", methods=["GET", "POST"])
@login_required
def view_report_detail(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)

    if request.method == "POST":
        return redirect(url_for("view_report_detail", report_id=report_id))

    return render_template("report_detail.html", report=report)

@app.route("/admin/reports/respond/<int:report_id>", methods=["POST"])
@login_required
def send_report_response(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)
    admin_response = request.form["admin_response"]

    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
    new_entry = f"\n\n--- Respuesta Admin ({timestamp}):\n{admin_response}"
    
    if report.admin_response:
        report.admin_response += new_entry
    else:
        report.admin_response = new_entry
        
    if report.status == 'En Proceso' or report.status == 'Cerrado':
        report.status = 'Abierto'
    
    report.date_resolved = datetime.utcnow()
    
    db.session.commit()
    flash(f"Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for("view_report_detail", report_id=report_id))


@app.route("/admin/reports/close/<int:report_id>", methods=["POST"])
@login_required
def close_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)
    
    if report.status != 'Cerrado':
        report.status = 'Cerrado'
        report.date_resolved = datetime.utcnow()
        db.session.commit()
        flash(f"Reporte #{report_id} marcado como CERRADO.", "success")
    
    return redirect(url_for("admin_reports"))

@app.route("/admin/reports/reopen/<int:report_id>", methods=["POST"])
@login_required
def reopen_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)
    
    if report.status == 'Cerrado':
        report.status = 'Abierto'
        report.date_resolved = None
        db.session.commit()
        flash(f"Reporte #{report_id} REABIERTO correctamente.", "success")
    
    return redirect(url_for("view_report_detail", report_id=report_id))


@app.route("/admin/announcements/status")
@login_required
def admin_announcement_read_status():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    announcements = Announcement.query.order_by(Announcement.date_published.desc()).all()
    all_students = User.query.filter_by(role='student', is_active=True).order_by(User.username).all() 
    
    read_statuses = AnnouncementReadStatus.query.all()
    read_map = {}
    
    for status in read_statuses:
        if status.announcement_id not in read_map:
            read_map[status.announcement_id] = set()
        read_map[status.announcement_id].add(status.user_id)
        
    return render_template(
        "admin_announcement_status.html", 
        announcements=announcements,
        all_students=all_students,
        read_map=read_map
    )


# ======================================================================
# --- RUTAS DE ALUMNO (Exámenes, Reportes, Anuncios) ---
# ======================================================================

@app.route("/update_phone_number", methods=["POST"])
@login_required
def update_phone_number():
    if current_user.role != "student":
        return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403
    
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
    except Exception:
        return jsonify({'success': False, 'message': 'Datos JSON inválidos.'}), 400

    if not phone_number or not re.match(r'^\+[1-9]\d{7,14}$', phone_number):
        return jsonify({'success': False, 'message': 'Formato de número inválido. Debe incluir código de país (ej: +52XXXXXXXXXX).'}), 400

    try:
        current_user.phone_number = phone_number
        db.session.commit()
        app.logger.info(f"AUDIT LOG: User {current_user.username} updated phone number to {phone_number}.")
        return jsonify({'success': True, 'message': 'Número de teléfono guardado correctamente.'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al guardar número de teléfono para user {current_user.username}: {e}")
        return jsonify({'success': False, 'message': 'Error interno al guardar los datos.'}), 500


@app.route("/reports/new", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour") 
def new_report():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        title = request.form["title"]
        # --- 🔥 ¡BUG CORREGIDO! (description en lugar de content) 🔥 ---
        content = request.form.get("description") 
        image_filename = None

        if len(title.strip()) == 0 or len(title) > 255:
            flash("El título del reporte es inválido o excede el límite de 255 caracteres.", "danger")
            return redirect(url_for("new_report"))

        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename:
                
                # --- 🔥 ¡INICIO DE VALIDACIÓN DE ARCHIVO! (Usando filetype) 🔥 ---
                try:
                    header = file.read(2048) 
                    file.stream.seek(0) 
                    
                    kind = filetype.guess(header)
                    if kind is None or kind.mime not in ALLOWED_MIMETYPES:
                        file_mime = kind.mime if kind else 'unknown'
                        app.logger.warning(f"SECURITY: {current_user.username} intentó subir un archivo no permitido ({file_mime}) en new_report.")
                        flash(f"Error: Tipo de archivo no permitido ({file_mime}). Solo se aceptan JPEG, PNG o GIF.", "danger")
                        return redirect(url_for('new_report'))

                except Exception as e:
                    app.logger.error(f"Error con 'filetype' al validar archivo: {e}")
                    flash("Error al validar el tipo de archivo.", "danger")
                    return redirect(url_for('new_report'))
                # --- 🔥 FIN DE VALIDACIÓN DE ARCHIVO! 🔥 ---

                image_filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'images')
                os.makedirs(upload_folder, exist_ok=True)
                file.save(os.path.join(upload_folder, image_filename))

        current_time_utc = datetime.utcnow()

        report = Report(
            title=title,
            content=content, # <-- Usar la variable 'content' corregida
            user_id=current_user.id,
            image_filename=image_filename,
            status='Abierto',
            date_submitted=current_time_utc 
        )
        db.session.add(report)
        db.session.commit()

        # 🔥 NUEVO: Emitir evento de nuevo reporte
        socketio.emit('new_activity', {
            'msg': f"🚨 ¡NUEVO REPORTE! {current_user.username} reportó: {title}",
            'type': 'danger'
        }, room='admin_pulse_room')

        flash("Reporte enviado correctamente. Pronto el administrador dará una solución.", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_report.html", user=current_user)

@app.route("/student/reports") 
@login_required
def student_reports():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    session.pop('just_logged_in', None) 
    
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).all()
    
    for report in reports:
        if report.admin_response and report.date_resolved:
            session_key = f'report_seen_{report.id}_{report.date_resolved.strftime("%Y%m%d%H%M")}'
            session[session_key] = True 
            
    
    return render_template("student_reports.html", reports=reports)

@app.route("/reports/reply/<int:report_id>", methods=["POST"])
@login_required
@limiter.limit("30 per hour") 
def reply_to_report(report_id):
    report = Report.query.get_or_404(report_id)

    if report.status == 'Cerrado':
        flash("No puedes responder a un reporte cerrado.", "danger")
        return redirect(url_for('student_reports'))

    if report.user_id != current_user.id:
        flash("Acceso denegado.", "danger")
        return redirect(url_for('student_reports'))

    student_response = request.form["student_response"]
    
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
    new_entry = f"\n\n--- Respuesta Alumno ({timestamp}):\n{student_response}"
    
    if report.admin_response:
        report.admin_response += new_entry
    else:
        report.admin_response = new_entry
        
    if report.status == 'En Proceso' or report.status == 'Cerrado':
        report.status = 'Abierto'
    
    db.session.commit()
    flash(f"Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for('student_reports'))


@app.route("/announcements")
@login_required
def view_announcements():
    session.pop('just_logged_in', None)
    
    all_announcements = Announcement.query.filter_by(is_active=True).join(User, Announcement.admin_id == User.id).order_by(Announcement.date_published.desc()).all()
    
    read_statuses = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).all()
    read_ids = {status.announcement_id for status in read_statuses}
    
    announcements_with_status = []
    for ann in all_announcements:
        announcements_with_status.append({
            'announcement': ann,
            'is_new': ann.id not in read_ids
        })

    return render_template(
        "view_announcements.html", 
        announcements=announcements_with_status
    )

@app.route("/announcements/mark_read/<int:announcement_id>")
@login_required
def mark_announcement_read(announcement_id):
    session.pop('just_logged_in', None) 
    
    status = AnnouncementReadStatus.query.filter_by(
        user_id=current_user.id,
        announcement_id=announcement_id
    ).first()
    
    if not status:
        new_status = AnnouncementReadStatus(
            user_id=current_user.id,
            announcement_id=announcement_id
        )
        db.session.add(new_status)
        db.session.commit()
    
    return '', 204 # Retorna un status 204 No Contenido


@app.route("/exams")
@login_required
def exams_list():
    session.pop('just_logged_in', None) 
    current_time = datetime.utcnow()
    
    exams = Exam.query.filter(
        (Exam.start_datetime == None) | (Exam.start_datetime <= current_time)
    ).filter(
        (Exam.end_datetime == None) | (Exam.end_datetime >= current_time)
    ).all()
    visible_exams = [
        e for e in exams 
        if current_user in e.assigned_students or not e.assigned_students
    ]
    return render_template("exams.html", exams=exams, current_time=current_time)


@app.route("/exam/save_answer", methods=["POST"])
@login_required
@limiter.limit("100 per 10 minutes") 
def save_answer():
    if current_user.role != "student":
        return jsonify({'success': False, 'message': 'Acceso denegado'}), 403
    
    data = request.get_json()
    question_id = data.get('question_id')
    response = data.get('response')
    
    if not question_id or response is None:
        return jsonify({'success': False, 'message': 'Faltan datos de pregunta o respuesta.'}), 400

    question = Question.query.get(question_id)
    if not question:
        return jsonify({'success': False, 'message': 'Pregunta no encontrada.'}), 404

    active_session = ActiveExamSession.query.filter_by(
        user_id=current_user.id, 
        exam_id=question.exam_id
    ).first()

    if not active_session:
        return jsonify({'success': False, 'message': 'Tu sesión de examen no está activa o ya ha terminado.'}), 403

    start_time = active_session.start_time
    time_added = active_session.time_added_sec
    BASE_DURATION_SEC = 3 * 60 * 60 # 10800 (3 horas)
    end_time = start_time + dt.timedelta(seconds=(BASE_DURATION_SEC + time_added))
    current_time_utc = datetime.utcnow()

    if current_time_utc > end_time:
        app.logger.warning(f"SECURITY: Rechazado auto-save TARDÍO de {current_user.username} para QID {question_id}.")
        return jsonify({'success': False, 'message': 'Tu tiempo ha expirado. No se pueden guardar más respuestas.'}), 403

    answer = Answer.query.filter_by(
        user_id=current_user.id, 
        question_id=question_id
    ).first()

    if answer:
        answer.response = response
        action = 'updated'
    else:
        answer = Answer(
            response=response,
            user_id=current_user.id,
            question_id=question_id
        )
        db.session.add(answer)
        action = 'created'

    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Respuesta {action} para QID {question_id}'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving answer (QID: {question_id}, User: {current_user.username}): {e}")
        return jsonify({'success': False, 'message': 'Error interno al guardar los datos.'}), 500


@app.route("/exam/<int:exam_id>/take", methods=["GET", "POST"])
@login_required
def take_exam(exam_id):
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
    
    exam = Exam.query.get_or_404(exam_id)
    current_time = datetime.utcnow()

    # Validaciones de fechas del examen
    if exam.start_datetime and exam.start_datetime > current_time:
        flash("El examen aún no está disponible. Vuelve más tarde.", "danger")
        return redirect(url_for('exams_list'))
    
    if exam.end_datetime and exam.end_datetime < current_time:
        flash("El tiempo para tomar este examen ha expirado.", "danger")
        return redirect(url_for('exams_list'))

    # Verificar si ya existe un resultado FINAL
    existing_result = ExamResult.query.filter_by(
        user_id=current_user.id, 
        exam_id=exam_id
    ).first()
    
    if existing_result:
        if existing_result.score >= 0.0:
            flash("Ya has completado este examen. No se permiten múltiples intentos.", "warning")
            return redirect(url_for('student_exam_detail', exam_id=exam.id))
        elif existing_result.score == -1.0:
            flash("Tu examen fue cancelado y está bloqueado. Contacta a un administrador.", "danger")
            return redirect(url_for('dashboard')) 


    # --- LÓGICA POST (Envío de respuestas o inicio de timer) ---
    if request.method == "POST":
        
        # 1. INICIAR EXAMEN (Botón "Comenzar")
        if request.form.get('action') == 'start_timer_now':
            try:
                # Verificar si ya existe sesión para no duplicar
                active_session = ActiveExamSession.query.filter_by(
                    user_id=current_user.id,
                    exam_id=exam_id
                ).first()

                if not active_session:
                    # CREAR NUEVA SESIÓN EN DB (Esto pone el status en "Haciendo Examen")
                    new_session = ActiveExamSession(
                        user_id=current_user.id,
                        exam_id=exam_id,
                        start_time=datetime.utcnow(),
                        time_added_sec=0 
                    )
                    db.session.add(new_session)
                    db.session.commit()
                    
                    # Actualizar cookie del usuario con la nueva hora
                    session[f'exam_start_time_{exam_id}'] = int(datetime.now(pytz.utc).timestamp())
                    
                    # Notificar al Monitor del Admin
                    socketio.emit('new_activity', {
                        'msg': f"🚀 {current_user.username} acaba de empezar el examen {exam.title}!",
                        'type': 'success'
                    }, room='admin_pulse_room')
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error al iniciar examen: {e}")
                
            return '', 204 
            
        
        # 2. ENVIAR EXAMEN FINAL
        submission_type = request.form.get('submission_type', 'manual')
        
        active_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
        
        # Si no hay sesión activa, rechazar envío (evita dobles envíos)
        if not active_session:
            return redirect(url_for('student_exam_detail', exam_id=exam_id))

        # Validar tiempo límite (con gracia)
        start_time = active_session.start_time
        time_added = active_session.time_added_sec
        BASE_DURATION_SEC = 3 * 60 * 60 # 180 minutos
        end_time = start_time + dt.timedelta(seconds=(BASE_DURATION_SEC + time_added))
        
        grace_period = dt.timedelta(seconds=30 if submission_type == 'auto' else 5)

        if datetime.utcnow() > (end_time + grace_period):
            # Tiempo excedido: Eliminar sesión y redirigir
            db.session.delete(active_session)
            session.pop(f'exam_start_time_{exam_id}', None)
            db.session.commit()
            flash("El envío fue rechazado por tiempo excedido.", "danger")
            return redirect(url_for('dashboard'))

        # Procesar Calificación
        session.pop(f'exam_start_time_{exam_id}', None) 
        final_proctoring_data = session.pop(f'proctoring_data_{exam_id}', None)
        # 🔥 RECIBIR LA GRABACIÓN DEL FORMULARIO 🔥
        recording_json = request.form.get('recording_data')
        
        # Obtener JSON de Proctoring de la sesión (si existe)
        proctoring_session_key = f'proctoring_data_{exam_id}'
        final_proctoring_data = session.pop(proctoring_session_key, None) 

        total_score_sum = 0.0 
        all_questions = Question.query.filter_by(exam_id=exam_id).all()
        
        # Cargar respuestas del usuario
        final_answers = Answer.query.join(Question).filter(
            Answer.user_id == current_user.id,
            Question.exam_id == exam_id
        ).all()
        answers_dict = {a.question_id: a for a in final_answers}
        
        for question in all_questions:
            answer = answers_dict.get(question.id)
            grade = 0.0
            feedback_text = None
            
            if answer and answer.response:
                if question.correct_option:
                    if answer.response == question.correct_option:
                        grade = 1.0 
                        total_score_sum += 1.0
                        feedback_text = "¡Correcto!" 
                    else:
                        grade = 0.0
                        feedback_text = f"Incorrecto. La respuesta correcta era {question.correct_option}."
                else:
                    grade = None 
                
                answer.grade = grade
                answer.feedback = feedback_text
                
                # Actualizar estadísticas de pregunta (Simulador)
                if question.correct_option:
                    question.times_answered += 1
                    if grade == 1.0: question.correct_answers += 1
                    if question.times_answered > 0:
                        question.difficulty_score = question.correct_answers / question.times_answered
                    db.session.add(question)

        # Guardar Resultado Final
            result = ExamResult(
            user_id=current_user.id, 
            exam_id=exam_id, 
            score=total_score_sum, 
            date_taken=datetime.now(pytz.utc),
            submission_type=submission_type, 
            proctoring_data=final_proctoring_data,
            session_recording=recording_json #
        )
        db.session.add(result)
        db.session.delete(active_session) # Borrar sesión activa
        
        try:
            db.session.commit()
            
            submission_tag = "Automático" if submission_type == 'auto' else "Manual"
            score_int = int(total_score_sum)
            socketio.emit('new_activity', {
                'msg': f"✅ {current_user.username} terminó '{exam.title}'. Nota: {score_int}. ({submission_tag})",
                'type': 'success'
            }, room='admin_pulse_room')

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error commit final exam: {e}")
            flash("Error al guardar resultado.", "danger")
            return redirect(url_for('exams_list'))

        flash("Examen finalizado correctamente.", "success")
        return redirect(url_for('student_exam_detail', exam_id=exam.id))


    # --- LÓGICA GET (Carga de la página del examen) ---
    if request.method == "GET":
        session.pop('just_logged_in', None) 
        
        # 1. 🔥 CORRECCIÓN MAESTRA: PRIORIZAR LA DB SOBRE LA COOKIE 🔥
        active_session = ActiveExamSession.query.filter_by(
            user_id=current_user.id, 
            exam_id=exam_id
        ).first()
        
        session_key = f'exam_start_time_{exam_id}'

        if active_session:
            # Si hay sesión en DB, forzamos la hora real de la DB
            # Esto arregla el problema si la cookie estaba mal o borrada
            start_time_timestamp = active_session.start_time.replace(tzinfo=pytz.utc).timestamp()
            session[session_key] = int(start_time_timestamp) # Sincronizar cookie
            start_time = int(start_time_timestamp)
            time_added_sec = active_session.time_added_sec
        else:
            # Si NO hay sesión en DB (ej. después de un reset del admin),
            # FORZAMOS que el tiempo sea 0 para que salga el botón de "Comenzar".
            start_time = 0
            session.pop(session_key, None) # Borrar cookie basura
            time_added_sec = 0

        # -----------------------------------------------------------
        
        is_user_cancelled = False
        user_cancellation_reason = "" 

        if existing_result and existing_result.score == -1.0:
            is_user_cancelled = True
            user_cancellation_reason = exam.cancellation_reason or "Tu examen fue cancelado."

        saved_answers = Answer.query.filter_by(user_id=current_user.id).join(
            Question, Answer.question_id == Question.id
        ).filter(
            Question.exam_id == exam_id
        ).all()
        
        saved_answers_dict = {a.question_id: a.response for a in saved_answers}
        
        return render_template(
            "take_exam.html", 
            exam=exam,
            start_time_utc=start_time, # Ahora envía 0 si fue reseteado
            saved_answers=saved_answers_dict, 
            time_added_sec=time_added_sec,
            is_cancelled=is_user_cancelled,
            cancellation_reason=user_cancellation_reason
        )

@app.route("/student/exams") 
@login_required
def student_exams():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    session.pop('just_logged_in', None) 
    
    results = ExamResult.query.filter_by(user_id=current_user.id).order_by(ExamResult.date_taken.desc()).all()
    
    return render_template("student_exams.html", 
                           results=results,
                           Exam=Exam
                           )


@app.route("/student/exam/<int:exam_id>/detail")
@login_required
def student_exam_detail(exam_id):
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    session.pop('just_logged_in', None) 
    
    exam = Exam.query.get_or_404(exam_id)
    
    result = ExamResult.query.filter_by(
        user_id=current_user.id,
        exam_id=exam_id
    ).first()
    
    answers = Answer.query.join(Question).filter(
        Answer.user_id == current_user.id,
        Question.exam_id == exam_id
    ).all()
    
    answers_dict = {a.question_id: a for a in answers}
    
    if not result:
        flash("Aún no has completado este examen.", "danger")
        return redirect(url_for('student_exams'))
        
    return render_template(
        "student_exam_detail.html", 
        exam=exam, 
        answers_dict=answers_dict,
        result=result 
    )


# ======================================================================
# --- INICIALIZACIÓN DE LA APLICACIÓN (NUEVA ESTRUCTURA RECOMENDADA) ---
# ======================================================================

if __name__ == "__main__":
    with app.app_context():
        # 1. Crea todas las tablas DENTRO DEL CONTEXTO de la aplicación
        db.create_all()
        app.logger.info("Database tables checked and created if non-existent.")
        
        # 2. Creación del usuario Admin
        from werkzeug.security import generate_password_hash 
        
        # --- 🔥 ¡MODIFICACIÓN DE CREDENCIALES DE ADMIN! 🔥 ---
        if User.query.filter_by(username='Gus').first() is None: # <-- CAMBIADO
            hashed_password = generate_password_hash('241224', method="pbkdf2:sha256") # <-- CAMBIADO
            
            admin_user = User(
                username='Gus',
                password=hashed_password,
                role='admin',
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Initial 'Gus' user created with password: '241224'") # <-- CAMBIADO
        # --- 🔥 FIN DE MODIFICACIÓN 🔥 ---

    import os
    port = int(os.environ.get("PORT", 5000))
    # Esta línea debe quedar fuera del bloque 'with'
    socketio.run(app, host="0.0.0.0", port=port, debug=True)