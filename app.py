from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    Response,
    jsonify,
    make_response,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    UserMixin,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_babel import Babel, format_datetime
import datetime as dt
import os
import pytz
import pyotp
import qrcode
import base64
import unicodedata
import psutil
from io import BytesIO
import time
import re
import cloudinary
import cloudinary.uploader
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from sqlalchemy import func, case, or_, text
from sqlalchemy.exc import IntegrityError
from flask_socketio import SocketIO, emit, join_room, leave_room, ConnectionRefusedError
import csv
import io
import uuid
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import bleach
import filetype
import random

load_dotenv()

app = Flask(__name__)

# ======================================================================
# --- CONFIGURACIÓN DE BASE DE DATOS Y CLOUDINARY ---
# ======================================================================

# 1. Obtenemos la URL que te dio Heroku
database_url = os.environ.get('DATABASE_URL')

# 2. Corrección para Heroku: SQLAlchemy necesita 'postgresql://' en vez de 'postgres://'
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# 3. Fallback: Si no hay URL (estás en local), usa SQLite
if not database_url:
    database_url = 'sqlite:///curso_ecoms.db'

# --- CONFIGURACIÓN DE CLOUDINARY (Imágenes Inmortales) ---
cloudinary.config(
    cloud_name = "djisdkjkf",
    api_key = "718931262622593",
    api_secret = "tXTLBgTP9estWoakSSRMQp0tHLc", # 🔥 TU SECRETO REAL
    secure = True
)

print(f"🔌 CONECTANDO A: {database_url}") # Esto nos servirá para depurar si falla

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = 'clave_secreta_emergencia_2025'
# Aumentamos el límite a 100 MB para soportar la grabación de video/sesión
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- CONFIGURACIÓN PARA SUBIDA DE IMÁGENES DE PREGUNTAS (NUEVO) ---
UPLOAD_FOLDER = "static/uploads/questions"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ======================================================================
# --- FUNCIONES AUXILIARES (HELPERS) ---
# ======================================================================

def normalizar_texto(texto):
    if not texto:
        return ""
    
    # 1. Convertir a minúsculas
    texto = texto.lower()
    
    # 2. Quitar acentos (Separa la letra de la tilde y elimina la tilde)
    texto = ''.join(c for c in unicodedata.normalize('NFD', texto) if unicodedata.category(c) != 'Mn')
    
    # 3. Quitar TODOS los espacios (junto, separado, etc)
    texto = texto.replace(" ", "")
    
    return texto

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image_helper(file_obj, prefix="img"):
    """Sube una imagen a Cloudinary y retorna la URL segura."""
    if not file_obj or file_obj.filename == '':
        return None
    
    try:
        # Intentamos subir a Cloudinary
        upload_result = cloudinary.uploader.upload(file_obj)
        # Si funciona, devolvemos el link de internet (https://...)
        return upload_result['secure_url'] 
    except Exception as e:
        # Si falla, imprimimos el error y devolvemos None
        print(f"Error subiendo a Cloudinary: {e}") 
        return None

def generar_orden_comipems(exam_id):
    """
    Genera una lista de IDs de preguntas ordenadas aleatoriamente
    pero agrupadas por Materia (Subject), estilo examen real.
    """
    questions = Question.query.filter_by(exam_id=exam_id).all()
    
    if not questions:
        return []

    # Agrupar por materia
    materias = {}
    for q in questions:
        nombre_materia = getattr(q, 'subject', 'General') or 'General'
        
        if nombre_materia not in materias:
            materias[nombre_materia] = []
        materias[nombre_materia].append(q.id)
    
    # Revolver el orden de las materias
    nombres_materias = list(materias.keys())
    random.shuffle(nombres_materias)
    
    # Crear la lista final plana
    orden_final = []
    for nombre in nombres_materias:
        ids_preguntas = materias[nombre]
        random.shuffle(ids_preguntas) # Revolver las preguntas DENTRO de la materia
        orden_final.extend(ids_preguntas)
        
    return orden_final

def send_dummy_notification(to_number, body_message):
    app.logger.warning(
        f"DUMMY NOTIFICATION: Mensaje a {to_number} (Cuerpo: {body_message[:50]}...) NO ENVIADO. Twilio deshabilitado."
    )
    return False

# ======================================================================
# --- CONFIGURACIÓN DE COOKIES Y SEGURIDAD ---
# ======================================================================

is_production = "DATABASE_URL" in os.environ and "postgres" in os.environ.get("DATABASE_URL", "")

if is_production:
    print("🔒 MODO PRODUCCIÓN DETECTADO: Cookies Seguras ACTIVADAS")
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
else:
    print("🔓 MODO LOCAL DETECTADO: Cookies Seguras DESACTIVADAS")
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)

app.config["PERMANENT_SESSION_LIFETIME"] = dt.timedelta(minutes=30)
LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300

# ======================================================================
# --- LOGGING ---
# ======================================================================
app_log_handler = RotatingFileHandler(
    "app.log", maxBytes=10000000, backupCount=5, encoding="utf-8"
)
app_log_handler.setLevel(logging.INFO)
app_log_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s: %(message)s [en %(pathname)s:%(lineno)d]")
)
security_log_handler = RotatingFileHandler(
    "security.log", maxBytes=5000000, backupCount=3, encoding="utf-8"
)
security_log_handler.setLevel(logging.WARNING)
security_log_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
app.logger.addHandler(app_log_handler)
app.logger.addHandler(security_log_handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False
logging.getLogger("werkzeug").propagate = False
logging.getLogger("socketio").propagate = False
logging.getLogger("engineio").propagate = False
app.logger.info("Iniciando aplicación y configurando loggers...")

# ======================================================================
# --- INICIALIZACIÓN DE EXTENSIONES ---
# ======================================================================
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://",
)

socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

babel = Babel(app)

def get_locale_selector():
    if request and hasattr(request, "accept_languages"):
        return request.accept_languages.best_match(["es", "en"])
    return "es"

def get_timezone_selector():
    return "America/Mexico_City"

app.config["BABEL_DEFAULT_LOCALE"] = "es"
app.config["BABEL_DEFAULT_TIMEZONE"] = "America/Mexico_City"
app.jinja_env.globals.update(format_datetime=format_datetime)

@app.template_filter("cdmx_time")
def cdmx_time_filter(value, format="%d/%m/%Y %I:%M %p"):
    if value is None:
        return ""
    try:
        utc = pytz.timezone("UTC")
        cdmx = pytz.timezone("America/Mexico_City")
        if value.tzinfo is None:
            value = utc.localize(value)
        local_dt = value.astimezone(cdmx)
        return local_dt.strftime(format)
    except Exception as e:
        return str(value)

# ======================================================================
# --- LISTAS BLANCAS (SEGURIDAD) ---
# ======================================================================
ALLOWED_TAGS = ["b", "strong", "i", "em", "u", "br", "p", "div", "span", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote", "pre", "a", "img", "table", "thead", "tbody", "tr", "th", "td", "hr"]
ALLOWED_ATTRIBUTES = {
    "*": ["style", "class"],
    "a": ["href", "title", "target"],
    "img": ["src", "alt", "width", "height", "style"],
}
ALLOWED_STYLES = ["color", "background-color", "font-family", "font-weight", "font-size", "text-align", "text-decoration", "width", "height", "margin", "padding", "border"]
ALLOWED_MIMETYPES = ["image/jpeg", "image/png", "image/gif"]

# ======================================================================
# --- MODELOS DE BASE DE DATOS ---
# ======================================================================

exam_assignments = db.Table(
    "exam_assignments",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("exam_id", db.Integer, db.ForeignKey("exam.id"), primary_key=True),
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="student")
    
    # --- 🔥 AQUÍ AGREGAMOS EL BOLSILLO SECRETO 🔥 ---
    visible_password = db.Column(db.String(150), nullable=True)
    # -----------------------------------------------

    two_factor_secret = db.Column(db.String(32), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    phone_number = db.Column(db.String(20), nullable=True)
    current_session_token = db.Column(db.String(100), nullable=True, unique=True)
    
    # Relaciones (No las borres)
    results = db.relationship("ExamResult", backref="user", lazy=True)
    violation_logs = db.relationship("ViolationLog", backref="user", lazy=True)
class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_datetime = db.Column(db.DateTime, nullable=True)
    end_datetime = db.Column(db.DateTime, nullable=True)
    
    is_cancelled = db.Column(db.Boolean, default=False)
    
    # 🔥 AGREGA ESTA LÍNEA AQUÍ:
    is_paused = db.Column(db.Boolean, default=False) 
    
    cancellation_reason = db.Column(db.Text, nullable=True)
    
    # ... (el resto de tus relaciones déjalas igual) ...
    assigned_students = db.relationship(
        "User",
        secondary=exam_assignments,
        lazy="subquery",
        backref=db.backref("assigned_exams", lazy=True),
    )
    answers_released = db.Column(db.Boolean, default=False, nullable=False)
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
    image_filename = db.Column(db.String(255), nullable=True) # Imagen Principal
    image_a = db.Column(db.String(255), nullable=True)
    image_b = db.Column(db.String(255), nullable=True)
    image_c = db.Column(db.String(255), nullable=True)
    image_d = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(100), nullable=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    times_answered = db.Column(db.Integer, default=0, nullable=False)
    correct_answers = db.Column(db.Integer, default=0, nullable=False)
    difficulty_score = db.Column(db.Float, default=0.5, nullable=False)
    manual_difficulty = db.Column(db.String(20), default="Medium", nullable=False)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    grade = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)

class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date_taken = db.Column(db.DateTime)
    submission_type = db.Column(db.String(50), default="manual")
    question_order = db.Column(db.JSON, nullable=True)
    proctoring_data = db.Column(db.Text, nullable=True)
    session_recording = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "exam_id": self.exam_id,
            "score": self.score,
            "submission_type": self.submission_type,
            "date_taken": self.date_taken.isoformat() if self.date_taken else None,
            "proctoring_data": self.proctoring_data,
            "session_recording": self.session_recording,
        }

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_published = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    publisher = db.relationship("User", backref="announcements")
    is_active = db.Column(db.Boolean, default=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Abierto")
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reporter = db.relationship("User", backref="reports")
    admin_response = db.Column(db.Text, nullable=True)
    date_resolved = db.Column(db.DateTime, nullable=True)

class AnnouncementReadStatus(db.Model):
    __tablename__ = "announcement_read_status"
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey("announcement.id", ondelete="CASCADE"), primary_key=True)
    user = db.relationship("User", backref="read_announcements")
    announcement = db.relationship("Announcement", backref="read_by")

class ActiveExamSession(db.Model):
    __tablename__ = "active_exam_session"
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    time_added_sec = db.Column(db.Integer, default=0)
    violation_count = db.Column(db.Integer, default=0)
    user = db.relationship("User", backref=db.backref("active_session", uselist=False))

class ViolationLog(db.Model):
    __tablename__ = "violation_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    violation_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)

# ======================================================================
# --- MANEJADORES DE SOCKETIO ---
# ======================================================================
# ==========================================
# 🚦 SEMÁFORO DE RED (PING REAL)
# ==========================================

@socketio.on('report_network_status')
def handle_network_report(data):
    """
    Recibe la velocidad del alumno y la reenvía a la Torre de Control.
    Data esperada: {'latency': 150} (en milisegundos)
    """
    if not current_user.is_authenticated:
        return
    
    # Solo reenviamos si hay un administrador escuchando
    # Esto actualiza el puntito verde/rojo en tu tabla
    socketio.emit('client_ping_update', {
        'user_id': current_user.id,
        'latency': data.get('latency', 0)
    }, room='admin_pulse_room') # 'admin_pulse_room' es donde vive tu monitor
    
@socketio.on("connect")
def handle_connect():
    app.logger.info("Socket CONNECTED. Attempting to get user context.")
    if current_user.is_authenticated:
        join_room(str(current_user.id))
        
        if current_user.role in ["admin", "ayudante"]:
            join_room("admin_pulse_room")
            app.logger.info(f"Admin/Ayudante {current_user.username} unido a admin_pulse_room.")
            
        app.logger.info(f"Socket conectado y unido al room de usuario: User {current_user.username} (ID: {current_user.id})")

@socketio.on("send_message_from_student")
def handle_student_message(data):
    if not current_user.is_authenticated:
        return

    message_content = data.get("message")

    if message_content:
        # --- 🔥 1. GUARDAR EN BASE DE DATOS 🔥 ---
        # Buscamos al primer admin disponible (o lo dejamos genérico si tienes un user Admin fijo)
        # Para este ejemplo, asumiremos que el recipient es el Admin Principal (ID 1 o buscado)
        admin_user = User.query.filter_by(role='admin').first() 
        admin_id = admin_user.id if admin_user else 1 # Fallback

        new_msg = ChatMessage(
            sender_id=current_user.id,
            recipient_id=admin_id,
            message=message_content,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_msg)
        db.session.commit()
        # -----------------------------------------

        # ... (Tu código de emisión de SocketIO sigue igual aquí abajo) ...
        # Solo asegúrate de enviar el timestamp formateado si quieres
        timestamp_str = datetime.now().strftime("%H:%M:%S")
        
        message_data = {
            "sender": current_user.username,
            "message": message_content,
            "timestamp": timestamp_str,
            "is_student": True, 
            "user_id": current_user.id
        }
        
        # Envíos...
        emit("chat_notification", message_data, room=str(current_user.id), namespace="/")
        emit("chat_notification", message_data, room="admin_pulse_room", namespace="/")
        
        app.logger.info(f"CHAT LIVE: Alumno {current_user.username} envió: {message_content}")
        

@socketio.on('record_violation')
def handle_violation(data):
    # data trae: {'violation_type': 'Celular', 'image': 'data:image/jpeg;base64...'}
    
    if not current_user.is_authenticated:
        return

    user_id = current_user.id
    violation_type = data.get('violation_type', 'Conducta sospechosa')
    image_base64 = data.get('image') # El texto gigante (Base64)
    
    final_filename_or_url = None

    # Lógica Cloudinary: Subir directo a la nube
    if image_base64:
        try:
            # Cloudinary es inteligente: detecta el formato "data:image..." automáticamente.
            # No hace falta decodificar manualmente.
            
            upload_result = cloudinary.uploader.upload(
                image_base64,
                folder="ecoems_evidencias", # Carpeta en tu Cloudinary
                public_id=f"evidencia_{user_id}_{uuid.uuid4().hex[:8]}" # Nombre del archivo
            )
            
            # Obtenemos el LINK seguro (https://...)
            final_filename_or_url = upload_result.get('secure_url')
            
        except Exception as e:
            print(f"❌ Error subiendo a Cloudinary: {e}")

    # Guardar en Base de Datos
    # AHORA guardamos el LINK COMPLETO, no solo el nombre
    log = ViolationLog(
        user_id=user_id,
        exam_id=getattr(current_user, 'current_exam_id', None), 
        violation_type=violation_type,
        image_filename=final_filename_or_url # <--- Aquí va la URL de Cloudinary
    )
    db.session.add(log)
    db.session.commit()
    
    # (Opcional) Avisar al admin en vivo que llegó una foto nueva
    socketio.emit('new_evidence_alert', {'msg': 'Nueva infracción detectada'}, room='admin_pulse_room')
@socketio.on("send_individual_ping")
@login_required
def handle_individual_ping(data):
    if current_user.role != "admin":
        return

    target_user_id = data.get("user_id")
    message = data.get("message", "👋 El administrador te ha enviado una alerta de atención.")

    if target_user_id:
        socketio.emit(
            "student_notification",
            {
                "title": "⚠️ Atención Requerida",
                "message": message,
                "link": None,
            },
            room=str(target_user_id),
        )

@socketio.on("send_screen_flash")
@login_required
def handle_screen_flash(data):
    if current_user.role != "admin":
        return
    socketio.emit("trigger_flash_effect", {}, room=str(data.get("user_id")))

@socketio.on("send_global_broadcast")
@login_required
def handle_global_broadcast(data):
    if current_user.role != "admin":
        return

    mensaje = data.get("message", "")
    if mensaje:
        socketio.emit(
            "student_notification",
            {
                "title": "📢 Anuncio General",
                "message": mensaje,
                "link": None,
            },
        )

@socketio.on("disconnect")
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(str(current_user.id))
        app.logger.info(f"Socket desconectado: User {current_user.username} (ID: {current_user.id})")

@socketio.on("join_room")
def on_join(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return

    target_user_id = str(data.get("user_id"))
    join_room(target_user_id)
    app.logger.info(f"ADMIN CHAT: Admin {current_user.username} joined room {target_user_id}.")

    emit("status_update", {"msg": f"Conectado a la sala del alumno ID {target_user_id}."}, room=str(current_user.id))

@socketio.on("send_message_to_student")
def handle_admin_message(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return

    target_user_id = data.get("target_user_id")
    message_content = data.get("message")

    if target_user_id and message_content:
        # 1. GUARDAR EN BASE DE DATOS (Memoria Permanente)
        new_msg = ChatMessage(
            sender_id=current_user.id,
            recipient_id=int(target_user_id),
            message=message_content,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_msg)
        db.session.commit()

        # 2. ENVIAR POR SOCKET (Velocidad en Vivo)
        emit(
            "chat_notification",
            {
                "sender": "Admin",
                "message": message_content,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "is_student": False 
            },
            room=str(target_user_id),
            namespace="/",
        )
        
        # 3. LOG EN TERMINAL (El "chismoso" útil para ti)
        app.logger.info(f"CHAT: Admin {current_user.username} sent to ID {target_user_id}: {message_content[:30]}...")

@socketio.on("join_report_room")
def on_join_report_room(data):
    if not current_user.is_authenticated:
        return
    report_id = data.get("report_id")
    if report_id:
        room = f"report_{report_id}"
        join_room(room)
        app.logger.info(f"User {current_user.username} joined room {room}")

@socketio.on("send_admin_report_message")
def handle_admin_report_message(data):
    with app.app_context():
        if not current_user.is_authenticated or current_user.role not in ["admin", "ayudante"]:
            return

        report_id = data.get("report_id")
        message_content = data.get("message")

        if not report_id or not message_content:
            return

        try:
            report = db.session.get(Report, report_id)
            if not report:
                return

            room_name = f"report_{report_id}"
            utc_now = datetime.now(pytz.utc)
            mexico_tz = pytz.timezone("America/Mexico_City")
            mexico_time = utc_now.astimezone(mexico_tz)
            timestamp_str = mexico_time.strftime("%d/%m/%Y %I:%M %p")

            emit(
                "new_chat_message",
                {
                    "report_id": report_id,
                    "sender": current_user.username,
                    "message": message_content,
                    "timestamp": timestamp_str,
                    "is_admin": True,
                    "is_self_response": True,
                },
                room=room_name,
                namespace="/",
            )

            socketio.emit(
                "student_notification",
                {
                    "title": "💬 Nueva Respuesta de Admin",
                    "message": f'Respondieron tu reporte #{report.id}: "{message_content[:30]}..."',
                    "type": "success",
                    "link": url_for("student_reports"),
                },
                room=str(report.user_id),
                namespace="/",
            )

            new_entry = f"\n\n--- Respuesta de {current_user.username} ({timestamp_str}) ---\n{message_content}"
            if report.admin_response:
                report.admin_response += new_entry
            else:
                report.admin_response = new_entry

            if report.status == "Abierto":
                report.status = "En Proceso"

            db.session.commit()

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error chat admin: {e}")

@socketio.on("send_student_report_message")
def handle_student_report_message(data):
    with app.app_context():
        if not current_user.is_authenticated or current_user.role != "student":
            return

        report_id = data.get("report_id")
        message_content = data.get("message")

        if not report_id or not message_content:
            return

        try:
            report = db.session.get(Report, report_id)
            if not report or report.user_id != current_user.id:
                return

            room_name = f"report_{report_id}"
            utc_now = datetime.now(pytz.utc)
            mexico_tz = pytz.timezone("America/Mexico_City")
            mexico_time = utc_now.astimezone(mexico_tz)
            timestamp_str = mexico_time.strftime("%d/%m/%Y %I:%M %p")

            emit(
                "new_chat_message",
                {
                    "report_id": report_id,
                    "sender": current_user.username,
                    "message": message_content,
                    "timestamp": timestamp_str,
                    "is_admin": False,
                    "is_self_response": True,
                },
                room=room_name,
                namespace="/",
            )

            new_entry = f"\n\n--- Respuesta de {current_user.username} (Alumno) ({timestamp_str}) ---\n{message_content}"
            if report.admin_response:
                report.admin_response += new_entry
            else:
                report.admin_response = new_entry

            if report.status == "Abierto":
                report.status = "En Proceso"

            db.session.commit()

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error chat alumno: {e}")

@socketio.on("admin_join_pulse")
def on_admin_join_pulse():
    if current_user.is_authenticated and current_user.role in ["admin", "ayudante"]:
        join_room("admin_pulse_room")
        app.logger.info(f"Admin {current_user.username} forzó la unión a admin_pulse_room.")

@socketio.on('admin_broadcast_message')
def handle_broadcast(data):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return
    
    mensaje = data.get('message', '')
    if not mensaje:
        return

    print(f"📢 BROADCAST ENVIADO: {mensaje}")
    emit('student_notification', {
        'title': '📢 MENSAJE DEL PROFE',
        'message': mensaje,
        'type': 'urgent',
        'link': '#'
    }, broadcast=True)

@socketio.on("request_system_probe")
@login_required
def handle_probe_request(data):
    if current_user.role != "admin":
        return
    socketio.emit("execute_system_probe", {}, room=str(data.get("user_id")))

@socketio.on("send_probe_report")
def handle_probe_report(data):
    socketio.emit("display_probe_result", data, room="admin_pulse_room")

@socketio.on("trigger_remote_rescue")
@login_required
def handle_rescue(data):
    if current_user.role != "admin":
        return
    user_id = data.get("user_id")
    socketio.emit(
        "execute_rescue_protocol",
        {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "force_reconnect": True,
            "message": "ESTAMOS CORRIGIENDO CUALQUIER ERROR.",
        },
        room=str(user_id),
    )

@socketio.on("toggle_console_spy")
@login_required
def handle_console_spy(data):
    if current_user.role != "admin":
        return
    action = data.get("action")
    user_id = data.get("user_id")
    socketio.emit("set_console_interceptor", {"active": (action == "on")}, room=str(user_id))

@socketio.on("stream_console_log")
def handle_log_stream(data):
    socketio.emit("new_console_entry", data, room="admin_pulse_room")

@socketio.on("inject_remote_code")
@login_required
def handle_code_injection(data):
    if current_user.role != "admin":
        return
    code = data.get("code")
    user_id = data.get("user_id")
    if code and user_id:
        socketio.emit("execute_injected_code", {"script": code}, room=str(user_id))

@socketio.on("student_requests_chat")
def handle_student_help_request():
    if not current_user.is_authenticated or current_user.role != "student":
        return
    socketio.emit(
        "admin_notification_alert",
        {
            "title": "🆘 Solicitud de Ayuda",
            "message": f"El alumno {current_user.username} quiere hablar contigo.",
            "user_id": current_user.id,
            "type": "warning",
        },
        room="admin_pulse_room",
    )
    app.logger.info(f"HELP: Student {current_user.username} requested chat support.")

@socketio.on("proctoring_update")
def handle_proctoring_update(data):
    if not current_user.is_authenticated or current_user.role != "student":
        return

    exam_id = data.get("exam_id")
    time_data = data.get("time_data", {})
    click_data = data.get("click_data", [])
    is_final = data.get("is_final", False)

    session_key = f"proctoring_data_{exam_id}"
    existing_data_json = session.get(session_key)

    try:
        if existing_data_json:
            existing_data = json.loads(existing_data_json)
        else:
            existing_data = {"time_data": {}, "click_data": []}
            
        if "time_data" not in existing_data: existing_data["time_data"] = {}
        if "click_data" not in existing_data: existing_data["click_data"] = []

        for qid, time_spent in time_data.items():
            existing_data["time_data"][qid] = (
                existing_data["time_data"].get(qid, 0) + time_spent
            )

        existing_data["click_data"].extend(click_data)
        session[session_key] = json.dumps(existing_data)
        session.modified = True

    except Exception as e:
        app.logger.error(f"[PROCTORING ERROR] {current_user.username}: {e}")

    if is_final:
        app.logger.info(f"[PROCTORING] Envío final completado para {current_user.username} (Exam {exam_id}).")
    else:
        app.logger.info(f"[PROCTORING] Data guardada para {current_user.username}.")

@socketio.on("close_student_chat_remote")
def handle_close_chat(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return
    target_room = str(data.get("target_user_id"))
    admin_username = data.get("admin_username", "Admin")
    if target_room:
        emit("close_chat_signal", {"msg": f"El soporte ha finalizado por {admin_username}."}, room=target_room, namespace="/")
        app.logger.info(f"CHAT: Admin {current_user.username} closed chat session for User ID {target_room}.")

@socketio.on("admin_repair_command")
def handle_repair_command(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return

    target_user_id = str(data.get("target_user_id"))
    command = data.get("command")
    payload = data.get("payload")

    app.logger.info(f"REPAIR: Admin {current_user.username} sent command '{command}' to User {target_user_id}")

    if command == "unlock":
        try:
            target_user_int = int(target_user_id)
            blocked_result = ExamResult.query.filter_by(user_id=target_user_int, score=-1.0).first()
            exam_id = None
            if blocked_result:
                exam_id = blocked_result.exam_id
                db.session.delete(blocked_result)

            if exam_id:
                existing_session = ActiveExamSession.query.filter_by(user_id=target_user_int, exam_id=exam_id).first()
                if not existing_session:
                    revived_session = ActiveExamSession(
                        user_id=target_user_int,
                        exam_id=exam_id,
                        start_time=datetime.utcnow(),
                        time_added_sec=0,
                    )
                    db.session.add(revived_session)

            db.session.commit()
            app.logger.info(f"REPAIR: Sesión del usuario {target_user_id} restaurada en DB.")

        except Exception as e:
            app.logger.error(f"Error al desbloquear usuario {target_user_id}: {e}")
            db.session.rollback()

    emit("execute_repair", {"command": command, "payload": payload}, room=target_user_id, namespace="/")

@socketio.on("exam_violation")
def handle_exam_violation(data):
    if not current_user.is_authenticated or current_user.role != "student":
        return

    exam_id = data.get("exam_id")
    user_id = current_user.id
    violation_type = data.get("type", "Unknown Violation")
    screenshot_data = data.get("screenshot")

    if not exam_id or not user_id:
        return

    try:
        current_time_utc = datetime.now(pytz.utc)
        mexico_tz = pytz.timezone("America/Mexico_City")
        mexico_time = current_time_utc.astimezone(mexico_tz)

        active_session = ActiveExamSession.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        if not active_session:
            return

        MAX_WARNINGS = 3
        CRITICAL_VIOLATIONS = ["WINDOW_BLUR", "TAB_CHANGE", "HERRAMIENTAS_DEV", "COPIAR_PEGAR", "INTENTO_IMPRESION", "CLIC_DERECHO"]

        if violation_type in CRITICAL_VIOLATIONS:
            active_session.violation_count += 1

        if active_session.violation_count >= MAX_WARNINGS:
            automatic_reason = "Límite de advertencias alcanzado (Cambio de pestaña/ventana)."
            details_to_save = screenshot_data if screenshot_data else f"Bloqueo automático. Motivo: {automatic_reason}"
            
            new_log = ViolationLog(
                user_id=user_id,
                exam_id=exam_id,
                violation_type="EXAM_CANCELED_AUTO_BLOCK",
                details=details_to_save,
                timestamp=current_time_utc,
            )
            db.session.add(new_log)

            existing_result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
            if existing_result:
                existing_result.score = -1.0
                existing_result.submission_type = "auto_cancel"
                existing_result.date_taken = current_time_utc
            else:
                cancelled_result = ExamResult(
                    user_id=user_id,
                    exam_id=exam_id,
                    score=-1.0,
                    date_taken=current_time_utc,
                    submission_type="auto_cancel",
                )
                db.session.add(cancelled_result)

            db.session.delete(active_session)
            db.session.commit()

            app.logger.critical(f"🚫 EXAMEN CANCELADO: User {current_user.username}")

            socketio.emit("exam_cancelled_alert", {"exam_id": exam_id, "reason": automatic_reason}, room=request.sid)
            socketio.emit(
                "admin_violation_alert",
                {
                    "user_id": user_id,
                    "username": current_user.username,
                    "exam_id": exam_id,
                    "type": "EXAM_CANCELED_AUTO_BLOCK",
                    "timestamp": mexico_time.strftime("%H:%M:%S"),
                    "warning_count": MAX_WARNINGS,
                },
                room="admin_pulse_room",
            )
            return

        details_msg = f"Tipo: {violation_type}. Advertencia #{active_session.violation_count}/{MAX_WARNINGS}"
        details_to_save = screenshot_data if screenshot_data else details_msg

        new_log = ViolationLog(
            user_id=user_id,
            exam_id=exam_id,
            violation_type=violation_type,
            details=details_to_save,
            timestamp=current_time_utc,
        )
        db.session.add(new_log)
        db.session.add(active_session) 
        db.session.commit()

        socketio.emit(
            "admin_violation_alert",
            {
                "user_id": user_id,
                "username": current_user.username,
                "exam_id": exam_id,
                "type": violation_type,
                "timestamp": mexico_time.strftime("%H:%M:%S"),
                "warning_count": active_session.violation_count,
            },
            room="admin_pulse_room",
        )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error DB violación: {e}")

# ======================================================================
# --- HOOKS DE SEGURIDAD ---
# ======================================================================

@app.after_request
def set_secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

@app.before_request
def before_request_hook():
    if current_user.is_authenticated:
        if not current_user.is_active:
            logout_user()
            flash("Tu cuenta ha sido desactivada por un administrador.", "danger")
            return redirect(url_for("login"))

        session.permanent = True
        last_activity = session.get("last_activity")
        session_lifetime = app.config["PERMANENT_SESSION_LIFETIME"]

        if last_activity:
            if isinstance(last_activity, str):
                try:
                    last_activity = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    try:
                        last_activity = datetime.strptime(last_activity.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        last_activity = datetime.utcnow() - session_lifetime * 2

            if (datetime.utcnow() - last_activity) > session_lifetime:
                logout_user()
                flash("Tu sesión ha expirado por inactividad. Vuelve a iniciar sesión.", "warning")
                return redirect(url_for("login"))

        if request.endpoint and request.endpoint not in ["logout"]:
            if session.get("session_token") != current_user.current_session_token:
                logout_user()
                flash("Se ha iniciado sesión con tu cuenta en otra ubicación.", "warning")
                return redirect(url_for("login"))

        session["last_activity"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

# --- CONFIGURACIÓN DE MANTENIMIENTO ---
MAINTENANCE_MODE = os.environ.get('MAINTENANCE_MODE', 'False') == 'True'

@app.before_request
def check_maintenance():
    # Si el mantenimiento está apagado, no hacemos nada
    if not MAINTENANCE_MODE:
        return

    # Si la petición es para archivos estáticos (CSS, JS, Imágenes), dejamos pasar
    if request.endpoint and 'static' in request.endpoint:
        return

    # Si intenta entrar al Login o cerrar sesión, dejamos pasar (para que tú puedas entrar)
    if request.endpoint in ['login', 'logout']:
        return

    # --- AQUÍ ESTÁ EL TRUCO BRO ---
    # Si el usuario es ADMIN, lo dejamos pasar a todo
    if current_user.is_authenticated and current_user.role == 'admin':
        return

    # Si es Alumno, o no está logueado, y trata de ver cualquier otra cosa -> MANTENIMIENTO
    return render_template('maintenance.html'), 503

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======================================================================
# --- RUTAS DE ACCESO ---
# ======================================================================

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión exitosamente.", "success")
    return redirect(url_for("index"))

@app.route("/admin")
@login_required
def admin_panel():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    if session.pop("just_logged_in", False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")

    exams = Exam.query.all()
    announcements_list = Announcement.query.order_by(Announcement.date_published.desc()).all()
    active_exams_summary = [] 

    return render_template(
        "admin.html",
        exams=exams,
        announcements_list=announcements_list,
        active_exams_summary=active_exams_summary,
    )

@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    total_students = User.query.filter_by(role="student").count()

    mexico_tz = pytz.timezone("America/Mexico_City")
    today_start_mexico = mexico_tz.localize(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0))
    today_end_mexico = today_start_mexico + dt.timedelta(days=1)
    today_start_utc = today_start_mexico.astimezone(pytz.utc)
    today_end_utc = today_end_mexico.astimezone(pytz.utc)

    completados_hoy = ExamResult.query.filter(
        ExamResult.date_taken >= today_start_utc,
        ExamResult.date_taken < today_end_utc,
        ExamResult.score >= 0,
    ).count()

    avg_score_query = db.session.query(func.avg(ExamResult.score)).filter(ExamResult.score >= 0).scalar()
    avg_score = round(avg_score_query, 1) if avg_score_query else 0.0

    return render_template(
        "admin_dashboard.html",
        total_students=total_students,
        completados_hoy=completados_hoy,
        avg_score=avg_score,
    )
# ==========================================
# ⏸️ PAUSA GLOBAL (TIME FREEZE)
# ==========================================
@app.route('/admin/api/toggle_pause/<int:exam_id>', methods=['POST'])
@login_required
def toggle_exam_pause(exam_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    exam = Exam.query.get_or_404(exam_id)
    
    # Cambiamos el estado (Toggle)
    exam.is_paused = not exam.is_paused
    db.session.commit()
    
    status = 'paused' if exam.is_paused else 'running'
    
    # 📢 AVISAR A TODOS LOS ALUMNOS
    socketio.emit('exam_status_change', {'status': status, 'exam_id': exam_id})
    
    return jsonify({'new_status': status})
@app.route('/api/chat/history/<int:user_id>')
@login_required
def get_chat_history(user_id):
    # Seguridad: Solo admin o el propio alumno pueden ver esto
    if current_user.role != 'admin' and current_user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Buscar mensajes donde (Sender es User Y Recipient es Admin) O (Sender es Admin Y Recipient es User)
    # Esto trae toda la conversación cruzada
    messages = ChatMessage.query.filter(
        or_(
            (ChatMessage.sender_id == user_id) & (User.role == 'admin'), # Mensajes del alumno
            (ChatMessage.recipient_id == user_id) # Mensajes PARA el alumno (del admin)
        )
    ).join(User, ChatMessage.sender_id == User.id).order_by(ChatMessage.timestamp.asc()).all()
    
    # PERO, tu lógica es más simple: Admin vs Alumno específico.
    # Usemos una lógica más directa para tu caso:
    messages = db.session.query(ChatMessage).filter(
        or_(
            (ChatMessage.sender_id == user_id),    # Lo que envió el alumno
            (ChatMessage.recipient_id == user_id)  # Lo que le enviaron al alumno
        )
    ).order_by(ChatMessage.timestamp.asc()).all()

    history = []
    utc_tz = pytz.utc
    mexico_tz = pytz.timezone("America/Mexico_City")

    for msg in messages:
        # Ajustar hora
        local_time = msg.timestamp
        if local_time.tzinfo is None:
            local_time = utc_tz.localize(local_time).astimezone(mexico_tz)
        
        history.append({
            'sender': 'Admin' if msg.sender_id == current_user.id and current_user.role == 'admin' else 'Alumno', # Ajustar lógica visual
            'sender_id': msg.sender_id,
            'message': msg.message,
            'timestamp': local_time.strftime("%H:%M"),
            'is_me': (msg.sender_id == current_user.id)
        })

    return jsonify(history)

@app.route("/admin/api/chart_data")
@login_required
def chart_data():
    if current_user.role not in ["admin", "ayudante"]:
        return jsonify({"error": "Acceso denegado"}), 403

    materias_reprobadas_query = (
        db.session.query(Question.subject, func.count(Answer.id).label("incorrect_count"))
        .join(Answer, Answer.question_id == Question.id)
        .filter(Answer.grade == 0.0, Question.subject != None)
        .group_by(Question.subject)
        .order_by(func.count(Answer.id).desc())
        .limit(5)
        .all()
    )

    chart_labels = [row.subject for row in materias_reprobadas_query]
    chart_data = [row.incorrect_count for row in materias_reprobadas_query]

    return jsonify(labels=chart_labels, data=chart_data)

# --- GENERADOR DE CREDENCIALES PDF ---
@app.route('/admin/print_credentials')
@login_required
def print_credentials():
    if current_user.role != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    
    # Buscamos solo a los alumnos activos
    students = User.query.filter_by(role='student', is_active=True).all()
    
    return render_template('credentials_print.html', students=students)

@app.route("/admin/api/exam_performance/<int:exam_id>")
@login_required
def api_exam_performance(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return jsonify({"error": "Acceso denegado"}), 403

    exam = Exam.query.get_or_404(exam_id)
    questions_data = Question.query.filter_by(exam_id=exam_id).all()

    total_analyzed = Question.query.filter_by(exam_id=exam_id).filter(Question.times_answered > 0).count()

    if total_analyzed == 0:
        difficulty_counts = (
            db.session.query(Question.manual_difficulty, func.count(Question.id))
            .filter_by(exam_id=exam_id)
            .group_by(Question.manual_difficulty)
            .all()
        )
        return jsonify({
            "exam_title": exam.title,
            "total_questions": len(questions_data),
            "total_analyzed": 0,
            "predicted_score": 0,
            "is_fallback": True,
            "difficulty_distribution": [{"subject": d[0], "count": d[1]} for d in difficulty_counts],
        })

    questions_with_data = Question.query.filter_by(exam_id=exam_id).filter(Question.times_answered > 0).all()
    total_difficulty = 0
    red_flag_questions = []

    for q in questions_with_data:
        total_difficulty += q.difficulty_score
        if q.difficulty_score < 0.3:
            red_flag_questions.append({"id": q.id, "text": q.text, "score": round(q.difficulty_score * 100, 1)})

    avg_difficulty = (total_difficulty / len(questions_with_data)) * 100
    predicted_score = round(avg_difficulty, 1)

    return jsonify({
        "exam_title": exam.title,
        "total_questions": len(questions_data),
        "total_analyzed": len(questions_with_data),
        "predicted_score": predicted_score,
        "average_difficulty_percent": predicted_score,
        "red_flag_questions": red_flag_questions,
        "difficulty_distribution": [{"id": q.id, "subject": q.subject, "difficulty": round(q.difficulty_score * 100, 1)} for q in questions_with_data],
    })

@app.route("/admin/reset_attempt/<int:exam_id>/<int:user_id>", methods=["POST"])
@login_required
def reset_attempt_by_user(exam_id, user_id):
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        exam_question_ids = db.session.query(Question.id).filter_by(exam_id=exam_id).all()
        exam_question_ids = [q[0] for q in exam_question_ids]

        if exam_question_ids:
            db.session.query(Answer).filter(Answer.user_id == user_id, Answer.question_id.in_(exam_question_ids)).delete(synchronize_session=False)

        result = ExamResult.query.filter_by(exam_id=exam_id, user_id=user_id).first()
        if result:
            db.session.delete(result)
        
        active_session = ActiveExamSession.query.filter_by(exam_id=exam_id, user_id=user_id).first()
        if active_session:
            db.session.delete(active_session)

        db.session.commit()

        socketio.emit(
            "exam_reset_notification",
            {"message": "Tu examen ha sido reiniciado por el administrador."},
            room=str(user_id),
        )

        return jsonify({"success": True, "message": "Examen reiniciado correctamente."})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error reset: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/admin/api/unlock_student', methods=['POST'])
@login_required
def unlock_student_exam():
    if current_user.role != 'admin':
        return jsonify({'error': 'No autorizado'}), 403

    try:
        data = request.json
        user_id = int(data.get('user_id'))
        exam_id = int(data.get('exam_id'))

        result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        if result:
            result.submission_type = None 
            result.score = -2.0 
            
        db.session.query(ViolationLog).filter_by(user_id=user_id, exam_id=exam_id).delete()

        active_session = ActiveExamSession.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        if active_session:
            db.session.delete(active_session)

        db.session.commit()
        socketio.emit('execute_repair', {'command': 'unlock'}, room=str(user_id))

        return jsonify({'success': True, 'msg': 'Alumno desbloqueado. Respuestas conservadas.'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al desbloquear: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/admin/exam_simulator/<int:exam_id>")
@login_required
def exam_simulator_view(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    exam = Exam.query.get_or_404(exam_id)
    return render_template("exam_simulator.html", exam=exam)

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    if session.pop("just_logged_in", False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")

    total_announcements = Announcement.query.filter_by(is_active=True).count()
    read_count = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).count()
    unread_count = max(0, total_announcements - read_count)

    last_result = ExamResult.query.filter_by(user_id=current_user.id).order_by(ExamResult.date_taken.desc()).first()
    last_exam_questions_count = 0
    if last_result:
        exam = db.session.get(Exam, last_result.exam_id)
        if exam:
            last_exam_questions_count = len(exam.questions)

    correct_count_expr = case((Answer.grade == 1, 1), else_=0)
    materias_query = (
        db.session.query(
            Question.subject,
            func.avg(Answer.grade).label("avg_score"),
            func.sum(correct_count_expr).label("correct_count"),
            func.count(Answer.id).label("total_answered"),
        )
        .join(Question, Answer.question_id == Question.id)
        .filter(Answer.user_id == current_user.id, Question.subject != None, Answer.grade != None)
        .group_by(Question.subject)
        .order_by(func.avg(Answer.grade).asc())
        .limit(3)
        .all()
    )

    weak_subjects = []
    for subject, avg_score, correct_count, total_answered in materias_query:
        if total_answered > 0:
            weak_subjects.append({
                "subject": subject,
                "avg_score": float(avg_score or 0) * 100,
                "correct_count": correct_count,
                "total_answered": total_answered,
            })

    latest_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).limit(3).all()

    return render_template(
        "dashboard.html",
        username=current_user.username,
        last_result=last_result,
        last_exam_questions_count=last_exam_questions_count,
        weak_subjects=weak_subjects,
        unread_count=unread_count,
        latest_reports=latest_reports,
        Exam=Exam,
    )

@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
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
        username = normalizar_texto(request.form.get("username"))
        password = normalizar_texto(request.form.get("password"))

        if not re.match(r"^[a-zA-Z0-9_\sáéíóúüñÁÉÍÓÚÜÑ]{3,150}$", username):
            flash("Formato de usuario inválido.", "danger")
            return redirect(url_for("login"))

        lockout_end_time = session.get("lockout_end_time", 0)
        current_time = time.time()

        if current_time < lockout_end_time:
            remaining_time = int(lockout_end_time - current_time)
            flash(f"Intenta de nuevo en {remaining_time} segundos.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            failed_attempts = session.get("failed_attempts", 0) + 1
            session["failed_attempts"] = failed_attempts
            if failed_attempts >= LOGIN_ATTEMPTS:
                session["lockout_end_time"] = current_time + LOCKOUT_TIME
                session["failed_attempts"] = 0
                flash(f"Cuenta bloqueada por {LOCKOUT_TIME} segundos.", "danger")
            else:
                flash("Usuario o contraseña incorrectos", "danger")
            return redirect(url_for("login"))

        if not user.is_active:
            flash("Tu cuenta está inactiva.", "danger")
            return redirect(url_for("login"))

        session.pop("failed_attempts", None)
        session.pop("lockout_end_time", None)

        if user.two_factor_secret:
            session["temp_user_id"] = user.id
            return redirect(url_for("verify_2fa"))

        login_user(user)
        session.permanent = True
        session["last_activity"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        session["just_logged_in"] = True
        token = str(uuid.uuid4())
        user.current_session_token = token
        db.session.commit()
        session["session_token"] = token

        socketio.emit(
            "new_activity",
            {"msg": f"El alumno 🔑 {user.username} ha iniciado sesión.", "type": "info"},
            room="admin_pulse_room",
        )

        if user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))

    return render_template("index.html")

@app.route("/verify_2fa", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def verify_2fa():
    user_id = session.get("temp_user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if not user or not user.two_factor_secret:
        session.pop("temp_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        totp_code = request.form.get("totp_code")
        secret = user.two_factor_secret
        totp = pyotp.TOTP(secret)

        if totp.verify(totp_code, valid_window=1):
            session.pop("temp_user_id", None)
            login_user(user)
            session.permanent = True
            session["last_activity"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
            session["just_logged_in"] = True
            
            token = str(uuid.uuid4())
            user.current_session_token = token
            db.session.commit()
            session["session_token"] = token

            if user.role in ["admin", "ayudante"]:
                return redirect(url_for("admin_panel"))
            else:
                return redirect(url_for("dashboard"))
        else:
            flash("Código de verificación 2FA incorrecto.", "danger")

    return render_template("verify_2fa.html")

@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    user = current_user

    if request.method == "POST":
        totp_code = request.form.get("totp_code", "").replace(" ", "")
        secret = session.get("new_2fa_secret")

        if not secret:
            flash("Error de sesión. Recarga la página.", "danger")
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(totp_code, valid_window=2):
            user.two_factor_secret = secret
            db.session.commit()
            session.pop("new_2fa_secret", None)
            flash("✅ 2FA activado correctamente.", "success")
            return redirect(url_for("admin_panel"))
        else:
            flash("Código incorrecto.", "danger")

    if user.two_factor_secret:
        flash("El 2FA ya está configurado.", "info")
        return redirect(url_for("admin_panel"))

    if "new_2fa_secret" not in session:
        session["new_2fa_secret"] = pyotp.random_base32()
    
    new_secret = session["new_2fa_secret"]
    service_name = "ECOMS_Admin"
    uri = pyotp.totp.TOTP(new_secret).provisioning_uri(name=user.username, issuer_name=service_name)

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    qr_base64 = base64.b64encode(buf.read()).decode("utf-8")

    return render_template("setup_2fa.html", qr_base64=qr_base64, secret=new_secret, uri=uri, username=user.username)

@app.route("/disable_2fa", methods=["POST"])
@login_required
def disable_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    current_user.two_factor_secret = None
    db.session.commit()
    flash("✅ 2FA desactivado.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/chat/<int:user_id>")
@login_required
def admin_chat(user_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))
    target_user = User.query.get_or_404(user_id)
    return render_template("admin_chat.html", target_user=target_user)

@app.route("/admin/exams/monitor/<int:exam_id>")
@login_required
def admin_exam_monitor_detail(exam_id):
    if current_user.role != "admin":
        return redirect(url_for("admin_panel"))

    exam = Exam.query.get_or_404(exam_id)
    all_students = User.query.filter_by(role="student", is_active=True).all()
    active_sessions_map = {
        session.user_id: session
        for session in ActiveExamSession.query.filter_by(exam_id=exam_id).all()
    }

    monitoring_data = []
    utc_tz = pytz.utc
    mexico_tz = pytz.timezone("America/Mexico_City")

    for student in all_students:
        user_id = student.id
        is_active_session = active_sessions_map.get(user_id)
        is_finished = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()

        status = "No Ha Iniciado"
        violation_count = 0

        if is_active_session:
            status = "Haciendo Examen"
            violation_count = is_active_session.violation_count
        elif is_finished:
            if is_finished.score == -1.0:
                status = "Cancelado (Bloqueado)"
            else:
                status = "Examen Terminado"

        last_violation_log = ViolationLog.query.filter_by(user_id=user_id, exam_id=exam_id).order_by(ViolationLog.timestamp.desc()).first()

        if last_violation_log and last_violation_log.timestamp:
            aware_utc_time = utc_tz.localize(last_violation_log.timestamp)
            last_violation_log.timestamp = aware_utc_time.astimezone(mexico_tz)

        monitoring_data.append({
            "user_id": user_id,
            "username": student.username,
            "status": status,
            "violation_count": violation_count,
            "is_active": is_active_session is not None,
            "last_violation": last_violation_log,
        })

    return render_template("admin_exam_monitor.html", exam=exam, monitoring_data=monitoring_data, student=current_user)

@app.route("/admin/adjust_exam_time", methods=["POST"])
@login_required
def admin_adjust_exam_time():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Acceso denegado."}), 403

    try:
        data = request.get_json()
        student_id = int(data.get("student_id"))
        time_to_adjust_sec = int(data.get("time_sec"))

        session_db = ActiveExamSession.query.filter_by(user_id=student_id).first()
        if not session_db:
            return jsonify({"success": False, "message": "Sesión no encontrada."}), 404

        session_db.time_added_sec += time_to_adjust_sec
        db.session.commit()

        socketio.emit("time_update", {"extra_time_sec": session_db.time_added_sec}, room=str(student_id))
        return jsonify({"success": True, "message": "Tiempo ajustado.", "new_total_extra_sec": session_db.time_added_sec})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/admin/cancel_exam", methods=["POST"])
@login_required
def admin_cancel_exam():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Acceso denegado."}), 403

    try:
        data = request.get_json()
        student_id = int(data.get("student_id"))
        exam_id = int(data.get("exam_id"))
        reason = data.get("reason", "Sin motivo.")

        exam = Exam.query.get_or_404(exam_id)
        student = User.query.get_or_404(student_id)

        exam.cancellation_reason = f"Cancelación para {student.username}: {reason}"

        existing_result = ExamResult.query.filter_by(user_id=student_id, exam_id=exam_id).first()
        if not existing_result:
            cancelled_result = ExamResult(user_id=student_id, exam_id=exam_id, score=-1.0, date_taken=datetime.utcnow(), submission_type="manual_cancel")
            db.session.add(cancelled_result)

        active_session = ActiveExamSession.query.filter_by(user_id=student_id, exam_id=exam_id).first()
        if active_session:
            db.session.delete(active_session)

        db.session.commit()
        socketio.emit("exam_cancelled_alert", {"exam_id": exam_id, "reason": reason}, room=str(student_id))

        return jsonify({"success": True, "message": "Examen CANCELADO."})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/admin/monitor/logs/<int:exam_id>/<int:user_id>")
@login_required
def view_violation_logs(exam_id, user_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    student = User.query.get_or_404(user_id)
    exam = Exam.query.get_or_404(exam_id)
    logs = ViolationLog.query.filter_by(user_id=user_id, exam_id=exam_id).order_by(ViolationLog.timestamp.desc()).all()

    utc_tz = pytz.utc
    mexico_tz = pytz.timezone("America/Mexico_City")
    for log in logs:
        if log.timestamp:
            aware_utc_time = utc_tz.localize(log.timestamp)
            log.timestamp = aware_utc_time.astimezone(mexico_tz)

    return render_template("admin_violation_logs.html", student=student, exam=exam, logs=logs)

@app.route("/admin/announcements/new", methods=["GET", "POST"])
@login_required
def new_announcement():
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = request.form["title"]
        unsafe_content = request.form["content"]
        content = bleach.clean(unsafe_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

        if len(title.strip()) == 0:
            flash("El título no puede estar vacío.", "danger")
            return redirect(url_for("new_announcement"))

        announcement = Announcement(
            title=title,
            content=content,
            admin_id=current_user.id,
            date_published=datetime.utcnow(),
        )
        db.session.add(announcement)
        db.session.commit()

        all_students = User.query.filter_by(role="student", is_active=True).all()
        for student in all_students:
            if student.phone_number:
                send_dummy_notification(student.phone_number, f"Nuevo Anuncio: {title}")

        socketio.emit("new_activity", {"msg": f"📢 Nuevo anuncio: {title}", "type": "info"}, room="admin_pulse_room")
        flash("Anuncio creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_announcement.html")
# ==========================================
# 📸 GALERÍA DE EVIDENCIAS (MURO DE LA VERGÜENZA)
# ==========================================
@app.route('/admin/evidence_gallery')
@login_required
def evidence_gallery():
    if current_user.role != 'admin':
        flash("Acceso restringido.", "danger")
        return redirect(url_for('dashboard'))
    
    # 1. Obtenemos las últimas 50 evidencias que tengan FOTO
    # Asumimos que tu modelo ViolationLog tiene un campo 'image_filename' o 'proof_data'
    # Ajusta 'ViolationLog.image_filename' al nombre real de tu columna de imagen
    evidence_logs = ViolationLog.query\
        .filter(ViolationLog.image_filename != None)\
        .order_by(ViolationLog.timestamp.desc())\
        .limit(60)\
        .all()
    
    return render_template('evidence_gallery.html', logs=evidence_logs)
@app.route("/admin/announcements/edit/<int:announcement_id>", methods=["GET", "POST"])
@login_required
def edit_announcement(announcement_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    announcement = Announcement.query.get_or_404(announcement_id)

    if request.method == "POST":
        title = request.form["title"]
        unsafe_content = request.form["content"]
        content = bleach.clean(unsafe_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, styles=ALLOWED_STYLES)

        if len(title.strip()) == 0:
            return redirect(url_for("edit_announcement", announcement_id=announcement_id))

        announcement.title = title
        announcement.content = content
        announcement.is_active = "is_active" in request.form
        db.session.commit()
        flash("Anuncio actualizado.", "success")
        return redirect(url_for("admin_panel"))

    return render_template("edit_announcement.html", announcement=announcement)

@app.route("/admin/announcements/delete/<int:announcement_id>", methods=["POST"])
@login_required
def delete_announcement(announcement_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    announcement_to_delete = Announcement.query.get_or_404(announcement_id)
    try:
        db.session.delete(announcement_to_delete)
        db.session.commit()
        flash("Anuncio eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar: {e}", "danger")

    return redirect(url_for("admin_panel"))

@app.route("/admin/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@login_required
def edit_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    students = User.query.filter(User.role.notin_(["admin", "ayudante"])).order_by(User.username).all()

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")

        start_dt = None
        end_dt = None
        try:
            if start_date_str: start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M")
            if end_date_str: end_dt = datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Formato de fecha inválido.", "danger")
            return redirect(url_for("edit_exam", exam_id=exam_id))

        exam.title = title
        exam.description = description
        exam.start_datetime = start_dt
        exam.end_datetime = end_dt

        selected_student_ids = request.form.getlist("assigned_students")
        if selected_student_ids:
            students_to_assign = User.query.filter(User.id.in_(selected_student_ids)).all()
            exam.assigned_students = students_to_assign
        else:
            exam.assigned_students = []

        try:
            db.session.commit()
            flash("Examen actualizado.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error al guardar.", "danger")

        return redirect(url_for("admin_panel"))

    def format_datetime_local(dt_obj):
        return dt_obj.strftime("%Y-%m-%dT%H:%M") if dt_obj else ""

    return render_template(
        "edit_exam.html",
        exam=exam,
        students=students,
        start_date_str=format_datetime_local(exam.start_datetime),
        end_date_str=format_datetime_local(exam.end_datetime),
    )
    

@app.route("/admin/exams/new", methods=["GET", "POST"])
@login_required
def new_exam():
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    students = User.query.filter(User.role.notin_(["admin", "ayudante"])).order_by(User.username).all()

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")

        start_dt = None
        end_dt = None
        try:
            if start_date_str: start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M")
            if end_date_str: end_dt = datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Fecha inválida.", "danger")
            return redirect(url_for("new_exam"))

        if not title.strip():
            flash("Título requerido.", "danger")
            return redirect(url_for("new_exam"))

        exam = Exam(title=title, description=description, start_datetime=start_dt, end_datetime=end_dt)
        selected_student_ids = request.form.getlist("assigned_students")
        if selected_student_ids:
            students_to_assign = User.query.filter(User.id.in_(selected_student_ids)).all()
            exam.assigned_students = students_to_assign
        else:
            exam.assigned_students = []

        db.session.add(exam)
        db.session.commit()
        flash("Examen creado.", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_exam.html", students=students)
@app.route("/admin/exams/duplicate/<int:exam_id>", methods=["POST"])
@login_required
def duplicate_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    original_exam = Exam.query.get_or_404(exam_id)
    
    try:
        # 1. Crear la Copia del Examen
        new_exam = Exam(
            title=f"Copia de {original_exam.title}", # Título más limpio
            description=original_exam.description,
            start_datetime=original_exam.start_datetime,
            end_datetime=original_exam.end_datetime,
            duration_minutes=original_exam.duration_minutes, # 🔥 IMPORTANTE: Copiar duración
            is_active=False, # Nace apagado para que lo edites tranquilo
            # is_cancelled=False, # (Si tu modelo lo tiene, descomenta)
            # password=original_exam.password # (Si usas contraseña, cópiala o déjala vacía)
        )
        db.session.add(new_exam)
        db.session.flush() # Generamos el ID nuevo antes de seguir

        # 2. Clonar Preguntas (Limpiando estadísticas)
        for question in original_exam.questions:
            new_question = Question(
                exam_id=new_exam.id,
                text=question.text,
                option_a=question.option_a,
                option_b=question.option_b,
                option_c=question.option_c,
                option_d=question.option_d,
                correct_option=question.correct_option,
                image_filename=question.image_filename,
                subject=question.subject,
                
                # 🔥 REINICIO DE ESTADÍSTICAS (Esto debe empezar en cero)
                times_answered=0,
                correct_answers=0,
                
                # Mantener dificultad calculada si quieres, o resetearla a 0.5
                difficulty_score=question.difficulty_score, 
                manual_difficulty=question.manual_difficulty
            )
            db.session.add(new_question)

        db.session.commit()
        flash(f"✅ Examen duplicado: '{new_exam.title}'", "success")
        
        # 3. Redirigir directo a EDITAR la copia
        return redirect(url_for("edit_exam", exam_id=new_exam.id))

    except Exception as e:
        db.session.rollback()
        flash(f"Error al duplicar: {e}", "danger")
        return redirect(url_for("admin_panel"))@app.route("/admin/exam/<int:exam_id>/questions", methods=["GET", "POST"])
@app.route("/admin/exam/<int:exam_id>/add_question", methods=["GET", "POST"])
@login_required
def add_question(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)

    if request.method == "POST":
        try:
            subject = request.form.get("subject")
            text = request.form.get("text")
            option_a = request.form.get("option_a")
            option_b = request.form.get("option_b")
            option_c = request.form.get("option_c")
            option_d = request.form.get("option_d")
            correct_option = request.form.get("correct_option")
            manual_difficulty = request.form.get("manual_difficulty", "Medium")

            main_image_filename = save_image_helper(request.files.get("image_file"), "q_main")
            img_a = save_image_helper(request.files.get("image_a"), "opt_a")
            img_b = save_image_helper(request.files.get("image_b"), "opt_b")
            img_c = save_image_helper(request.files.get("image_c"), "opt_c")
            img_d = save_image_helper(request.files.get("image_d"), "opt_d")

            new_question = Question(
                exam_id=exam.id, 
                subject=subject,
                text=text,
                option_a=option_a,
                option_b=option_b,
                option_c=option_c,
                option_d=option_d,
                image_a=img_a,
                image_b=img_b,
                image_c=img_c,
                image_d=img_d,
                correct_option=correct_option,
                image_filename=main_image_filename,
                manual_difficulty=manual_difficulty,
            )

            db.session.add(new_question)
            db.session.commit()
            flash("✅ Pregunta agregada.", "success")
            return redirect(url_for("add_question", exam_id=exam.id))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al guardar: {str(e)}", "danger")
            return redirect(url_for("add_question", exam_id=exam.id))

    questions = Question.query.filter_by(exam_id=exam_id).order_by(Question.id.asc()).all()
    return render_template("add_question.html", exam=exam, questions=questions, question=None)

@app.route("/admin/exam/<int:exam_id>/import", methods=["POST"])
@login_required
def import_csv(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    if "csv_file" not in request.files:
        return redirect(url_for("add_question", exam_id=exam_id))

    file = request.files["csv_file"]
    if file.filename == "":
        return redirect(url_for("add_question", exam_id=exam_id))

    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        try:
            next(csv_input) # Skip header
        except StopIteration:
            return redirect(url_for("add_question", exam_id=exam_id))

        count = 0
        for row in csv_input:
            if len(row) >= 7:
                new_q = Question(
                    exam_id=exam_id,
                    subject=row[0].strip(),
                    text=row[1].strip(),
                    option_a=row[2].strip(),
                    option_b=row[3].strip(),
                    option_c=row[4].strip(),
                    option_d=row[5].strip(),
                    correct_option=row[6].upper().strip(),
                    manual_difficulty="Medium",
                )
                db.session.add(new_q)
                count += 1

        db.session.commit()
        flash(f"🚀 {count} preguntas importadas.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error CSV: {str(e)}", "danger")

    return redirect(url_for("add_question", exam_id=exam_id))

@app.route("/admin/question/edit/<int:question_id>", methods=["GET", "POST"])
@login_required
def edit_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    question = Question.query.get_or_404(question_id)
    exam = Exam.query.get(question.exam_id)

    if request.method == "POST":
        try:
            question.subject = request.form.get("subject")
            question.text = request.form.get("text")
            question.option_a = request.form.get("option_a")
            question.option_b = request.form.get("option_b")
            question.option_c = request.form.get("option_c")
            question.option_d = request.form.get("option_d")
            question.correct_option = request.form.get("correct_option")
            question.manual_difficulty = request.form.get("manual_difficulty")

            file_a = request.files.get("image_a")
            if file_a and file_a.filename != '':
                new_url_a = save_image_helper(file_a, "opt_a_edit")
                if new_url_a: question.image_a = new_url_a
            
            file_b = request.files.get("image_b")
            if file_b and file_b.filename != '':
                new_url_b = save_image_helper(file_b, "opt_b_edit")
                if new_url_b: question.image_b = new_url_b
            
            file_c = request.files.get("image_c")
            if file_c and file_c.filename != '':
                new_url_c = save_image_helper(file_c, "opt_c_edit")
                if new_url_c: question.image_c = new_url_c

            file_d = request.files.get("image_d")
            if file_d and file_d.filename != '':
                new_url_d = save_image_helper(file_d, "opt_d_edit")
                if new_url_d: question.image_d = new_url_d

            file_main = request.files.get("image_file")
            if file_main and file_main.filename != '':
                new_url = save_image_helper(file_main, "q_edit")
                if new_url: question.image_filename = new_url

            db.session.commit()
            flash("✅ Pregunta actualizada.", "success")
            return redirect(url_for("add_question", exam_id=question.exam_id))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al editar: {str(e)}", "danger")

    return render_template("edit_question.html", question=question, exam=exam)

@app.route("/admin/exam/<int:exam_id>/download_failure_stats")
@login_required
def download_failure_stats(exam_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    stats = {
        'Habilidad verbal': 0, 'Habilidad matemática': 0, 'Español': 0,
        'Matemáticas': 0, 'Biología': 0, 'Física': 0, 'Química': 0,
        'Historia': 0, 'Geografía': 0, 'Formación Cívica y Ética': 0
    }

    results = ExamResult.query.filter_by(exam_id=exam_id).all()
    questions = Question.query.filter_by(exam_id=exam_id).all()
    
    qid_to_subject = {q.id: q.subject for q in questions}
    qid_to_correct = {q.id: q.correct_option for q in questions}

    for result in results:
        user_id = result.user_id
        student_answers = Answer.query.filter_by(user_id=user_id).join(Question).filter(Question.exam_id == exam_id).all()
        aciertos_alumno = {key: 0 for key in stats.keys()}

        for ans in student_answers:
            correcta = qid_to_correct.get(ans.question_id)
            if ans.response == correcta and correcta is not None:
                materia = qid_to_subject.get(ans.question_id)
                if materia in aciertos_alumno:
                    aciertos_alumno[materia] += 1

        for materia, aciertos in aciertos_alumno.items():
            es_reprobado = False
            if materia in ['Habilidad verbal', 'Habilidad matemática']:
                if aciertos <= 7: es_reprobado = True
            else:
                if aciertos <= 6: es_reprobado = True
            
            if es_reprobado:
                stats[materia] += 1

    output_stream = io.StringIO()
    cw = csv.writer(output_stream)
    cw.writerow(['Materia', 'Total Alumnos Reprobados', 'Criterio de Reprobación'])
    
    for materia, total_reprobados in stats.items():
        criterio = "7 aciertos o menos" if "Habilidad" in materia else "6 aciertos o menos"
        cw.writerow([materia, total_reprobados, criterio])

    response = make_response(output_stream.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=Reprobacion_materia_{exam_id}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/admin/questions/move/<int:question_id>/<direction>")
@login_required
def move_question(question_id, direction):
    if current_user.role not in ["admin", "ayudante"]:
        return jsonify({"success": False}), 403

    question = Question.query.get_or_404(question_id)
    current_order = question.order_index

    if direction == "up":
        swap_target = Question.query.filter(
            Question.exam_id == question.exam_id, Question.order_index < current_order
        ).order_by(Question.order_index.desc()).first()
    else:
        swap_target = Question.query.filter(
            Question.exam_id == question.exam_id, Question.order_index > current_order
        ).order_by(Question.order_index.asc()).first()

    if swap_target:
        question.order_index, swap_target.order_index = swap_target.order_index, question.order_index
        db.session.commit()

    return redirect(url_for("add_question", exam_id=question.exam_id))

@app.route("/admin/question/delete/<int:question_id>", methods=["POST"])
@login_required
def delete_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id

    db.session.delete(question)
    db.session.commit()
    flash("Pregunta eliminada.", "info")
    return redirect(url_for("add_question", exam_id=exam_id))

@app.route("/admin/exams/delete/<int:exam_id>", methods=["POST"])
@login_required
def delete_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    exam_to_delete = Exam.query.get_or_404(exam_id)

    try:
        db.session.query(ExamResult).filter_by(exam_id=exam_id).delete()
        db.session.query(ActiveExamSession).filter_by(exam_id=exam_id).delete()
        db.session.query(ViolationLog).filter_by(exam_id=exam_id).delete()
        question_ids = [q.id for q in db.session.query(Question.id).filter_by(exam_id=exam_id).all()]
        if question_ids:
            db.session.query(Answer).filter(Answer.question_id.in_(question_ids)).delete(synchronize_session=False)

        db.session.delete(exam_to_delete)
        db.session.commit()
        flash("Examen eliminado.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error crítico al eliminar: {e}", "danger")

    return redirect(url_for("admin_panel"))

@app.route("/admin/export/results")
@login_required
def export_results():
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    all_results = (
        db.session.query(User.username, Exam.title, ExamResult.score, ExamResult.date_taken)
        .join(Exam, ExamResult.exam_id == Exam.id)
        .join(User, ExamResult.user_id == User.id)
        .order_by(ExamResult.date_taken.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
    writer.writerow(['Alumno', 'Examen', 'Puntuacion Final', 'Fecha de Presentacion'])

    for username, title, score, date_taken in all_results:
        final_score = score if score is not None else 0
        date_str = date_taken.strftime("%Y-%m-%d %H:%M:%S") if date_taken else "N/A"
        writer.writerow([username, title, final_score, date_str])

    response = Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=Reporte_Calificaciones_ECOMS.csv"},
    )
    return response

@app.route("/admin/exams/<int:exam_id>/answers")
@login_required
def view_answers(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    try:
        results = (
            db.session.query(User.username, ExamResult.score, ExamResult.date_taken, User.id.label("user_id"), ExamResult.submission_type)
            .join(ExamResult, User.id == ExamResult.user_id)
            .filter(ExamResult.exam_id == exam_id)
            .order_by(ExamResult.date_taken.desc())
            .all()
        )
    except Exception as e:
        results = []

    return render_template("review_results.html", exam=exam, results=results)

@app.route("/admin/exams/<int:exam_id>/review/<int:user_id>")
@login_required
def review_student_exam(exam_id, user_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    student = User.query.get_or_404(user_id)
    result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()

    if not result:
        flash("No hay resultados para este alumno.", "warning")
        return redirect(url_for("view_answers", exam_id=exam_id))

    proctoring_viz_data = None
    if result.proctoring_data:
        try:
            proctoring_viz_data = json.loads(result.proctoring_data)
        except Exception:
            proctoring_viz_data = {"time_data": {}, "click_data": []}

    review_data_query = (
        db.session.query(Question, Answer)
        .outerjoin(Answer, (Answer.question_id == Question.id) & (Answer.user_id == user_id))
        .filter(Question.exam_id == exam_id)
        .order_by(Question.id)
        .all()
    )

    return render_template("review_detail.html", exam=exam, student=student, review_data=review_data_query, result=result, proctoring_viz_data=proctoring_viz_data)

@app.route("/admin/exams/release_answers/<int:exam_id>", methods=["POST"])
@login_required
def release_answers(exam_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    if not exam.answers_released:
        exam.answers_released = True
        db.session.commit()
        flash("Respuestas liberadas.", "success")
    else:
        flash("Las respuestas ya estaban liberadas.", "info")

    return redirect(url_for("view_answers", exam_id=exam_id))
# --- RUTA PARA IMPERSONAR (LOGIN AS) ---
@app.route('/admin/impersonate/<int:user_id>')
@login_required
def impersonate_user(user_id):
    # 1. Seguridad: Solo el admin puede hacer esto
    if current_user.role != 'admin':
        flash("🚫 Acceso denegado. No eres administrador.", "danger")
        return redirect(url_for('dashboard'))

    # 2. Buscar al usuario víctima
    user_to_impersonate = User.query.get_or_404(user_id)

    # 3. Evitar que un admin se impersone a sí mismo (sería tonto, pero pasa)
    if user_to_impersonate.id == current_user.id:
        flash("No puedes auto-impersonarte.", "warning")
        return redirect(url_for('admin_users')) # O tu panel de usuarios

    # 4. LA MAGIA: Logout Admin -> Login Alumno
    logout_user() # Cerramos tu sesión
    login_user(user_to_impersonate) # Abrimos la del alumno SIN pedir password

    # 5. Redirigir al Dashboard del alumno
    flash(f"🕵️‍♂️ Modo Espía Activado: Ahora eres '{user_to_impersonate.username}'", "info")
    return redirect(url_for('dashboard'))
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    session.pop("just_logged_in", None)
    show_inactive = request.args.get("show_inactive", "0") == "1"
    query = User.query.order_by(User.username)
    if not show_inactive:
        query = query.filter_by(is_active=True)
    users = query.all()

    if request.method == "POST":
        username = normalizar_texto(request.form.get("username"))
        password = normalizar_texto(request.form.get("password"))
        role = request.form.get("role", "student")
        phone_number = request.form.get("phone_number")

        if not username or not password:
            flash("Faltan datos.", "danger")
            return redirect(url_for("manage_users"))

        if not re.match(r"^[a-zA-Z0-9_\sáéíóúüñÁÉÍÓÚÜÑ]{3,150}$", username):
            flash("Formato de usuario inválido.", "danger")
            return redirect(url_for("manage_users"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        
        new_user = User(
            username=username,
            password=hashed_password, # Contraseña encriptada (para Login)
            role=role,
            is_active=True,
            phone_number=phone_number if phone_number else None,
            
            # 🔥 AQUÍ ESTÁ EL CAMBIO CLAVE 🔥
            visible_password=password  # Contraseña normal (para Impresión)
        )
        
        db.session.add(new_user)
        try:
            db.session.commit()
            flash(f"Usuario {username} creado.", "success")
        except IntegrityError:
            db.session.rollback()
            flash("El usuario ya existe.", "danger")
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {e}", "danger")

        return redirect(url_for("manage_users"))

    return render_template("manage_users.html", users=users, show_inactive=show_inactive)
@app.route("/admin/users/toggle_status/<int:user_id>", methods=["POST"])
@login_required
def toggle_user_status(user_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    user_to_toggle = User.query.get_or_404(user_id)
    if user_to_toggle.username == "Gus":
        flash("No puedes desactivar al admin principal.", "danger")
    else:
        new_status = not user_to_toggle.is_active
        user_to_toggle.is_active = new_status
        db.session.commit()
        flash(f"Usuario {user_to_toggle.username} {'activado' if new_status else 'desactivado'}.", "success")

    return redirect(url_for("manage_users"))

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        return redirect(url_for("admin_panel"))

    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for("manage_users"))
    if user.username == "Gus":
        flash("No se puede eliminar al admin principal.", "danger")
        return redirect(url_for("manage_users"))

    try:
        ExamResult.query.filter_by(user_id=user_id).delete()
        Answer.query.filter_by(user_id=user_id).delete()
        Report.query.filter_by(user_id=user_id).delete()
        AnnouncementReadStatus.query.filter_by(user_id=user_id).delete()
        ActiveExamSession.query.filter_by(user_id=user_id).delete()
        ViolationLog.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("Usuario eliminado permanentemente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar: {e}", "danger")

    return redirect(url_for("manage_users"))

@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))
    reports = Report.query.join(User, Report.user_id == User.id).order_by(Report.date_submitted.desc()).all()
    return render_template("admin_reports.html", reports=reports)

@app.route("/admin/reports/<int:report_id>", methods=["GET", "POST"])
@login_required
def view_report_detail(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))
    report = Report.query.get_or_404(report_id)
    return render_template("report_detail.html", report=report)

@app.route("/admin/reports/respond/<int:report_id>", methods=["POST"])
@login_required
def send_report_response(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    report = Report.query.get_or_404(report_id)
    admin_response = request.form["admin_response"]
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
    new_entry = f"\n\n--- Respuesta Admin ({timestamp}):\n{admin_response}"

    if report.admin_response:
        report.admin_response += new_entry
    else:
        report.admin_response = new_entry

    if report.status in ["En Proceso", "Cerrado"]:
        report.status = "Abierto"
    report.date_resolved = datetime.utcnow()
    db.session.commit()
    
    flash("Respuesta enviada.", "success")
    return redirect(url_for("view_report_detail", report_id=report_id))

@app.route("/admin/reports/close/<int:report_id>", methods=["POST"])
@login_required
def close_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    report = Report.query.get_or_404(report_id)
    if report.status != "Cerrado":
        report.status = "Cerrado"
        report.date_resolved = datetime.utcnow()
        db.session.commit()
        socketio.emit("report_closed", {"report_id": report_id}, room=f"report_{report_id}", namespace="/")
        flash("Reporte cerrado.", "success")

    return redirect(url_for("admin_reports"))

@app.route("/admin/reports/reopen/<int:report_id>", methods=["POST"])
@login_required
def reopen_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    report = Report.query.get_or_404(report_id)
    if report.status == "Cerrado":
        report.status = "Abierto"
        report.date_resolved = None
        db.session.commit()
        flash("Reporte reabierto.", "success")

    return redirect(url_for("view_report_detail", report_id=report_id))

@app.route("/admin/announcements/status")
@login_required
def admin_announcement_read_status():
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))

    announcements = Announcement.query.order_by(Announcement.date_published.desc()).all()
    all_students = User.query.filter_by(role="student", is_active=True).order_by(User.username).all()
    read_statuses = AnnouncementReadStatus.query.all()
    read_map = {}
    for status in read_statuses:
        if status.announcement_id not in read_map:
            read_map[status.announcement_id] = set()
        read_map[status.announcement_id].add(status.user_id)

    return render_template("admin_announcement_status.html", announcements=announcements, all_students=all_students, read_map=read_map)

@app.route("/update_phone_number", methods=["POST"])
@login_required
def update_phone_number():
    if current_user.role != "student":
        return jsonify({"success": False, "message": "Acceso denegado."}), 403

    try:
        data = request.get_json()
        phone_number = data.get("phone_number")
    except Exception:
        return jsonify({"success": False, "message": "Datos inválidos."}), 400

    if not phone_number or not re.match(r"^\+[1-9]\d{7,14}$", phone_number):
        return jsonify({"success": False, "message": "Formato inválido."}), 400

    current_user.phone_number = phone_number
    db.session.commit()
    return jsonify({"success": True, "message": "Guardado."})

@app.route("/reports/new", methods=["GET", "POST"])
@login_required
@limiter.limit("1000 per hour")
def new_report():
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        title = request.form["title"]
        content = request.form.get("description")
        image_filename = None

        if len(title.strip()) == 0:
            flash("Título inválido.", "danger")
            return redirect(url_for("new_report"))

        if "image_file" in request.files:
            file = request.files["image_file"]
            if file.filename:
                try:
                    header = file.read(2048)
                    file.stream.seek(0)
                    kind = filetype.guess(header)
                    if kind is None or kind.mime not in ALLOWED_MIMETYPES:
                        flash("Archivo no permitido.", "danger")
                        return redirect(url_for("new_report"))
                except Exception:
                    flash("Error al validar archivo.", "danger")
                    return redirect(url_for("new_report"))

                image_filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, "static", "images")
                os.makedirs(upload_folder, exist_ok=True)
                file.save(os.path.join(upload_folder, image_filename))

        report = Report(
            title=title,
            content=content,
            user_id=current_user.id,
            image_filename=image_filename,
            status="Abierto",
            date_submitted=datetime.utcnow(),
        )
        db.session.add(report)
        db.session.commit()

        socketio.emit("new_activity", {"msg": f"🚨 REPORTE NUEVO: {current_user.username} - {title}", "type": "danger"}, room="admin_pulse_room")
        flash("Reporte enviado.", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_report.html", user=current_user)

@app.route("/student/reports")
@login_required
def student_reports():
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).all()
    for report in reports:
        if report.admin_response and report.date_resolved:
            session[f'report_seen_{report.id}_{report.date_resolved.strftime("%Y%m%d%H%M")}'] = True

    return render_template("student_reports.html", reports=reports)

@app.route("/reports/reply/<int:report_id>", methods=["POST"])
@login_required
@limiter.limit("1000 per hour")
def reply_to_report(report_id):
    report = Report.query.get_or_404(report_id)
    if report.status == "Cerrado":
        flash("El reporte está cerrado.", "danger")
        return redirect(url_for("student_reports"))
    if report.user_id != current_user.id:
        flash("Acceso denegado.", "danger")
        return redirect(url_for("student_reports"))

    student_response = request.form["student_response"]
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
    new_entry = f"\n\n--- Respuesta Alumno ({timestamp}):\n{student_response}"

    if report.admin_response:
        report.admin_response += new_entry
    else:
        report.admin_response = new_entry

    if report.status in ["En Proceso", "Cerrado"]:
        report.status = "Abierto"

    db.session.commit()
    flash("Respuesta enviada.", "success")
    return redirect(url_for("student_reports"))

@app.route("/announcements")
@login_required
def view_announcements():
    session.pop("just_logged_in", None)
    all_announcements = Announcement.query.filter_by(is_active=True).join(User, Announcement.admin_id == User.id).order_by(Announcement.date_published.desc()).all()
    read_statuses = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).all()
    read_ids = {status.announcement_id for status in read_statuses}

    announcements_with_status = []
    for ann in all_announcements:
        announcements_with_status.append({"announcement": ann, "is_new": ann.id not in read_ids})

    return render_template("view_announcements.html", announcements=announcements_with_status)

@app.route("/announcements/mark_read/<int:announcement_id>")
@login_required
def mark_announcement_read(announcement_id):
    status = AnnouncementReadStatus.query.filter_by(user_id=current_user.id, announcement_id=announcement_id).first()
    if not status:
        new_status = AnnouncementReadStatus(user_id=current_user.id, announcement_id=announcement_id)
        db.session.add(new_status)
        db.session.commit()
    return "", 204

@app.route("/exams")
@login_required
def student_exams():
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    completed_exam_ids = [r.exam_id for r in ExamResult.query.filter(ExamResult.user_id == current_user.id, ExamResult.score >= 0.0).all()]
    available_exams = Exam.query.filter(Exam.assigned_students.any(id=current_user.id), ~Exam.id.in_(completed_exam_ids)).all()

    return render_template("exams.html", exams=available_exams)

@app.route("/exam/save_answer", methods=["POST"])
@login_required
@limiter.limit("100 per 10 minutes")
def save_answer():
    if current_user.role != "student":
        return jsonify({"success": False, "message": "Acceso denegado"}), 403

    data = request.get_json()
    question_id = data.get("question_id")
    response = data.get("response")

    if not question_id or response is None:
        return jsonify({"success": False}), 400

    question = Question.query.get(question_id)
    if not question: return jsonify({"success": False}), 404

    active_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=question.exam_id).first()
    if not active_session: return jsonify({"success": False, "message": "Sesión inactiva."}), 403

    answer = Answer.query.filter_by(user_id=current_user.id, question_id=question_id).first()
    if answer:
        answer.response = response
    else:
        answer = Answer(response=response, user_id=current_user.id, question_id=question_id)
        db.session.add(answer)

    db.session.commit()
    return jsonify({"success": True})

@app.route("/exam/<int:exam_id>/take", methods=["GET", "POST"])
@login_required
def take_exam(exam_id):
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    exam = Exam.query.get_or_404(exam_id)
    current_time = datetime.now()

    is_locked = False
    seconds_until_start = 0
    final_result = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    final_result = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    
    if final_result:
        # Solo bloqueamos si el score es de un examen ya enviado (>=0) o cancelado (-1)
        # Si el score es -2.0, significa que es su sesión actual, ¡déjalo pasar!
        if final_result.score >= 0.0:
            flash("Ya has realizado este examen y no puedes repetirlo.", "danger")
            return redirect(url_for('student_exams'))
        elif final_result.score == -1.0:
            flash("Este examen ha sido cancelado o bloqueado.", "danger")
            return redirect(url_for('dashboard'))
    if exam.start_datetime and exam.start_datetime > current_time:
        time_diff = exam.start_datetime - current_time
        seconds_until_start = int(time_diff.total_seconds())
        is_locked = True
        return render_template("take_exam.html", exam=exam, is_locked=True, seconds_until_start=seconds_until_start, questions=[], start_time_utc=0, saved_answers={}, time_added_sec=0, is_cancelled=False, cancellation_reason="", active_result=None)

    if exam.end_datetime and exam.end_datetime < current_time:
        flash("El tiempo ha expirado.", "danger")
        return redirect(url_for("student_exams")) # <--- ✅ CORREGIDO
    existing_result = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()

    if existing_result:
        if existing_result.score is not None and existing_result.score >= 0.0:
            flash("Examen ya completado.", "info")
            return redirect(url_for("student_exam_detail", exam_id=exam.id))
        elif existing_result.score == -1.0:
            flash("Examen cancelado/bloqueado.", "danger")
            return redirect(url_for("dashboard"))

    if request.method == "POST":
        if request.form.get("action") == "start_timer_now":
            try:
                old_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
                if old_session:
                    db.session.delete(old_session)
                    db.session.commit()
                
                new_session = ActiveExamSession(user_id=current_user.id, exam_id=exam_id, start_time=datetime.now(), time_added_sec=0)
                db.session.add(new_session)

                if not existing_result:
                    result = ExamResult(user_id=current_user.id, exam_id=exam_id, score=-2.0)
                    result.question_order = generar_orden_comipems(exam_id)
                    db.session.add(result)

                db.session.commit()
                socketio.emit("new_activity", {"msg": f"🚀 {current_user.username} empezó {exam.title}!", "type": "success"}, room="admin_pulse_room")
            except Exception as e:
                db.session.rollback()
                print(f"Error al iniciar: {e}")
            return "", 204

        submission_type = request.form.get("submission_type", "manual")
        active_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
        if not active_session:
            return redirect(url_for("student_exam_detail", exam_id=exam_id))

        recording_json = request.form.get("recording_data")
        final_proctoring_data = session.pop(f"proctoring_data_{exam_id}", None)

        total_score_sum = db.session.query(Answer).join(Question).filter(
            Answer.user_id == current_user.id,
            Question.exam_id == exam_id,
            Answer.response == Question.correct_option
        ).count()

        result_to_update = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
        if not result_to_update:
            result_to_update = ExamResult(user_id=current_user.id, exam_id=exam_id)
            db.session.add(result_to_update)

        result_to_update.score = float(total_score_sum)
        result_to_update.date_taken = datetime.now(pytz.utc)
        result_to_update.submission_type = submission_type
        result_to_update.proctoring_data = final_proctoring_data
        result_to_update.session_recording = recording_json

        db.session.delete(active_session)
        db.session.commit()
        socketio.emit("new_activity", {"msg": f"✅ {current_user.username} terminó '{exam.title}'.", "type": "success"}, room="admin_pulse_room")
        
        return redirect(url_for("student_exam_detail", exam_id=exam.id))

    active_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    start_time = 0
    time_added_sec = 0

    if active_session:
        if active_session.start_time:
            start_time = int(active_session.start_time.timestamp())
        time_added_sec = active_session.time_added_sec if active_session.time_added_sec else 0

    questions = []
    if existing_result and existing_result.question_order:
        ids_ordenados = existing_result.question_order
        todas = Question.query.filter(Question.id.in_(ids_ordenados)).all()
        q_map = {q.id: q for q in todas}
        for q_id in ids_ordenados:
            if q_id in q_map: questions.append(q_map[q_id])
        
        ids_set = set(ids_ordenados)
        nuevas = Question.query.filter_by(exam_id=exam_id).filter(~Question.id.in_(ids_set)).all()
        questions.extend(nuevas)
    else:
        questions = Question.query.filter_by(exam_id=exam_id).all()

    saved_answers = Answer.query.filter_by(user_id=current_user.id).join(Question).filter(Question.exam_id == exam_id).all()
    saved_answers_dict = {a.question_id: a.response for a in saved_answers}

    is_user_cancelled = False
    user_cancellation_reason = ""
    if existing_result and existing_result.score == -1.0:
        is_user_cancelled = True
        user_cancellation_reason = exam.cancellation_reason

    return render_template(
        "take_exam.html",
        exam=exam,
        is_locked=is_locked,
        seconds_until_start=seconds_until_start,
        questions=questions,
        start_time_utc=start_time,
        saved_answers=saved_answers_dict,
        time_added_sec=time_added_sec,
        is_cancelled=is_user_cancelled,
        cancellation_reason=user_cancellation_reason,
        active_result=existing_result,
    )

@app.route("/student/exam/<int:exam_id>/detail")
@login_required
def student_exam_detail(exam_id):
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    session.pop("just_logged_in", None)
    exam = Exam.query.get_or_404(exam_id)
    result = ExamResult.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    answers = Answer.query.join(Question).filter(Answer.user_id == current_user.id, Question.exam_id == exam_id).all()
    answers_dict = {a.question_id: a for a in answers}

    if not result:
        flash("Aún no completado.", "danger")
        return redirect(url_for("student_exams"))

    return render_template("student_exam_detail.html", exam=exam, answers_dict=answers_dict, result=result)

@app.route("/admin/repair_scores/<int:exam_id>")
@login_required
def repair_scores(exam_id):
    if current_user.role != "admin":
        return "Acceso denegado", 403

    stuck_results = ExamResult.query.filter_by(exam_id=exam_id, score=-2.0).all()
    count_fixed = 0
    log_details = []

    for result in stuck_results:
        real_score = db.session.query(Answer).join(Question).filter(
            Answer.user_id == result.user_id,
            Question.exam_id == exam_id,
            Answer.response == Question.correct_option
        ).count()

        result.score = float(real_score)
        result.submission_type = "RESCATE_ADMIN"
        result.date_taken = datetime.now()
        
        log_details.append(f"Usuario {result.user_id}: De -2 a {real_score}")
        count_fixed += 1

    try:
        db.session.commit()
        return f"<h1>✅ Reparación Exitosa</h1><p>Se recalcularon {count_fixed} alumnos.</p>"
    except Exception as e:
        db.session.rollback()
        return f"❌ Error: {str(e)}"
# --- RUTA TEMPORAL PARA AGREGAR PAUSA ---
@app.route('/fix_db_pause')
def fix_db_pause():
    try:
        # Comando SQL para agregar la columna
        db.session.execute(text('ALTER TABLE exam ADD COLUMN is_paused BOOLEAN DEFAULT FALSE'))
        db.session.commit()
        return "<h1>✅ Columna 'is_paused' creada con éxito.</h1>"
    except Exception as e:
        return f"<h1>⚠️ Detalle:</h1> <p>{str(e)}</p>"
# --- RUTA DE HISTORIAL (Opcional, si quieres que el botón funcione como historial) ---
@app.route("/student/history")
@login_required
def student_exam_history():
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    # Buscar todos los resultados (incluso los completados)
    history = ExamResult.query.filter_by(user_id=current_user.id).order_by(ExamResult.date_taken.desc()).all()
    
    # Renderizamos la misma plantilla de exámenes pero pasándole los resultados
    # O podrías crear un 'history.html' específico.
    # Por ahora, redirigir a student_exams es lo más fácil.
    return redirect(url_for('student_exams'))
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
# ======================================================================
# --- RUTA API: MONITOR DE SERVIDOR REAL (Para la gráfica Matrix) ---
# ======================================================================
@app.route('/api/server-stats')
def server_stats():
    # Solo permite ver esto si es admin
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    # Leer CPU
    cpu = psutil.cpu_percent(interval=None)
    
    # Leer RAM
    ram = psutil.virtual_memory()
    ram_used_mb = ram.used // 1024 // 1024  # Convertir a MB
    
    return jsonify({
        'cpu': cpu,
        'ram_mb': ram_used_mb,
        'status': 'stable'
    })
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Puede ser el ID del admin o del alumno
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # Relaciones para facilitar acceso (opcional pero recomendado)
    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    recipient = db.relationship("User", foreign_keys=[recipient_id], backref="received_messages")
# ======================================================================
# --- INICIO DEL SERVIDOR ---
# ======================================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.logger.info("Verificación de tablas completada.")

        if User.query.filter_by(username="gus").first() is None:
            try:
                pass_limpia = normalizar_texto("241224") 
            except NameError:
                pass_limpia = "241224" 
            
            hashed_password = generate_password_hash(pass_limpia, method="pbkdf2:sha256")
            admin_user = User(username="gus", password=hashed_password, role="admin", is_active=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Usuario Admin 'gus' creado exitosamente.")
        else:
            print("El usuario Admin 'gus' ya existe.")

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Iniciando servidor SocketIO en http://0.0.0.0:{port}")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)