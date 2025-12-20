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

# --- CONFIGURACIÓN DE BASE DE DATOS ROBUSTA ---
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ueeq6njlb46im8:p19c3a3e50ba55d594a397225ff9dd56288ae26a932335a0a5d18645f3fb27b80@c85cgnr0vdhse3.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com:5432/dablvf5cje245k'
app.config['SECRET_KEY'] = 'clave_secreta_emergencia_2025'
# Aumentamos el límite a 500 MB para soportar la grabación de video/sesión
# Límite de 100 MB (100 * 1024 * 1024)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- CONFIGURACIÓN PARA SUBIDA DE IMÁGENES DE PREGUNTAS (NUEVO) ---
UPLOAD_FOLDER = "static/uploads/questions"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Función auxiliar para validar extensiones de imagen
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ======================================================================
# --- CONFIGURACIÓN DE COOKIES (INTELIGENTE) ---
# ======================================================================

# Detectamos si estamos en producción revisando si existe la variable DATABASE_URL
# (En local usas SQLite, en producción usas PostgreSQL u otra)
is_production = "DATABASE_URL" in os.environ and "postgres" in os.environ.get(
    "DATABASE_URL", ""
)

if is_production:
    # 🔒 CONFIGURACIÓN PARA INTERNET (PRODUCCIÓN - HTTPS)
    print("🔒 MODO PRODUCCIÓN DETECTADO: Cookies Seguras ACTIVADAS")
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
else:
    # 🔓 CONFIGURACIÓN PARA TU PC (LOCALHOST - HTTP)
    print(
        "🔓 MODO LOCAL DETECTADO: Cookies Seguras DESACTIVADAS (Para evitar error CSRF)"
    )
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# --- INICIALIZACIÓN DE CSRF ---
csrf = CSRFProtect(app)

# SEGURIDAD: Configuración de Sesión y Fuerza Bruta
app.config["PERMANENT_SESSION_LIFETIME"] = dt.timedelta(minutes=30)
LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300

# ======================================================================
# --- CONFIGURACIÓN DE LOGGING AVANZADA ---
# ======================================================================
app_log_handler = RotatingFileHandler(
    "app.log", maxBytes=10000000, backupCount=5, encoding="utf-8"
)
app_log_handler.setLevel(logging.INFO)
app_log_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s - %(levelname)s: %(message)s [en %(pathname)s:%(lineno)d]"
    )
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
    # 🔥 AUMENTAR EL LÍMITE DE 50 A 500 🔥
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://",
)
# INICIALIZACIÓN DE SOCKETIO
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ======================================================================
# INTEGRACIÓN DE BABEL Y ZONA HORARIA
# ======================================================================
babel = Babel(app)


def get_locale_selector():
    if request and hasattr(request, "accept_languages"):
        return request.accept_languages.best_match(["es", "en"])
    return "es"


# En app.py:
babel = Babel(app)


def get_timezone_selector():
    return "America/Mexico_City"


app.config["BABEL_DEFAULT_LOCALE"] = "es"
app.config["BABEL_DEFAULT_TIMEZONE"] = "America/Mexico_City"
app.jinja_env.globals.update(format_datetime=format_datetime)


# ==========================================
# 🕒 FILTRO DE HORA CDMX (Pegar en app.py)
# ==========================================
@app.template_filter("cdmx_time")
def cdmx_time_filter(value, format="%d/%m/%Y %I:%M %p"):
    if value is None:
        return ""

    try:
        # Definir zonas horarias
        utc = pytz.timezone("UTC")
        cdmx = pytz.timezone("America/Mexico_City")

        # Si la fecha viene sin zona (naive), le decimos que es UTC
        if value.tzinfo is None:
            value = utc.localize(value)

        # Convertir a hora de México
        local_dt = value.astimezone(cdmx)

        # Regresar texto formateado
        return local_dt.strftime(format)
    except Exception as e:
        return str(value)  # Si falla, devuelve la fecha original


# ======================================================================
# --- LISTAS BLANCAS DE SEGURIDAD (BLEACH Y FILETYPE) ---
# ======================================================================
ALLOWED_TAGS = [
    "b",
    "strong",
    "i",
    "em",
    "u",
    "br",
    "p",
    "div",
    "span",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "a",
    "img",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "hr",
]
ALLOWED_ATTRIBUTES = {
    "*": ["style", "class"],  # Permitir estilos (colores, fuentes) en todo
    "a": ["href", "title", "target"],
    "img": ["src", "alt", "width", "height", "style"],  # Permitir imágenes
}

ALLOWED_STYLES = [
    "color",
    "background-color",
    "font-family",
    "font-weight",
    "font-size",
    "text-align",
    "text-decoration",
    "width",
    "height",
    "margin",
    "padding",
    "border",
]
ALLOWED_MIMETYPES = ["image/jpeg", "image/png", "image/gif"]
# ======================================================================
# --- 🔥 NUEVA TABLA DE ASIGNACIONES (Muchos a Muchos) 🔥 ---
exam_assignments = db.Table(
    "exam_assignments",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("exam_id", db.Integer, db.ForeignKey("exam.id"), primary_key=True),
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
    assigned_students = db.relationship(
        "User",
        secondary=exam_assignments,
        lazy="subquery",
        backref=db.backref("assigned_exams", lazy=True),
    )
    # --- 🔥 ¡NUEVA COLUMNA AÑADIDA! 🔥 ---
    # Esto controla si los alumnos pueden ver las respuestas correctas.
    answers_released = db.Column(db.Boolean, default=False, nullable=False)
    # --- 🔥 FIN DE NUEVA COLUMNA 🔥 ---

    questions = db.relationship(
        "Question", backref="exam", cascade="all, delete-orphan"
    )
    active_sessions = db.relationship(
        "ActiveExamSession", backref="exam", cascade="all, delete-orphan"
    )
    violation_logs = db.relationship(
        "ViolationLog", backref="exam", lazy=True, cascade="all, delete-orphan"
    )
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=True)
    option_b = db.Column(db.String(255), nullable=True)
    option_c = db.Column(db.String(255), nullable=True)
    option_d = db.Column(db.String(255), nullable=True)
    correct_option = db.Column(db.String(10), nullable=True)
    
    image_filename = db.Column(db.String(255), nullable=True) # Imagen Principal

    # 🔥🔥 AGREGA ESTAS 4 LÍNEAS PARA QUE FUNCIONEN LOS INCISOS 🔥🔥
    image_a = db.Column(db.String(255), nullable=True)
    image_b = db.Column(db.String(255), nullable=True)
    image_c = db.Column(db.String(255), nullable=True)
    image_d = db.Column(db.String(255), nullable=True)
    # -------------------------------------------------------------

    subject = db.Column(db.String(100), nullable=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    order_index = db.Column(db.Integer, default=0)
    
    # --- MODIFICACIÓN: SIMULADOR DE RENDIMIENTO ---
    times_answered = db.Column(db.Integer, default=0, nullable=False)
    correct_answers = db.Column(db.Integer, default=0, nullable=False)
    difficulty_score = db.Column(db.Float, default=0.5, nullable=False)
    manual_difficulty = db.Column(db.String(20), default="Medium", nullable=False)
    # <--- NUEVO CAMPO MANUAL
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
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date_taken = db.Column(db.DateTime)
    submission_type = db.Column(db.String(50), default="manual")
    question_order = db.Column(db.JSON, nullable=True)

    # --- 🔥 RASTREO DE CALOR 🔥 ---
    proctoring_data = db.Column(db.Text, nullable=True)
    session_recording = db.Column(db.Text, nullable=True)
    # --- FIN DE RASTREO ---

    # --- 🔥 AGREGA ESTO AQUÍ ABAJO 🔥 ---
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "exam_id": self.exam_id,
            "score": self.score,
            "submission_type": self.submission_type,
            # Convertimos la fecha a texto para que JSON la entienda
            "date_taken": self.date_taken.isoformat() if self.date_taken else None,
            # Si proctoring_data es JSON en texto, lo mandamos tal cual
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
    announcement_id = db.Column(
        db.Integer,
        db.ForeignKey("announcement.id", ondelete="CASCADE"),
        primary_key=True,
    )
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


# -------------------------------------------------------------------

# ======================================================================
# --- FUNCIÓN DE UTILIDAD: ENVÍO DE NOTIFICACIONES ---
# ======================================================================


def send_dummy_notification(to_number, body_message):
    app.logger.warning(
        f"DUMMY NOTIFICATION: Mensaje a {to_number} (Cuerpo: {body_message[:50]}...) NO ENVIADO. Twilio deshabilitado."
    )
    return False


# ======================================================================
# --- MANEJADORES DE SOCKETIO (CHAT EN VIVO Y SEGURIDAD) ---
# ======================================================================


@socketio.on("connect")
def handle_connect():
    app.logger.info("Socket CONNECTED. Attempting to get user context.")
    if current_user.is_authenticated:
        join_room(str(current_user.id))

        # 🔥 NUEVO: Unir admins a la sala de pulso
        if current_user.role in ["admin", "ayudante"]:
            join_room("admin_pulse_room")
            app.logger.info(
                f"Admin/Ayudante {current_user.username} unido a admin_pulse_room."
            )

        app.logger.info(
            f"Socket conectado y unido al room de usuario: User {current_user.username} (ID: {current_user.id})"
        )
        # --- ENVIAR ALERTA INDIVIDUAL (PING) ---
# --- 🔥 AGREGAR ESTO PARA QUE EL ADMIN LEA AL ALUMNO 🔥 ---
# --- 🔥 ESTA ES LA FUNCIÓN QUE DEBES MODIFICAR 🔥 ---
@socketio.on("send_message_from_student")
def handle_student_message(data):
    # 1. Seguridad: Solo alumnos autenticados
    if not current_user.is_authenticated:
        return

    message_content = data.get("message")

    if message_content:
        # Preparamos el paquete de datos
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Diccionario con la info del mensaje
        message_data = {
            "sender": current_user.username,
            "message": message_content,
            "timestamp": timestamp,
            "is_student": True, 
            "user_id": current_user.id
        }

        # 1. Envía a la sala privada del alumno (para que él lo vea en su pantalla)
        emit(
            "chat_notification",
            message_data,
            room=str(current_user.id),
            namespace="/"
        )
        
        # 2. 🔥 ESTO ES LO NUEVO: Envía también al panel global del Admin 🔥
        # Esto asegura que el Admin reciba el mensaje aunque haya problemas con la sala privada
        emit(
            "chat_notification",
            message_data,
            room="admin_pulse_room",
            namespace="/"
        )
        
        # Log para que veas en la terminal si el servidor procesó el mensaje
        app.logger.info(f"CHAT LIVE: Alumno {current_user.username} envió: {message_content}")

@socketio.on("send_individual_ping")
@login_required
def handle_individual_ping(data):
    if current_user.role != "admin":
        return

    target_user_id = data.get("user_id")
    message = data.get(
        "message", "👋 El administrador te ha enviado una alerta de atención."
    )

    if target_user_id:
        # Enviamos el evento SOLO a la sala de ese alumno
        socketio.emit(
            "student_notification",
            {
                "title": "⚠️ Atención Requerida",
                "message": message,
                "link": None,  # Es solo informativo
            },
            room=str(target_user_id),
        )  # <--- IMPORTANTE: Sala personal

        # --- FOCO DE ATENCIÓN (FLASH ROJO) ---


@socketio.on("send_screen_flash")
@login_required
def handle_screen_flash(data):
    if current_user.role != "admin":
        return

    # Enviamos la orden de flash a la sala personal del usuario
    socketio.emit("trigger_flash_effect", {}, room=str(data.get("user_id")))


# --- EVENTO DE MENSAJE GLOBAL (BROADCAST) ---
@socketio.on("send_global_broadcast")
@login_required
def handle_global_broadcast(data):
    # 1. Seguridad: Solo admins pueden gritarle a todos
    if current_user.role != "admin":
        return

    mensaje = data.get("message", "")

    if mensaje:
        # 2. Reutilizamos el evento 'student_notification' que ya creamos.
        # Al no especificar 'room', se envía a TODOS los conectados.
        # Como en base.html protegimos el script con {% if student %},
        # solo los alumnos verán la notificación (el admin no se auto-notifica).
        socketio.emit(
            "student_notification",
            {
                "title": "📢 Anuncio General",
                "message": mensaje,
                "link": None,  # No lleva link, es solo informativo
            },
        )


def generar_orden_comipems(exam_id):
    # 1. Traer todas las preguntas del examen
    questions = Question.query.filter_by(exam_id=exam_id).all()

    # 2. Agrupar preguntas por Materia (Subject)
    # IMPORTANTE: Tu tabla Question debe tener una columna 'subject' o 'topic'
    # Si no la tienes, asegúrate de que tus preguntas tengan un campo para identificar la materia.
    materias_dict = {}

    for q in questions:
        # Usamos q.subject (o q.category, como lo hayas llamado en tu DB)
        # Si no tienes categorías, usa un string genérico "General"
        materia = getattr(q, "subject", "General")

        if materia not in materias_dict:
            materias_dict[materia] = []
        materias_dict[materia].append(q.id)

    # 3. Barajar el orden de las MATERIAS (Regla 1)
    nombres_materias = list(materias_dict.keys())
    random.shuffle(nombres_materias)

    orden_final_ids = []

    # 4. Recorrer materias y barajar PREGUNTAS (Regla 2)
    for nombre in nombres_materias:
        preguntas_de_esta_materia = materias_dict[nombre]

        # Mezclamos las preguntas internamente
        random.shuffle(preguntas_de_esta_materia)

        # Las agregamos a la lista final
        orden_final_ids.extend(preguntas_de_esta_materia)

    # Retorna la lista de IDs mezclados: [45, 12, 3, 99, ...]
    return orden_final_ids


@socketio.on("disconnect")
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(str(current_user.id))
        app.logger.info(
            f"Socket desconectado: User {current_user.username} (ID: {current_user.id})"
        )


@socketio.on("join_room")
def on_join(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        app.logger.warning("SECURITY: Unauthorized user tried to join admin chat.")
        return

    target_user_id = str(data.get("user_id"))
    join_room(target_user_id)
    app.logger.info(
        f"ADMIN CHAT: Admin {current_user.username} joined room {target_user_id}."
    )

    emit(
        "status_update",
        {"msg": f"Conectado a la sala del alumno ID {target_user_id}."},
        room=str(current_user.id),
    )


@socketio.on("send_message_to_student")
def handle_admin_message(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        app.logger.warning(
            f"SECURITY: Non-admin user {current_user.username} attempted to send chat message."
        )
        return

    target_room = str(data.get("target_user_id"))
    message_content = data.get("message")

    if target_room and message_content:
        emit(
            "chat_notification",
            {
                "sender": "Admin",
                "message": message_content,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            },
            room=target_room,
            namespace="/",
        )
        app.logger.info(
            f"CHAT: Admin {current_user.username} sent message to User ID {target_room}: {message_content[:30]}..."
        )

        # --- EN APP.PY (Aproximadamente Línea 295 o cerca de tus otros handlers de SocketIO) ---


# ... (Después de que terminen tus modelos de SQLAlchemy) ...

# ======================================================================
# --- 💬 HANDLERS PARA EL CHAT DE REPORTES (VERSIÓN FINAL) 💬 ---
# ======================================================================


# 1. Unirse a la sala del reporte
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
        # 1. Validaciones de Seguridad
        if not current_user.is_authenticated or current_user.role not in [
            "admin",
            "ayudante",
        ]:
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

            # 2. 🔥 LÓGICA DE TIEMPO CDMX 🔥
            utc_now = datetime.now(pytz.utc)
            mexico_tz = pytz.timezone("America/Mexico_City")
            mexico_time = utc_now.astimezone(mexico_tz)

            # Formato bonito: 06/12/2025 02:30 PM
            timestamp_str = mexico_time.strftime("%d/%m/%Y %I:%M %p")

            # 3. Enviar mensaje a la sala del chat (Live)
            emit(
                "new_chat_message",
                {
                    "report_id": report_id,
                    "sender": current_user.username,
                    "message": message_content,
                    "timestamp": timestamp_str,  # <--- Hora CDMX
                    "is_admin": True,
                    "is_self_response": True,
                },
                room=room_name,
                namespace="/",
            )

            # 4. 🔥 NUEVA NOTIFICACIÓN (TOAST) AL ALUMNO 🔥
            # Esto envía una alerta a la sala personal del alumno (su ID)
            # Nota: El alumno debe haber hecho join_room(str(current_user.id)) al conectarse.
            socketio.emit(
                "student_notification",
                {
                    "title": "💬 Nueva Respuesta de Admin",
                    "message": f'Respondieron tu reporte #{report.id}: "{message_content[:30]}..."',
                    "type": "success",
                    "link": url_for(
                        "student_reports"
                    ),  # O la ruta donde el alumno ve sus reportes
                },
                room=str(report.user_id),
                namespace="/",
            )

            # 5. Guardar en Base de Datos
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


# 3. Mensaje del ALUMNO (CORREGIDO CON HORA CDMX)
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
            # Verificar propiedad
            if not report or report.user_id != current_user.id:
                return

            room_name = f"report_{report_id}"

            # 🔥 LÓGICA DE TIEMPO CDMX 🔥
            utc_now = datetime.now(pytz.utc)
            mexico_tz = pytz.timezone("America/Mexico_City")
            mexico_time = utc_now.astimezone(mexico_tz)

            # Formato bonito: 06/12/2025 02:30 PM
            timestamp_str = mexico_time.strftime("%d/%m/%Y %I:%M %p")

            # 1. Enviar mensaje a la sala (Live)
            emit(
                "new_chat_message",
                {
                    "report_id": report_id,
                    "sender": current_user.username,
                    "message": message_content,
                    "timestamp": timestamp_str,  # <--- Hora CDMX
                    "is_admin": False,
                    "is_self_response": True,
                },
                room=room_name,
                namespace="/",
            )

            # 2. Guardar en Base de Datos
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


# ... (Continúa el resto de tu app.py: hooks de seguridad, user_loader, rutas, etc.) ...
# ... (imports y config igual) ...


# --- 🔥 NUEVO EVENTO: FORZAR UNIÓN AL PULSO (Para asegurar notificaciones) 🔥 ---
@socketio.on("admin_join_pulse")
def on_admin_join_pulse():
    if current_user.is_authenticated and current_user.role in ["admin", "ayudante"]:
        join_room("admin_pulse_room")
        app.logger.info(
            f"Admin {current_user.username} forzó la unión a admin_pulse_room."
        )


# ... (handle_connect y disconnect igual) ...
# ==========================================
# 📟 SYSTEM PROBE (TELEMETRÍA REMOTA)
# ==========================================


# 1. El Admin solicita la sonda
@socketio.on("request_system_probe")
@login_required
def handle_probe_request(data):
    if current_user.role != "admin":
        return

    # Enviamos la orden al alumno específico
    socketio.emit("execute_system_probe", {}, room=str(data.get("user_id")))


# 2. El Alumno responde y le mostramos al Admin
@socketio.on("send_probe_report")
def handle_probe_report(data):
    # Reenviamos el reporte a la sala de administración
    # (Asegúrate de que tu admin esté unido a 'admin_pulse_room' o similar)
    socketio.emit("display_probe_result", data, room="admin_pulse_room")
    # ==========================================


# --- PROTOCOLO DE REANIMACIÓN (RESCUE) ---
@socketio.on("trigger_remote_rescue")
@login_required
def handle_rescue(data):
    if current_user.role != "admin":
        return

    user_id = data.get("user_id")

    # AQUÍ ES DONDE OCURRE LA MAGIA DEL TIEMPO ⏳
    # Si quieres sincronizar el reloj, deberías buscar el examen activo del usuario
    # y calcular: (Hora Fin - Hora Actual).
    # Por ahora, enviaremos un timestamp para confirmar que el servidor responde.

    socketio.emit(
        "execute_rescue_protocol",
        {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "force_reconnect": True,
            "message": "ESTAMOS CORRIGIENDO CUALQUIER ERROR.",
        },
        room=str(user_id),
    )


# 📡 CONSOLE SPY (INTERCEPTOR DE TRÁFICO)
# ==========================================


# 1. Interruptor On/Off
@socketio.on("toggle_console_spy")
@login_required
def handle_console_spy(data):
    if current_user.role != "admin":
        return

    action = data.get("action")  # 'on' o 'off'
    user_id = data.get("user_id")

    # Le decimos al alumno: "Empieza a enviar tus logs" o "Ya cállate"
    socketio.emit(
        "set_console_interceptor", {"active": (action == "on")}, room=str(user_id)
    )


# 2. Recibir log del alumno y pasarlo al admin
@socketio.on("stream_console_log")
def handle_log_stream(data):
    # data trae: { type: 'error', message: '...', timestamp: '...' }
    # Lo enviamos a la sala de monitoreo del admin
    socketio.emit("new_console_entry", data, room="admin_pulse_room")


# --- INYECTOR DE CÓDIGO (LIVE PATCHER) ---
@socketio.on("inject_remote_code")
@login_required
def handle_code_injection(data):
    # Seguridad absoluta: Solo admin
    if current_user.role != "admin":
        return

    code = data.get("code")
    user_id = data.get("user_id")

    if code and user_id:
        # Enviamos el script a la sala del usuario
        socketio.emit("execute_injected_code", {"script": code}, room=str(user_id))


@socketio.on("student_requests_chat")
def handle_student_help_request():
    if not current_user.is_authenticated or current_user.role != "student":
        return

    # Notificar a TODOS los admins conectados al 'admin_pulse_room'
    socketio.emit(
        "admin_notification_alert",
        {
            "title": "🆘 Solicitud de Ayuda",
            "message": f"El alumno {current_user.username} quiere hablar contigo.",
            "user_id": current_user.id,
            "type": "warning",  # Amarillo para llamar la atención
        },
        room="admin_pulse_room",
    )

    app.logger.info(f"HELP: Student {current_user.username} requested chat support.")


# ... (resto del archivo igual) ...


# --- 🔥🔥 INICIO DE MODIFICACIÓN: RASTREO DE CALOR (Nuevo Socket Handler) 🔥🔥 ---
@socketio.on("proctoring_update")
def handle_proctoring_update(data):
    if not current_user.is_authenticated or current_user.role != "student":
        return

    exam_id = data.get("exam_id")
    time_data = data.get("time_data", {})
    click_data = data.get("click_data", [])
    is_final = data.get("is_final", False)

    session_key = f"proctoring_data_{exam_id}"

    # 1. Recuperar datos existentes o crear estructura vacía SIEMPRE
    existing_data_json = session.get(session_key)

    try:
        if existing_data_json:
            existing_data = json.loads(existing_data_json)
        else:
            existing_data = {"time_data": {}, "click_data": []}
            
        # 🔥 VALIDACIÓN CRÍTICA: Asegurar que las llaves existan antes de usarlas
        if "time_data" not in existing_data: existing_data["time_data"] = {}
        if "click_data" not in existing_data: existing_data["click_data"] = []

        # 2. Agregar data de tiempo
        for qid, time_spent in time_data.items():
            existing_data["time_data"][qid] = (
                existing_data["time_data"].get(qid, 0) + time_spent
            )

        # 3. Agregar data de clics (Ya no dará KeyError)
        existing_data["click_data"].extend(click_data)

        # 4. Guardar
        session[session_key] = json.dumps(existing_data)
        session.modified = True

    except Exception as e:
        app.logger.error(f"[PROCTORING ERROR] {current_user.username}: {e}")

    if is_final:
        app.logger.info(
            f"[PROCTORING] Envío final completado para {current_user.username} (Exam {exam_id})."
        )
    else:
        app.logger.info(
            f"[PROCTORING] Data guardada para {current_user.username} (Exam {exam_id}). Times tracked: {len(existing_data['time_data'])}."
        )


# --- 🔥🔥 FIN DE MODIFICACIÓN: RASTREO DE CALOR (Nuevo Socket Handler) 🔥🔥 ---


@socketio.on("close_student_chat_remote")
def handle_close_chat(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return

    target_room = str(data.get("target_user_id"))
    admin_username = data.get("admin_username", "Admin")

    if target_room:
        emit(
            "close_chat_signal",
            {"msg": f"El soporte ha finalizado por {admin_username}."},
            room=target_room,
            namespace="/",
        )
        app.logger.info(
            f"CHAT: Admin {current_user.username} closed chat session for User ID {target_room}."
        )


# ... (código anterior)
# ... (otros handlers de socket) ...

# --- 🔥 NUEVO: SISTEMA DE REPARACIÓN REMOTA 🔥 ---


@socketio.on("admin_repair_command")
def handle_repair_command(data):
    if not current_user.is_authenticated or current_user.role != "admin":
        return

    target_user_id = str(data.get("target_user_id"))
    command = data.get("command")
    payload = data.get("payload")

    app.logger.info(
        f"REPAIR: Admin {current_user.username} sent command '{command}' to User {target_user_id}"
    )

    # 🔥 LÓGICA DE DESBLOQUEO EN SERVIDOR (REVIVIR SESIÓN)
    if command == "unlock":
        try:
            # 1. Buscar y borrar el resultado de "Cancelado" (-1.0)
            target_user_int = int(target_user_id)
            blocked_result = ExamResult.query.filter_by(
                user_id=target_user_int, score=-1.0
            ).first()

            exam_id = None
            if blocked_result:
                exam_id = blocked_result.exam_id
                db.session.delete(blocked_result)

            # 2. Restaurar una sesión activa (si sabemos el examen)
            # Nota: Para no complicar, creamos una sesión nueva con el tiempo actual.
            # El frontend gestionará el tiempo visual restante real. Esto es solo para que el backend acepte respuestas.
            if exam_id:
                existing_session = ActiveExamSession.query.filter_by(
                    user_id=target_user_int, exam_id=exam_id
                ).first()
                if not existing_session:
                    # Restauramos la sesión para permitir guardar respuestas
                    revived_session = ActiveExamSession(
                        user_id=target_user_int,
                        exam_id=exam_id,
                        start_time=datetime.utcnow(),  # Reiniciamos el reloj del servidor para evitar errores de "Tiempo Expirado" al enviar
                        time_added_sec=0,
                    )
                    db.session.add(revived_session)

            db.session.commit()
            app.logger.info(
                f"REPAIR: Sesión del usuario {target_user_id} restaurada en DB."
            )

        except Exception as e:
            app.logger.error(f"Error al desbloquear usuario {target_user_id}: {e}")
            db.session.rollback()

    # Reenviar el comando al navegador del alumno
    emit(
        "execute_repair",
        {"command": command, "payload": payload},
        room=target_user_id,
        namespace="/",
    )


# --------------------------------------------------


@socketio.on("exam_violation")
def handle_exam_violation(data):
    # 1. Validaciones de Seguridad
    if not current_user.is_authenticated or current_user.role != "student":
        return

    exam_id = data.get("exam_id")
    user_id = current_user.id
    violation_type = data.get("type", "Unknown Violation")
    screenshot_data = data.get("screenshot")

    if not exam_id or not user_id:
        app.logger.error(f"Error violación: Faltan datos (Exam: {exam_id}, User: {user_id})")
        return

    try:
        # 2. Configuración de Tiempos
        current_time_utc = datetime.now(pytz.utc)
        mexico_tz = pytz.timezone("America/Mexico_City")
        mexico_time = current_time_utc.astimezone(mexico_tz)

        # 3. Buscar Sesión Activa
        active_session = ActiveExamSession.query.filter_by(
            user_id=user_id, exam_id=exam_id
        ).first()

        if not active_session:
            # Si no hay sesión, no podemos penalizar (ya salió o no empezó)
            return

        # 4. Configuración de Reglas
        MAX_WARNINGS = 3
        CRITICAL_VIOLATIONS = [
            "WINDOW_BLUR", "TAB_CHANGE", "HERRAMIENTAS_DEV",
            "COPIAR_PEGAR", "INTENTO_IMPRESION", "CLIC_DERECHO"
        ]

        # Solo aumentamos contador si es una violación crítica (no de IA por ahora)
        if violation_type in CRITICAL_VIOLATIONS:
            active_session.violation_count += 1

        # ==============================================================================
        # 💀 CASO A: LÍMITE DE ADVERTENCIAS ALCANZADO -> EXPULSIÓN
        # ==============================================================================
        if active_session.violation_count >= MAX_WARNINGS:
            automatic_reason = "Límite de advertencias alcanzado (Cambio de pestaña/ventana)."
            
            # Guardar Log Final
            details_to_save = screenshot_data if screenshot_data else f"Bloqueo automático. Motivo: {automatic_reason}"
            
            new_log = ViolationLog(
                user_id=user_id,
                exam_id=exam_id,
                violation_type="EXAM_CANCELED_AUTO_BLOCK",
                details=details_to_save,
                timestamp=current_time_utc,
            )
            db.session.add(new_log)

            # 🔥 ACTUALIZAR O CREAR RESULTADO COMO CANCELADO (-1.0) 🔥
            existing_result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
            
            if existing_result:
                existing_result.score = -1.0  # -1.0 Bloquea el acceso futuro
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

            # 🔥 MATAR LA SESIÓN ACTIVA (Detiene el reloj) 🔥
            db.session.delete(active_session)
            
            # Guardar cambios en BD
            db.session.commit()

            app.logger.critical(f"🚫 EXAMEN CANCELADO: User {current_user.username}")

            # 📢 AVISAR AL ALUMNO (Para que el JS lo saque)
            socketio.emit(
                "exam_cancelled_alert",
                {"exam_id": exam_id, "reason": automatic_reason},
                room=request.sid, # Usamos request.sid para asegurar que le llegue a esa pestaña
            )

            # 📢 AVISAR AL ADMIN
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
                room="admin_pulse_room", # Asegúrate que este sea el room de admins
            )
            return # Terminamos aquí porque ya lo expulsamos

        # ==============================================================================
        # ⚠️ CASO B: ADVERTENCIA (Aún tiene vidas)
        # ==============================================================================
        
        # Preparar detalles del log
        details_msg = f"Tipo: {violation_type}. Advertencia #{active_session.violation_count}/{MAX_WARNINGS}"
        details_to_save = screenshot_data if screenshot_data else details_msg

        # Guardar Log
        new_log = ViolationLog(
            user_id=user_id,
            exam_id=exam_id,
            violation_type=violation_type,
            details=details_to_save,
            timestamp=current_time_utc,
        )
        db.session.add(new_log)
        
        # Guardar el incremento del contador de violaciones
        db.session.add(active_session) 
        db.session.commit()

        # 📢 AVISAR AL ADMIN (Solo alerta, no expulsión)
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
# --- HOOKS DE SEGURIDAD Y MANEJADORES ---
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
            app.logger.warning(
                f"SECURITY: Active user {current_user.username} was deactivated. Forcing logout."
            )
            logout_user()
            flash("Tu cuenta ha sido desactivada por un administrador.", "danger")
            return redirect(url_for("login"))

        session.permanent = True

        last_activity = session.get("last_activity")
        session_lifetime = app.config["PERMANENT_SESSION_LIFETIME"]

        if last_activity:
            if isinstance(last_activity, str):
                try:
                    last_activity = datetime.strptime(
                        last_activity, "%Y-%m-%d %H:%M:%S.%f"
                    )
                except ValueError:
                    try:
                        last_activity = datetime.strptime(
                            last_activity.split(".")[0], "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        last_activity = datetime.utcnow() - session_lifetime * 2

            if (datetime.utcnow() - last_activity) > session_lifetime:
                logout_user()
                flash(
                    "Tu sesión ha expirado por inactividad. Vuelve a iniciar sesión.",
                    "warning",
                )
                return redirect(url_for("login"))

        if request.endpoint and request.endpoint not in ["logout"]:
            if session.get("session_token") != current_user.current_session_token:

                app.logger.warning(
                    f"[USER_ID: {current_user.id} | USER: {current_user.username}] Múltiples sesiones detectadas. Cerrando esta sesión."
                )
                logout_user()
                flash(
                    "Se ha iniciado sesión con tu cuenta en otra ubicación. Esta sesión ha sido cerrada.",
                    "warning",
                )
                return redirect(url_for("login"))

        session["last_activity"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")


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

    if session.pop("just_logged_in", False):
        flash(
            f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success"
        )

    # --- Consultas de estadísticas movidas a '/admin/dashboard' ---

    exams = Exam.query.all()
    announcements_list = Announcement.query.order_by(
        Announcement.date_published.desc()
    ).all()
    active_exams_summary = (
        []
    )  # Esto se maneja en vivo, pero lo dejamos por si se usa en otro lado

    return render_template(
        "admin.html",
        exams=exams,
        announcements_list=announcements_list,
        active_exams_summary=active_exams_summary,
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
    total_students = User.query.filter_by(role="student").count()

    # 2. Exámenes Completados Hoy (en Zona Horaria de México)
    mexico_tz = pytz.timezone("America/Mexico_City")
    today_start_mexico = mexico_tz.localize(
        datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    )
    today_end_mexico = today_start_mexico + dt.timedelta(days=1)
    # Convertir a UTC para comparar con la base de datos
    today_start_utc = today_start_mexico.astimezone(pytz.utc)
    today_end_utc = today_end_mexico.astimezone(pytz.utc)

    completados_hoy = ExamResult.query.filter(
        ExamResult.date_taken >= today_start_utc,
        ExamResult.date_taken < today_end_utc,
        ExamResult.score >= 0,  # Ignorar cancelados
    ).count()

    # 3. Puntaje Promedio (Aciertos promedio, no porcentaje)
    # Usamos 'func' que es el que importamos arriba
    avg_score_query = (
        db.session.query(func.avg(ExamResult.score))
        .filter(ExamResult.score >= 0)
        .scalar()
    )
    avg_score = round(avg_score_query, 1) if avg_score_query else 0.0

    # --- FIN DE QUERIES DEL DASHBOARD ---

    return render_template(
        "admin_dashboard.html",
        total_students=total_students,
        completados_hoy=completados_hoy,
        avg_score=avg_score,
    )


# --- 🔥 FIN DE NUEVA RUTA 🔥 ---


# --- 🔥 ¡NUEVA RUTA DE API PARA LA GRÁFICA! 🔥 ---
@app.route("/admin/api/chart_data")
@login_required
def chart_data():
    if current_user.role not in ["admin", "ayudante"]:
        app.logger.warning(
            f"SECURITY: Usuario {current_user.username} intentó acceder a la API de admin sin permisos."
        )
        return jsonify({"error": "Acceso denegado"}), 403

    # Query: 5 Materias con más respuestas incorrectas
    materias_reprobadas_query = (
        db.session.query(
            Question.subject, func.count(Answer.id).label("incorrect_count")
        )
        .join(Answer, Answer.question_id == Question.id)
        .filter(Answer.grade == 0.0, Question.subject != None)
        .group_by(Question.subject)
        .order_by(func.count(Answer.id).desc())
        .limit(5)
        .all()
    )

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
    total_analyzed = (
        Question.query.filter_by(exam_id=exam_id)
        .filter(Question.times_answered > 0)
        .count()
    )

    # --- 🔥 COMPENSACIÓN POR FALTA DE DATOS HISTÓRICOS 🔥 ---
    if total_analyzed == 0:
        # Fallback: Calcular distribución basada en Tags Manuales
        difficulty_counts = (
            db.session.query(Question.manual_difficulty, func.count(Question.id))
            .filter_by(exam_id=exam_id)
            .group_by(Question.manual_difficulty)
            .all()
        )

        # El frontend usará el campo 'is_fallback' para mostrar esta data
        return jsonify(
            {
                "exam_title": exam.title,
                "total_questions": len(questions_data),
                "total_analyzed": 0,
                "predicted_score": 0,
                "is_fallback": True,
                "difficulty_distribution": [
                    {"subject": d[0], "count": d[1]} for d in difficulty_counts
                ],
            }
        )
    # --- 🔥 FIN DE COMPENSACIÓN ---

    # Si hay datos estadísticos, proceder con el cálculo normal:
    questions_with_data = (
        Question.query.filter_by(exam_id=exam_id)
        .filter(Question.times_answered > 0)
        .all()
    )

    total_difficulty = 0
    red_flag_questions = []

    # 2. Recopilar datos y calcular la dificultad promedio
    for q in questions_with_data:
        total_difficulty += q.difficulty_score

        # Banderas Rojas: dificultad < 0.3 (menos del 30% de aciertos)
        if q.difficulty_score < 0.3:
            red_flag_questions.append(
                {
                    "id": q.id,
                    "text": q.text,
                    "score": round(q.difficulty_score * 100, 1),
                }
            )

    avg_difficulty = (total_difficulty / len(questions_with_data)) * 100
    predicted_score = round(avg_difficulty, 1)

    return jsonify(
        {
            "exam_title": exam.title,
            "total_questions": len(questions_data),
            "total_analyzed": len(questions_with_data),
            "predicted_score": predicted_score,
            "average_difficulty_percent": predicted_score,
            "red_flag_questions": red_flag_questions,
            "difficulty_distribution": [
                {
                    "id": q.id,
                    "subject": q.subject,
                    "difficulty": round(
                        q.difficulty_score * 100, 1
                    ),  # Porcentaje de acierto
                }
                for q in questions_with_data
            ],
        }
    )


# --- EN app.py ---

@app.route("/admin/reset_attempt/<int:exam_id>/<int:user_id>", methods=["POST"])
@login_required
def reset_attempt_by_user(exam_id, user_id):
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "No autorizado"}), 403

    try:
        # 1. 🔥 CORRECCIÓN AQUÍ: Borrar respuestas filtrando por PREGUNTAS del examen 🔥
        # Subquery: Obtener IDs de preguntas de este examen
        exam_question_ids = db.session.query(Question.id).filter_by(exam_id=exam_id).all()
        exam_question_ids = [q[0] for q in exam_question_ids] # Convertir a lista simple [1, 2, 3...]

        if exam_question_ids:
            # Borrar respuestas que coincidan con esas preguntas y el usuario
            db.session.query(Answer).filter(
                Answer.user_id == user_id,
                Answer.question_id.in_(exam_question_ids)
            ).delete(synchronize_session=False)

        # 2. Borrar el resultado del examen (El intento general)
        result = ExamResult.query.filter_by(exam_id=exam_id, user_id=user_id).first()
        if result:
            db.session.delete(result)
        
        # 3. Borrar sesión activa si existe
        active_session = ActiveExamSession.query.filter_by(exam_id=exam_id, user_id=user_id).first()
        if active_session:
            db.session.delete(active_session)

        db.session.commit()

        # 4. Avisar al alumno
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
# --- EN app.py (Reemplaza la función unlock_student_exam completa) ---

@app.route('/admin/api/unlock_student', methods=['POST'])
@login_required
def unlock_student_exam():
    # Solo el admin puede hacer esto
    if current_user.role != 'admin':
        return jsonify({'error': 'No autorizado'}), 403

    try:
        data = request.json
        # Convertimos a enteros por seguridad
        user_id = int(data.get('user_id'))
        exam_id = int(data.get('exam_id'))

        # 1. BUSCAR EL RESULTADO (NO LO BORRAMOS, SOLO LO EDITAMOS)
        result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        
        if result:
            # 🔥 LA CLAVE: No borramos el resultado. Solo quitamos la marca de "Cancelado".
            # Al poner submission_type en None, el sistema piensa que sigue haciéndolo.
            result.submission_type = None 
            
            # Si usas el score para marcar estado, lo ponemos en -2.0 (Iniciando/En curso)
            # o en None, dependiendo de tu lógica. -2.0 suele ser seguro para "no calificado".
            # (Si tenías una nota parcial, esto no borra las respuestas, solo la nota final).
            result.score = -2.0 
            
            # Opcional: Si quieres que el cronómetro "recupere" el tiempo perdido,
            # tendrías que sumar tiempo extra manualmente. Por defecto, el reloj
            # sigue corriendo desde que inició. Esta función solo le abre la puerta.

        # 2. BORRAR ADVERTENCIAS (Logs de Violaciones)
        # Esto sí lo borramos para que quede "limpio" de pecados.
        db.session.query(ViolationLog).filter_by(user_id=user_id, exam_id=exam_id).delete()

        # 3. ¿Y LAS RESPUESTAS (Answers)? 
        # ¡NO LAS TOCAMOS! Así, cuando el alumno recargue, sus respuestas seguirán ahí.

        # 4. LIMPIAR SESIÓN ACTIVA (Opcional, pero recomendado resetearla)
        # Esto ayuda a que el sistema de monitoreo no se confunda con sockets viejos.
        active_session = ActiveExamSession.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        if active_session:
            db.session.delete(active_session)

        db.session.commit()

        # 5. AVISAR AL ALUMNO (SocketIO)
        # Le enviamos la orden de "unlock" para que su pantalla roja desaparezca
        # y recargue la página. Al recargar, Flask cargará sus respuestas guardadas.
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


# --- 🔥 FIN DE NUEVAS RUTAS 🔥 ---


@app.route("/dashboard")
@login_required
def dashboard():
    # 1. Seguridad
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    # Mensaje bienvenida
    if session.pop("just_logged_in", False):
        flash(
            f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success"
        )

    # 2. Anuncios
    total_announcements = Announcement.query.filter_by(is_active=True).count()
    # Asegúrate de que el modelo sea el correcto (AnnouncementReadStatus o AnnouncementRead)
    read_count = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).count()
    unread_count = max(0, total_announcements - read_count)

    # 3. Último Resultado
    last_result = (
        ExamResult.query.filter_by(user_id=current_user.id)
        .order_by(ExamResult.date_taken.desc())
        .first()
    )
    last_exam_questions_count = 0
    if last_result:
        exam = db.session.get(Exam, last_result.exam_id)
        if exam:
            last_exam_questions_count = len(exam.questions)

    # 4. Materias a Reforzar
    correct_count_expr = case((Answer.grade == 1, 1), else_=0)

    materias_query = (
        db.session.query(
            Question.subject,
            func.avg(Answer.grade).label("avg_score"),
            func.sum(correct_count_expr).label("correct_count"),
            func.count(Answer.id).label("total_answered"),
        )
        .join(Question, Answer.question_id == Question.id)
        .filter(
            Answer.user_id == current_user.id,
            Question.subject != None,
            Answer.grade != None,
        )
        .group_by(Question.subject)
        .order_by(func.avg(Answer.grade).asc())
        .limit(3)
        .all()
    )

    weak_subjects = []
    for subject, avg_score, correct_count, total_answered in materias_query:
        if total_answered > 0:
            weak_subjects.append(
                {
                    "subject": subject,
                    "avg_score": float(avg_score or 0) * 100,
                    "correct_count": correct_count,
                    "total_answered": total_answered,
                }
            )

    # 5. Reportes Recientes
    # 🔥 CORRECCIÓN AQUÍ: Cambiamos 'reporter_id' por 'user_id' 🔥
    latest_reports = (
        Report.query.filter_by(user_id=current_user.id)
        .order_by(Report.date_submitted.desc())
        .limit(3)
        .all()
    )

    # 6. RETURN FINAL
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
        # Usamos .strip() para limpiar espacios accidentales al inicio/final
        username = request.form["username"].strip() if request.form["username"] else ""
        password = request.form["password"]

        # Regex actualizada para permitir espacios, acentos (áéíóúüñ) y mayúsculas
        if not re.match(r"^[a-zA-Z0-9_\sáéíóúüñÁÉÍÓÚÜÑ]{3,150}$", username):
            app.logger.warning(
                f"SECURITY: Invalid username format attempted: {username}"
            )
            flash(
                "Formato de usuario inválido. Se permiten letras, números, espacios, acentos y '_'.",
                "danger",
            )
            return redirect(url_for("login"))

        lockout_end_time = session.get("lockout_end_time", 0)
        current_time = time.time()

        if current_time < lockout_end_time:
            remaining_time = int(lockout_end_time - current_time)
            app.logger.warning(
                f"SECURITY: Login attempt blocked for user {username} (Lockout active)"
            )
            flash(
                f"Demasiados intentos fallidos. Intenta de nuevo en {remaining_time} segundos.",
                "danger",
            )
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            failed_attempts = session.get("failed_attempts", 0) + 1
            session["failed_attempts"] = failed_attempts

            app.logger.warning(
                f"[IP: {get_remote_address()} | USER_ATTEMPT: {username}] Intento de inicio de sesión fallido."
            )

            if failed_attempts >= LOGIN_ATTEMPTS:
                session["lockout_end_time"] = current_time + LOCKOUT_TIME
                session["failed_attempts"] = 0
                app.logger.critical(
                    f"[IP: {get_remote_address()} | USER_ATTEMPT: {username}] CUENTA BLOQUEADA por {LOCKOUT_TIME} segundos."
                )
                flash(
                    f"Demasiados intentos. Tu cuenta ha sido bloqueada por {LOCKOUT_TIME} segundos.",
                    "danger",
                )
            else:
                flash("Usuario o contraseña incorrectos", "danger")

            return redirect(url_for("login"))

        if not user.is_active:
            app.logger.warning(
                f"SECURITY ALERT: Blocked inactive user {username} login attempt."
            )
            flash("Tu cuenta está inactiva. Contacta al administrador.", "danger")
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

        app.logger.info(f"AUDIT LOG: User {user.username} logged in successfully.")

        socketio.emit(
            "new_activity",
            {
                "msg": f"El alumno 🔑 {user.username} ha iniciado sesión.",
                "type": "info",
            },
            room="admin_pulse_room",
        )

        if user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))

    return render_template("index.html")
# --- 🔥 FIN DE MODIFICACIÓN 🔥 ---


# ======================================================================
# --- RUTAS DE SEGURIDAD (2FA) ---
# ======================================================================


@app.route("/verify_2fa", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def verify_2fa():
    user_id = session.get("temp_user_id")

    if not user_id:
        flash("Debes ingresar la contraseña primero.", "danger")
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
            session["last_activity"] = datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            session["just_logged_in"] = True
            app.logger.info(
                f"AUDIT LOG: User {user.username} verified 2FA successfully."
            )
            flash("Verificación 2FA exitosa. Bienvenido.", "success")

            token = str(uuid.uuid4())
            user.current_session_token = token
            db.session.commit()
            session["session_token"] = token

            if user.role in ["admin", "ayudante"]:
                return redirect(url_for("admin_panel"))
            else:
                return redirect(url_for("dashboard"))
        else:
            app.logger.warning(
                f"SECURITY ALERT: Failed 2FA code entered for user: {user.username}"
            )
            flash("Código de verificación 2FA incorrecto.", "danger")

    return render_template("verify_2fa.html")


# --- EN app.py (Sustituye la función setup_2fa completa) ---

@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    user = current_user

    # ---------------------------------------------------------
    # 1. SI ENVIAN EL CÓDIGO (POST) - Lógica de Verificación
    # ---------------------------------------------------------
    if request.method == "POST":
        # Limpiar espacios
        totp_code = request.form.get("totp_code", "").replace(" ", "")
        
        # Recuperar el secreto que está en memoria
        secret = session.get("new_2fa_secret")

        if not secret:
            flash("Error de sesión. Recarga la página.", "danger")
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(secret)

        # Logs para depurar en Heroku si falla
        expected = totp.now()
        app.logger.info(f"DEBUG 2FA -> Input: '{totp_code}' | Esperado: '{expected}'")

        # Verificamos con tolerancia de tiempo (valid_window=2)
        if totp.verify(totp_code, valid_window=2):
            user.two_factor_secret = secret
            db.session.commit()
            session.pop("new_2fa_secret", None) # Limpiamos la sesión
            
            app.logger.info(f"AUDIT: Admin {user.username} activó 2FA.")
            flash("✅ Autenticación de Dos Factores activada correctamente.", "success")
            return redirect(url_for("admin_panel"))
        else:
            flash(f"Código incorrecto. El servidor esperaba: {expected}", "danger")

    # ---------------------------------------------------------
    # 2. SI ENTRAN A LA PÁGINA (GET) - Lógica de Generar QR
    # ---------------------------------------------------------
    
    # Si ya lo tiene activado, lo sacamos
    if user.two_factor_secret:
        flash("El 2FA ya está configurado.", "info")
        return redirect(url_for("admin_panel"))

    # 🔥 CORRECCIÓN CRÍTICA: SOLO GENERAR SECRETO SI NO EXISTE 🔥
    # Esto evita que el código QR cambie si recargas la página (F5)
    if "new_2fa_secret" not in session:
        session["new_2fa_secret"] = pyotp.random_base32()
    
    new_secret = session["new_2fa_secret"]

    # Generar URI y QR
    service_name = "ECOMS_Admin"
    uri = pyotp.totp.TOTP(new_secret).provisioning_uri(
        name=user.username, issuer_name=service_name
    )

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    qr_base64 = base64.b64encode(buf.read()).decode("utf-8")

    return render_template(
        "setup_2fa.html",
        qr_base64=qr_base64,
        secret=new_secret,
        uri=uri,
        username=user.username,
    )

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
    return redirect(url_for("admin_panel"))


# ======================================================================
# --- RUTAS DE ADMINISTRACIÓN Y GESTIÓN ---
# ======================================================================


@app.route("/admin/chat/<int:user_id>")
@login_required
def admin_chat(user_id):
    if current_user.role != "admin":
        flash(
            "Acceso denegado. Solo los administradores principales pueden iniciar el chat de soporte.",
            "danger",
        )
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

    all_students = User.query.filter_by(role="student", is_active=True).all()

    active_sessions_map = {
        session.user_id: session
        for session in ActiveExamSession.query.filter_by(exam_id=exam_id).all()
    }

    monitoring_data = []

    # 🔥 ZONAS HORARIAS PARA LOCALIZAR EL TIMESTAMP 🔥
    utc_tz = pytz.utc
    mexico_tz = pytz.timezone("America/Mexico_City")

    for student in all_students:
        user_id = student.id

        is_active_session = active_sessions_map.get(user_id)
        is_finished = ExamResult.query.filter_by(
            user_id=user_id, exam_id=exam_id
        ).first()

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

        last_violation_log = (
            ViolationLog.query.filter_by(user_id=user_id, exam_id=exam_id)
            .order_by(ViolationLog.timestamp.desc())
            .first()
        )

        # 🔥 CORRECCIÓN: Localizar a CDMX para el Jinja
        if last_violation_log and last_violation_log.timestamp:
            aware_utc_time = utc_tz.localize(last_violation_log.timestamp)
            last_violation_log.timestamp = aware_utc_time.astimezone(mexico_tz)
        # 🔥 FIN DE CORRECCIÓN

        monitoring_data.append(
            {
                "user_id": user_id,
                "username": student.username,
                "status": status,
                "violation_count": violation_count,
                "is_active": is_active_session is not None,
                "last_violation": last_violation_log,
            }
        )

    return render_template(
        "admin_exam_monitor.html",
        exam=exam,
        monitoring_data=monitoring_data,
        student=current_user,
    )  # <--- Esto es lo importante para que no falle el HTML


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
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Sesión de examen activa no encontrada.",
                    }
                ),
                404,
            )

        session_db.time_added_sec += time_to_adjust_sec
        db.session.commit()

        action_msg = "añadieron" if time_to_adjust_sec >= 0 else "restaron"

        socketio.emit(
            "time_update",
            {"extra_time_sec": session_db.time_added_sec},
            room=str(student_id),
        )

        return jsonify(
            {
                "success": True,
                "message": f"Se {action_msg} {abs(time_to_adjust_sec)/60} minutos al alumno {student_id}.",
                "new_total_extra_sec": session_db.time_added_sec,
            }
        )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al ajustar tiempo: {e}")
        return jsonify({"success": False, "message": f"Error interno: {str(e)}"}), 500


@app.route("/admin/cancel_exam", methods=["POST"])
@login_required
def admin_cancel_exam():
    if current_user.role != "admin":
        return jsonify({"success": False, "message": "Acceso denegado."}), 403

    try:
        data = request.get_json()
        student_id = int(data.get("student_id"))
        exam_id = int(data.get("exam_id"))
        reason = data.get("reason", "Sin motivo especificado por el administrador.")

        exam = Exam.query.get_or_404(exam_id)
        student = User.query.get_or_404(student_id)

        if not exam or not student:
            return (
                jsonify(
                    {"success": False, "message": "Examen o alumno no encontrado."}
                ),
                404,
            )

        exam.cancellation_reason = f"Cancelación para {student.username}: {reason}"

        existing_result = ExamResult.query.filter_by(
            user_id=student_id, exam_id=exam_id
        ).first()
        if not existing_result:
            cancelled_result = ExamResult(
                user_id=student_id,
                exam_id=exam_id,
                score=-1.0,
                date_taken=datetime.utcnow(),
                submission_type="manual_cancel",
            )
            db.session.add(cancelled_result)

        active_session = ActiveExamSession.query.filter_by(
            user_id=student_id, exam_id=exam_id
        ).first()

        if active_session:
            db.session.delete(active_session)

        session_key = f"exam_start_time_{exam_id}"
        session.pop(session_key, None)

        app.logger.warning(
            f"[ADMIN_ACTION] Admin '{current_user.username}' canceló manualmente el examen {exam_id} para el usuario '{student.username}'. Motivo: {reason}"
        )
        db.session.commit()

        socketio.emit(
            "exam_cancelled_alert",
            {"exam_id": exam_id, "reason": reason},
            room=str(student_id),
        )

        return jsonify(
            {
                "success": True,
                "message": f"Examen {exam.title} CANCELADO para el alumno {student.username}. Notificación enviada.",
                "reason": reason,
            }
        )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al cancelar examen: {e}")
        return jsonify({"success": False, "message": f"Error interno: {str(e)}"}), 500


@app.route("/admin/monitor/logs/<int:exam_id>/<int:user_id>")
@login_required
def view_violation_logs(exam_id, user_id):
    if current_user.role != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("dashboard"))

    student = User.query.get_or_404(user_id)
    exam = Exam.query.get_or_404(exam_id)

    utc_tz = pytz.utc
    mexico_tz = pytz.timezone("America/Mexico_City")
    logs = (
        ViolationLog.query.filter_by(user_id=user_id, exam_id=exam_id)
        .order_by(ViolationLog.timestamp.desc())
        .all()
    )

    for log in logs:
        if log.timestamp:
            aware_utc_time = utc_tz.localize(log.timestamp)
            mexico_time = aware_utc_time.astimezone(mexico_tz)
            log.timestamp = mexico_time

    return render_template(
        "admin_violation_logs.html", student=student, exam=exam, logs=logs
    )


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
        # app.py, alrededor de la línea 1395
        content = bleach.clean(
            unsafe_content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True,
            # styles=ALLOWED_STYLES, <-- Ya no se necesita o acepta
        )

        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(url_for("new_announcement"))

        current_time_utc = datetime.utcnow()

        announcement = Announcement(
            title=title,
            content=content,
            admin_id=current_user.id,
            date_published=current_time_utc,
        )
        db.session.add(announcement)
        db.session.commit()

        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} created new announcement '{title}'."
        )

        all_students = User.query.filter_by(role="student", is_active=True).all()
        notification_body = f"Nuevo Anuncio Crítico: '{title}'. Revisa la plataforma para leer el mensaje completo."

        for student in all_students:
            if student.phone_number:
                send_dummy_notification(student.phone_number, notification_body)

        # 🔥 NUEVO: Emitir evento de nuevo reporte
        socketio.emit(
            "new_activity",
            {"msg": f"📢 Admin publicó nuevo anuncio: {title}", "type": "info"},
            room="admin_pulse_room",
        )

        flash("Anuncio creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_announcement.html")

# @app.route('/fix_database_images')
# def fix_db_images():
#     try:
#         with db.engine.connect() as conn:
#             conn.execute(text("ALTER TABLE question ADD COLUMN image_a VARCHAR(255)"))
#             # ... etc
#             conn.commit()
#         return "✅ Base de datos actualizada"
#     except Exception as e:
#         return f"⚠️ Error: {str(e)}"
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
        content = bleach.clean(
            unsafe_content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            styles=ALLOWED_STYLES,
        )  # <-- AGREGADO: Permite CSS en línea

        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(
                url_for("edit_announcement", announcement_id=announcement_id)
            )

        announcement.title = title
        announcement.content = content
        announcement.is_active = "is_active" in request.form

        db.session.commit()
        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} edited announcement ID {announcement_id}."
        )
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
        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} deleted announcement '{announcement_to_delete.title}' (ID: {announcement_id})."
        )
        flash(f"Anuncio '{announcement_to_delete.title}' ha sido eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar el anuncio: {e}", "danger")

    return redirect(url_for("admin_panel"))


@app.route("/admin/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@login_required
def edit_exam(exam_id):
    # 1. Verificación de permisos (Seguridad)
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    
    # Obtener lista de todos los estudiantes para los checkboxes
    students = (
        User.query.filter(User.role.notin_(["admin", "ayudante"]))
        .order_by(User.username)
        .all()
    )

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")

        # Conversión de strings a objetos datetime
        start_dt = None
        end_dt = None
        try:
            if start_date_str:
                start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M")
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Formato de fecha inválido. Intenta de nuevo.", "danger")
            return redirect(url_for("edit_exam", exam_id=exam_id))

        # Actualizar datos básicos del examen
        exam.title = title
        exam.description = description
        exam.start_datetime = start_dt
        exam.end_datetime = end_dt

        # 🔥 ACTUALIZAR LISTA DE ALUMNOS (Lógica Restrictiva) 🔥
        # Capturamos los IDs de los checkboxes marcados
        selected_student_ids = request.form.getlist("assigned_students")

        if selected_student_ids:
            # Traemos todos los alumnos seleccionados de golpe (Optimizado)
            # Esto sincroniza la relación: quita a los no marcados y añade los nuevos
            students_to_assign = User.query.filter(User.id.in_(selected_student_ids)).all()
            exam.assigned_students = students_to_assign
        else:
            # Si no hay ninguno seleccionado, el examen queda vacío (nadie lo ve)
            exam.assigned_students = []

        try:
            db.session.commit()
            app.logger.info(f"AUDIT: {current_user.username} editó el examen ID: {exam.id}")
            flash("Examen y asignaciones actualizados correctamente.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error al guardar los cambios.", "danger")
            print(f"Error en edit_exam: {e}")

        return redirect(url_for("admin_panel"))

    # Función auxiliar para formatear fechas en el input datetime-local
    def format_datetime_local(dt_obj):
        if dt_obj:
            return dt_obj.strftime("%Y-%m-%dT%H:%M")
        return ""

    # GET: Renderizar formulario con datos actuales
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
    # 1. Verificación de permisos
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop("just_logged_in", None)

    # 2. Obtener lista de estudiantes para mostrar en el formulario
    students = (
        User.query.filter(User.role.notin_(["admin", "ayudante"]))
        .order_by(User.username)
        .all()
    )

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
                start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M")
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash(
                "Formato de fecha y hora inválido. Usa el formato YYYY-MM-DD HH:MM.",
                "danger",
            )
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
            end_datetime=end_dt,
        )

        # 🔥 RECOGER ALUMNOS SELECCIONADOS 🔥
        selected_student_ids = request.form.getlist("assigned_students")

        if selected_student_ids:
            # Buscamos todos los alumnos de golpe para no hacer un query por cada uno
            students_to_assign = User.query.filter(User.id.in_(selected_student_ids)).all()
            exam.assigned_students = students_to_assign
        else:
            # Si no hay nadie seleccionado, la lista queda vacía 
            # y por lo tanto NADIE lo verá con el nuevo filtro.
            exam.assigned_students = []

        db.session.add(exam)
        db.session.commit()

        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} created new exam '{title}'."
        )

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
            cancellation_reason=None,
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
                manual_difficulty=question.manual_difficulty,
            )
            db.session.add(new_question)

        db.session.commit()

        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} duplicated exam '{original_exam.title}' to '{new_exam.title}'."
        )
        flash(
            f"Examen '{original_exam.title}' duplicado correctamente a '{new_exam.title}'.",
            "success",
        )

    except Exception as e:
        db.session.rollback()
        flash(f"Error al duplicar el examen: {e}", "danger")

    return redirect(url_for("admin_panel"))

# ==============================================================================
# 1. FUNCIÓN DE AYUDA (DEBE IR PRIMERO Y PEGADA A LA IZQUIERDA)
# ==============================================================================
def save_image_helper(file_obj, prefix="img"):
    # Validación básica: si no hay archivo, devolvemos None
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


# ==============================================================================
# 2. RUTA DE AGREGAR PREGUNTAS (VA DEBAJO DE LA FUNCIÓN DE AYUDA)
# ==============================================================================
@app.route("/admin/exam/<int:exam_id>/questions", methods=["GET", "POST"])
@login_required
def add_question(exam_id):
    # Verificar permisos de admin
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso no autorizado.", "danger")
        return redirect(url_for("dashboard"))

    # 🔥 BUSCAR EL EXAMEN (Vital para que no de error 500)
    exam = Exam.query.get_or_404(exam_id)

    # --- LÓGICA PARA GUARDAR NUEVA PREGUNTA (POST) ---
    if request.method == "POST":
        try:
            # Recopilar datos del formulario
            subject = request.form.get("subject")
            text = request.form.get("text")
            option_a = request.form.get("option_a")
            option_b = request.form.get("option_b")
            option_c = request.form.get("option_c")
            option_d = request.form.get("option_d")
            correct_option = request.form.get("correct_option")
            manual_difficulty = request.form.get("manual_difficulty", "Medium")

            # --- USO DE LA FUNCIÓN HELPER ---
            # (Como la definimos arriba, aquí ya la reconoce)
            main_image_filename = save_image_helper(request.files.get("image_file"), "q_main")
            img_a = save_image_helper(request.files.get("image_a"), "opt_a")
            img_b = save_image_helper(request.files.get("image_b"), "opt_b")
            img_c = save_image_helper(request.files.get("image_c"), "opt_c")
            img_d = save_image_helper(request.files.get("image_d"), "opt_d")

            # Crear la pregunta en la DB
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

            flash("✅ Pregunta agregada correctamente.", "success")
            return redirect(url_for("add_question", exam_id=exam.id))

        except Exception as e:
            db.session.rollback()
            # Es bueno usar app.logger si está disponible, si no print sirve para debug
            print(f"Error al guardar pregunta: {e}")
            flash(f"Error al guardar la pregunta: {str(e)}", "danger")
            return redirect(url_for("add_question", exam_id=exam.id))

    # --- LÓGICA PARA MOSTRAR LA PÁGINA (GET) ---
    questions = (
        Question.query.filter_by(exam_id=exam_id).order_by(Question.id.asc()).all()
    )

    # Retornar el HTML (Vital para que se vea la página)
    return render_template("add_question.html", exam=exam, questions=questions, question=None)


# --- 🔥 RUTA PARA IMPORTAR CSV (NUEVO) 🔥 ---
@app.route("/admin/exam/<int:exam_id>/import", methods=["POST"])
@login_required
def import_csv(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    if "csv_file" not in request.files:
        flash("No se subió ningún archivo", "danger")
        return redirect(url_for("add_question", exam_id=exam_id))

    file = request.files["csv_file"]
    if file.filename == "":
        flash("Nombre de archivo vacío", "danger")
        return redirect(url_for("add_question", exam_id=exam_id))

    try:
        # Leer archivo en memoria
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)

        # Intentar saltar cabecera si existe
        try:
            header = next(csv_input)
        except StopIteration:
            flash("Archivo CSV vacío", "danger")
            return redirect(url_for("add_question", exam_id=exam_id))

        count = 0
        for row in csv_input:
            # Asumiendo el orden: subject, text, opA, opB, opC, opD, correct
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
                    manual_difficulty="Medium",  # Valor por defecto
                )
                db.session.add(new_q)
                count += 1

        db.session.commit()
        flash(f"🚀 Se importaron {count} preguntas exitosamente.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error al procesar CSV: {str(e)}", "danger")

    return redirect(url_for("add_question", exam_id=exam_id))


# --- EN app.py (Reemplaza edit_question) ---

@app.route("/admin/question/edit/<int:question_id>", methods=["GET", "POST"])
@login_required
def edit_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("No autorizado", "danger")
        return redirect(url_for("dashboard"))

    question = Question.query.get_or_404(question_id)
    exam = Exam.query.get(question.exam_id)

    if request.method == "POST":
        try:
            # DEBUG: Ver qué archivos están llegando
            app.logger.info(f"--- EDITANDO PREGUNTA {question_id} ---")
            app.logger.info(f"Archivos recibidos: {request.files}")

            # 1. Actualizar textos
            question.subject = request.form.get("subject")
            question.text = request.form.get("text")
            question.option_a = request.form.get("option_a")
            question.option_b = request.form.get("option_b")
            question.option_c = request.form.get("option_c")
            question.option_d = request.form.get("option_d")
            question.correct_option = request.form.get("correct_option")
            question.manual_difficulty = request.form.get("manual_difficulty")

            # 2. Actualizar imágenes (Con logs de debug)
            
            # --- INCISO A ---
            file_a = request.files.get("image_a")
            if file_a and file_a.filename != '':
                app.logger.info(f"Procesando imagen A: {file_a.filename}")
                new_url_a = save_image_helper(file_a, "opt_a_edit")
                if new_url_a:
                    question.image_a = new_url_a
                    app.logger.info(f"✅ Imagen A guardada: {new_url_a}")
                else:
                    app.logger.error("❌ Error: save_image_helper devolvió None para A")
            
            # --- INCISO B ---
            file_b = request.files.get("image_b")
            if file_b and file_b.filename != '':
                app.logger.info(f"Procesando imagen B: {file_b.filename}")
                new_url_b = save_image_helper(file_b, "opt_b_edit")
                if new_url_b:
                    question.image_b = new_url_b
            
            # --- INCISO C ---
            file_c = request.files.get("image_c")
            if file_c and file_c.filename != '':
                app.logger.info(f"Procesando imagen C: {file_c.filename}")
                new_url_c = save_image_helper(file_c, "opt_c_edit")
                if new_url_c:
                    question.image_c = new_url_c

            # --- INCISO D ---
            file_d = request.files.get("image_d")
            if file_d and file_d.filename != '':
                app.logger.info(f"Procesando imagen D: {file_d.filename}")
                new_url_d = save_image_helper(file_d, "opt_d_edit")
                if new_url_d:
                    question.image_d = new_url_d

            # --- IMAGEN PRINCIPAL ---
            file_main = request.files.get("image_file")
            if file_main and file_main.filename != '':
                app.logger.info(f"Procesando imagen Principal: {file_main.filename}")
                new_url = save_image_helper(file_main, "q_edit")
                if new_url:
                    question.image_filename = new_url

            db.session.commit()
            app.logger.info("--- CAMBIOS GUARDADOS EN DB ---")
            flash("✅ Pregunta e imágenes actualizadas.", "success")
            return redirect(url_for("add_question", exam_id=question.exam_id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"FATAL ERROR EDITANDO: {e}")
            flash(f"Error al editar: {str(e)}", "danger")

    return render_template("edit_question.html", question=question, exam=exam)
# --- RUTA PARA VER LISTA DE EXÁMENES (ESTUDIANTE) ---
@app.route('/exams') 
@login_required
def student_exams(): 
    # 1. Seguridad básica: solo estudiantes
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    # 2. Obtenemos IDs de exámenes YA TERMINADOS (score >= 0)
    # (Para no mostrarlos en la lista)
    completed_exam_ids = [r.exam_id for r in ExamResult.query.filter(
        ExamResult.user_id == current_user.id,
        ExamResult.score >= 0.0
    ).all()]

    # 3. CONSULTA CORRECTA Y FILTRADA
    # - Filtramos que el estudiante esté asignado (.any)
    # - Filtramos que NO esté completado (NOT IN)
    exams = Exam.query.filter(
        Exam.assigned_students.any(id=current_user.id), 
        ~Exam.id.in_(completed_exam_ids)
    ).all()
    
    # 4. Renderizamos pasando la lista directa de objetos
    # El HTML nuevo se encarga de calcular los bloqueos de tiempo con JavaScript
    return render_template('exams.html', exams=exams)

@app.route('/admin/exam/<int:exam_id>/download_failure_stats')
@login_required
def download_failure_stats(exam_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    exam = Exam.query.get_or_404(exam_id)
    
    stats = {
        'Habilidad verbal': 0, 'Habilidad matemática': 0, 'Español': 0,
        'Matemáticas': 0, 'Biología': 0, 'Física': 0, 'Química': 0,
        'Historia': 0, 'Geografía': 0, 'Formación Cívica y Ética': 0
    }

    results = ExamResult.query.filter_by(exam_id=exam_id).all()
    questions = Question.query.filter_by(exam_id=exam_id).all()
    
    # Mapa de Pregunta -> Materia y Pregunta -> Respuesta Correcta
    qid_to_subject = {q.id: q.subject for q in questions}
    qid_to_correct = {q.id: q.correct_option for q in questions}

    for result in results:
        user_id = result.user_id
        
        # Obtenemos las respuestas directamente
        student_answers = Answer.query.filter_by(user_id=user_id).join(Question).filter(Question.exam_id == exam_id).all()

        aciertos_alumno = {key: 0 for key in stats.keys()}

        for ans in student_answers:
            # En lugar de confiar en 'grade', comparamos respuesta vs correcta
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

    # AQUÍ ESTABA EL ERROR: Usaremos io directamente o importaremos StringIO
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
    exam_id = question.exam_id
    current_order = question.order_index

    if direction == "up":
        # Buscar la pregunta que está justo antes (orden menor)
        swap_target = (
            Question.query.filter(
                Question.exam_id == exam_id, Question.order_index < current_order
            )
            .order_by(Question.order_index.desc())
            .first()
        )
    else:  # down
        # Buscar la pregunta que está justo después (orden mayor)
        swap_target = (
            Question.query.filter(
                Question.exam_id == exam_id, Question.order_index > current_order
            )
            .order_by(Question.order_index.asc())
            .first()
        )

    if swap_target:
        # Intercambiar los índices de orden
        question.order_index, swap_target.order_index = (
            swap_target.order_index,
            question.order_index,
        )
        db.session.commit()

    return redirect(url_for("add_question", exam_id=exam_id))


# --- 🔥 RUTA PARA ELIMINAR PREGUNTA (CON BORRADO DE IMAGEN) 🔥 ---
@app.route("/admin/question/delete/<int:question_id>", methods=["POST"])
@login_required
def delete_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        return redirect(url_for("dashboard"))

    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id

    # Opcional: Borrar la imagen del servidor si existe
    if question.image_filename:
        try:
            # Intentar borrar primero de la carpeta nueva
            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"], question.image_filename
            )
            if os.path.exists(file_path):
                os.remove(file_path)
            else:
                # Intentar borrar de la carpeta antigua si no está en la nueva (retrocompatibilidad)
                old_path = os.path.join(
                    app.root_path, "static", "images", question.image_filename
                )
                if os.path.exists(old_path):
                    os.remove(old_path)
        except Exception as e:
            app.logger.error(f"Error borrando imagen: {e}")

    db.session.delete(question)
    db.session.commit()

    flash("Pregunta eliminada.", "info")
    return redirect(url_for("add_question", exam_id=exam_id))


# --- EN app.py ---

@app.route("/admin/exams/delete/<int:exam_id>", methods=["POST"])
@login_required
def delete_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam_to_delete = Exam.query.get_or_404(exam_id)

    try:
        # 🔥 PASO 1: LIMPIEZA PROFUNDA (Borrar hijos antes que al padre) 🔥
        
        # A. Borrar Resultados de este examen
        db.session.query(ExamResult).filter_by(exam_id=exam_id).delete()
        
        # B. Borrar Sesiones Activas de este examen
        db.session.query(ActiveExamSession).filter_by(exam_id=exam_id).delete()

        # C. Borrar Logs de Violaciones (Trampas) de este examen
        db.session.query(ViolationLog).filter_by(exam_id=exam_id).delete()

        # D. Borrar Respuestas de los alumnos (Esto es vital, suelen bloquear el borrado de preguntas)
        # Obtenemos los IDs de las preguntas de este examen
        question_ids = db.session.query(Question.id).filter_by(exam_id=exam_id).all()
        question_ids = [q[0] for q in question_ids] # Convertir a lista simple [1, 2, 3...]

        if question_ids:
            # Borramos todas las respuestas asociadas a esas preguntas
            db.session.query(Answer).filter(Answer.question_id.in_(question_ids)).delete(synchronize_session=False)

        # 🔥 PASO 2: AHORA SÍ, BORRAR EL EXAMEN 🔥
        # Al haber borrado las respuestas, las preguntas se borran solas por el "cascade" del modelo,
        # o se borrarán sin protestar al borrar el examen.
        db.session.delete(exam_to_delete)
        
        db.session.commit()
        
        app.logger.info(
            f"AUDIT LOG: Admin {current_user.username} deleted exam '{exam_to_delete.title}' (ID: {exam_id})."
        )
        flash(
            f"Examen '{exam_to_delete.title}' y todos sus datos asociados han sido eliminados correctamente.",
            "success",
        )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al eliminar el examen: {e}")
        flash(f"Error crítico al eliminar: {e}", "danger")

    return redirect(url_for("admin_panel"))


@app.route("/admin/export/results")
@login_required
def export_results():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    all_results = (
        db.session.query(
            User.username, Exam.title, ExamResult.score, ExamResult.date_taken
        )
        .join(Exam, ExamResult.exam_id == Exam.id)
        .join(User, ExamResult.user_id == User.id)
        .order_by(ExamResult.date_taken.desc())
        .all()
    )

    # Usamos StringIO para manejar correctamente la memoria y caracteres especiales
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)

    # Cabeceras
    writer.writerow(['Alumno', 'Examen', 'Puntuacion Final', 'Fecha de Presentacion'])

    for username, title, score, date_taken in all_results:
        # Validamos el score: si es None, ponemos 0
        final_score = score if score is not None else 0
        
        # Validamos la fecha
        date_str = date_taken.strftime("%Y-%m-%d %H:%M:%S") if date_taken else "N/A"
        
        # Escribimos la fila
        writer.writerow([username, title, final_score, date_str])

    # Preparamos la respuesta con codificación utf-8 para los acentos
    response = Response(
        output.getvalue().encode('utf-8-sig'), # El sig añade el BOM para que Excel abra bien los acentos
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=Reporte_Calificaciones_ECOMS.csv",
        },
    )
    return response

@app.route("/admin/exams/<int:exam_id>/answers")
@login_required
def view_answers(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)

    # Usamos un bloque try/except general para capturar fallos de base de datos
    try:
        results = (
            db.session.query(
                User.username,
                ExamResult.score,
                ExamResult.date_taken,
                User.id.label("user_id"),
                ExamResult.submission_type,
            )
            .join(ExamResult, User.id == ExamResult.user_id)
            .filter(ExamResult.exam_id == exam_id)
            .order_by(ExamResult.date_taken.desc())
            .all()
        )
    except Exception as e:
        app.logger.error(f"Error crítico en base de datos al ver respuestas: {e}")
        flash("Hay un error con los datos de algunos alumnos. Contacta a soporte.", "danger")
        results = []

    return render_template("review_results.html", exam=exam, results=results)


@app.route("/admin/exams/<int:exam_id>/review/<int:user_id>")
@login_required
def review_student_exam(exam_id, user_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)
    student = User.query.get_or_404(user_id)
    result = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()

    # Si no hay resultado, no podemos revisar
    if not result:
        flash("No hay resultados para este alumno.", "warning")
        return redirect(url_for("view_answers", exam_id=exam_id))

    # --- CARGA SEGURA DE DATOS DE PROCTORING ---
    proctoring_viz_data = None
    if result.proctoring_data:
        try:
            proctoring_viz_data = json.loads(result.proctoring_data)
        except Exception as e:
            app.logger.error(f"Error cargando proctoring para {student.username}: {e}")
            proctoring_viz_data = {"time_data": {}, "click_data": []} # Fallback vacío

    review_data_query = (
        db.session.query(Question, Answer)
        .outerjoin(
            Answer, (Answer.question_id == Question.id) & (Answer.user_id == user_id)
        )
        .filter(Question.exam_id == exam_id)
        .order_by(Question.id)
        .all()
    )

    return render_template(
        "review_detail.html",
        exam=exam,
        student=student,
        review_data=review_data_query,
        result=result,
        proctoring_viz_data=proctoring_viz_data # Asegúrate de pasarlo
    )


# --- 🔥 ¡INICIO DE NUEVA RUTA! 🔥 ---
@app.route("/admin/exams/release_answers/<int:exam_id>", methods=["POST"])
@login_required
def release_answers(exam_id):
    """
    Permite a un admin "liberar" las respuestas de un examen,
    haciendo que las revisiones de los alumnos muestren las respuestas correctas.
    """
    if current_user.role != "admin":
        app.logger.warning(
            f"SECURITY: Usuario no admin {current_user.username} intentó liberar respuestas."
        )
        flash("Acceso denegado.", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)

    if not exam.answers_released:
        exam.answers_released = True
        db.session.commit()
        app.logger.warning(
            f"[ADMIN_ACTION] Admin '{current_user.username}' liberó las respuestas para el examen '{exam.title}' (ID: {exam_id})."
        )
        flash(
            f"¡Éxito! Las respuestas para '{exam.title}' ahora son visibles para todos los alumnos que lo presentaron.",
            "success",
        )
    else:
        flash("Las respuestas para este examen ya habían sido liberadas.", "info")

    return redirect(url_for("view_answers", exam_id=exam_id))


# --- 🔥 ¡FIN DE NUEVA RUTA! 🔥 ---


@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop("just_logged_in", None)

    show_inactive = request.args.get("show_inactive", "0") == "1"

    query = User.query.order_by(User.username)

    if not show_inactive:
        query = query.filter_by(is_active=True)

    users = query.all()

    if request.method == "POST":
        # .strip() elimina espacios accidentales al principio o final
        username = request.form.get("username").strip() if request.form.get("username") else None
        password = request.form.get("password")
        role = request.form.get("role", "student")
        phone_number = request.form.get("phone_number")

        if not username or not password:
            flash("El nombre de usuario y la contraseña son obligatorios.", "danger")
            return redirect(url_for("manage_users"))

        # Regex actualizada: 
        # a-zA-Z (letras), 0-9 (números), _ (guion bajo), \s (espacios)
        # áéíóúüñÁÉÍÓÚÜÑ (acentos y letra ñ)
        if not re.match(r"^[a-zA-Z0-9_\sáéíóúüñÁÉÍÓÚÜÑ]{3,150}$", username):
            flash(
                "El nombre debe tener entre 3 y 150 caracteres (letras, números, espacios, acentos o '_').",
                "danger",
            )
            return redirect(url_for("manage_users"))

        if phone_number and not re.match(r"^\+[1-9]\d{7,14}$", phone_number):
            flash(
                "Formato de número de teléfono inválido. Debe incluir el código de país (ej: +52XXXXXXXXXX).",
                "danger",
            )
            return redirect(url_for("manage_users"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            is_active=True,
            phone_number=phone_number if phone_number else None,
        )
        db.session.add(new_user)

        try:
            db.session.commit()
            app.logger.info(
                f"AUDIT LOG: Admin user {current_user.username} created new user '{username}' ({role})."
            )
            flash(f"Usuario {username} ({role}) creado exitosamente.", "success")

        except IntegrityError:
            db.session.rollback()
            flash(
                f"Error: El usuario '{username}' ya existe. Por favor, elige otro nombre.",
                "danger",
            )

        except Exception as e:
            db.session.rollback()
            flash(f"Error desconocido al crear el usuario: {e}", "danger")

        return redirect(url_for("manage_users"))

    return render_template(
        "manage_users.html", users=users, show_inactive=show_inactive
    )

@app.route("/admin/users/toggle_status/<int:user_id>", methods=["POST"])
@login_required
def toggle_user_status(user_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    user_to_toggle = User.query.get_or_404(user_id)

    if user_to_toggle.username == "Gus":
        flash(
            "No puedes desactivar/eliminar al usuario administrador principal.",
            "danger",
        )
    else:
        new_status = not user_to_toggle.is_active
        user_to_toggle.is_active = new_status
        db.session.commit()

        action = "activado" if new_status else "desactivado"

        app.logger.info(
            f"AUDIT LOG: Admin user {current_user.username} {action} user '{user_to_toggle.username}' (ID: {user_id})."
        )

        flash(f"Usuario {user_to_toggle.username} ha sido {action}.", "success")

        if user_to_toggle.id == current_user.id and not new_status:
            logout_user()
            flash(
                "Tu propia cuenta ha sido desactivada. Debes volver a iniciar sesión.",
                "warning",
            )
            return redirect(url_for("login"))

    return redirect(url_for("manage_users"))


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        flash(
            "Acceso denegado. Solo administradores pueden eliminar usuarios.", "danger"
        )
        return redirect(url_for("admin_panel"))

    user = db.session.get(User, user_id)

    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("manage_users"))

    if user.username == "Gus":
        flash("No se puede eliminar el usuario administrador principal.", "danger")
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
        app.logger.info(
            f"AUDIT LOG: Admin {current_user.username} permanently deleted user {user.username} (ID: {user_id})."
        )
        flash(
            f"Usuario {user.username} (ID: {user_id}) eliminado permanentemente junto con todos sus datos.",
            "success",
        )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al eliminar usuario {user_id}: {e}")
        flash(f"Error crítico al eliminar el usuario: {e}", "danger")

    return redirect(url_for("manage_users"))


@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    reports = (
        Report.query.join(User, Report.user_id == User.id)
        .order_by(Report.date_submitted.desc())
        .all()
    )

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

    if report.status == "En Proceso" or report.status == "Cerrado":
        report.status = "Abierto"

    report.date_resolved = datetime.utcnow()

    db.session.commit()
    flash(f"Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for("view_report_detail", report_id=report_id))


@app.route("/admin/reports/close/<int:report_id>", methods=["POST"])
@login_required
def close_report(report_id):
    # 1. Verificación de Permisos (Tu lógica original)
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    # 2. Lógica de Cierre
    report = Report.query.get_or_404(report_id)

    if report.status != "Cerrado":
        report.status = "Cerrado"
        report.date_resolved = datetime.utcnow()
        db.session.commit()

        # 3. Emisión de SocketIO (La nueva funcionalidad)
        # Asegúrate de que 'socketio' esté disponible (importado o definido globalmente)
        socketio.emit(
            "report_closed",
            {"report_id": report_id},
            room=f"report_{report_id}",
            namespace="/",
        )

        flash(f"Reporte #{report_id} marcado como CERRADO.", "success")

    # 4. Redirección final
    # Puedes redirigir a la lista de reportes o al detalle, dependiendo de lo que prefieras
    return redirect(url_for("admin_reports"))


@app.route("/admin/reports/reopen/<int:report_id>", methods=["POST"])
@login_required
def reopen_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    report = Report.query.get_or_404(report_id)

    if report.status == "Cerrado":
        report.status = "Abierto"
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

    announcements = Announcement.query.order_by(
        Announcement.date_published.desc()
    ).all()
    all_students = (
        User.query.filter_by(role="student", is_active=True)
        .order_by(User.username)
        .all()
    )

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
        read_map=read_map,
    )


# ======================================================================
# --- RUTAS DE ALUMNO (Exámenes, Reportes, Anuncios) ---
# ======================================================================


@app.route("/update_phone_number", methods=["POST"])
@login_required
def update_phone_number():
    if current_user.role != "student":
        return jsonify({"success": False, "message": "Acceso denegado."}), 403

    try:
        data = request.get_json()
        phone_number = data.get("phone_number")
    except Exception:
        return jsonify({"success": False, "message": "Datos JSON inválidos."}), 400

    if not phone_number or not re.match(r"^\+[1-9]\d{7,14}$", phone_number):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Formato de número inválido. Debe incluir código de país (ej: +52XXXXXXXXXX).",
                }
            ),
            400,
        )

    try:
        current_user.phone_number = phone_number
        db.session.commit()
        app.logger.info(
            f"AUDIT LOG: User {current_user.username} updated phone number to {phone_number}."
        )
        return jsonify(
            {"success": True, "message": "Número de teléfono guardado correctamente."}
        )
    except Exception as e:
        db.session.rollback()
        app.logger.error(
            f"Error al guardar número de teléfono para user {current_user.username}: {e}"
        )
        return (
            jsonify(
                {"success": False, "message": "Error interno al guardar los datos."}
            ),
            500,
        )


@app.route("/reports/new", methods=["GET", "POST"])
@login_required
@limiter.limit("1000 per hour")
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
            flash(
                "El título del reporte es inválido o excede el límite de 255 caracteres.",
                "danger",
            )
            return redirect(url_for("new_report"))

        if "image_file" in request.files:
            file = request.files["image_file"]
            if file.filename:

                # --- 🔥 ¡INICIO DE VALIDACIÓN DE ARCHIVO! (Usando filetype) 🔥 ---
                try:
                    header = file.read(2048)
                    file.stream.seek(0)

                    kind = filetype.guess(header)
                    if kind is None or kind.mime not in ALLOWED_MIMETYPES:
                        file_mime = kind.mime if kind else "unknown"
                        app.logger.warning(
                            f"SECURITY: {current_user.username} intentó subir un archivo no permitido ({file_mime}) en new_report."
                        )
                        flash(
                            f"Error: Tipo de archivo no permitido ({file_mime}). Solo se aceptan JPEG, PNG o GIF.",
                            "danger",
                        )
                        return redirect(url_for("new_report"))

                except Exception as e:
                    app.logger.error(f"Error con 'filetype' al validar archivo: {e}")
                    flash("Error al validar el tipo de archivo.", "danger")
                    return redirect(url_for("new_report"))
                # --- 🔥 FIN DE VALIDACIÓN DE ARCHIVO! 🔥 ---

                image_filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, "static", "images")
                os.makedirs(upload_folder, exist_ok=True)
                file.save(os.path.join(upload_folder, image_filename))

        current_time_utc = datetime.utcnow()

        report = Report(
            title=title,
            content=content,  # <-- Usar la variable 'content' corregida
            user_id=current_user.id,
            image_filename=image_filename,
            status="Abierto",
            date_submitted=current_time_utc,
        )
        db.session.add(report)
        db.session.commit()

        # 🔥 NUEVO: Emitir evento de nuevo reporte
        socketio.emit(
            "new_activity",
            {
                "msg": f"🚨 ¡NUEVO REPORTE! {current_user.username} reportó: {title}",
                "type": "danger",
            },
            room="admin_pulse_room",
        )

        flash(
            "Reporte enviado correctamente. Pronto el administrador dará una solución.",
            "success",
        )
        return redirect(url_for("dashboard"))

    return render_template("new_report.html", user=current_user)


@app.route("/student/reports")
@login_required
def student_reports():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    session.pop("just_logged_in", None)

    reports = (
        Report.query.filter_by(user_id=current_user.id)
        .order_by(Report.date_submitted.desc())
        .all()
    )

    for report in reports:
        if report.admin_response and report.date_resolved:
            session_key = (
                f'report_seen_{report.id}_{report.date_resolved.strftime("%Y%m%d%H%M")}'
            )
            session[session_key] = True

    return render_template("student_reports.html", reports=reports)


@app.route("/reports/reply/<int:report_id>", methods=["POST"])
@login_required
@limiter.limit("1000 per hour")
def reply_to_report(report_id):
    report = Report.query.get_or_404(report_id)

    if report.status == "Cerrado":
        flash("No puedes responder a un reporte cerrado.", "danger")
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

    if report.status == "En Proceso" or report.status == "Cerrado":
        report.status = "Abierto"

    db.session.commit()
    flash(f"Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for("student_reports"))


@app.route("/announcements")
@login_required
def view_announcements():
    session.pop("just_logged_in", None)

    all_announcements = (
        Announcement.query.filter_by(is_active=True)
        .join(User, Announcement.admin_id == User.id)
        .order_by(Announcement.date_published.desc())
        .all()
    )

    read_statuses = AnnouncementReadStatus.query.filter_by(
        user_id=current_user.id
    ).all()
    read_ids = {status.announcement_id for status in read_statuses}

    announcements_with_status = []
    for ann in all_announcements:
        announcements_with_status.append(
            {"announcement": ann, "is_new": ann.id not in read_ids}
        )

    return render_template(
        "view_announcements.html", announcements=announcements_with_status
    )


@app.route("/announcements/mark_read/<int:announcement_id>")
@login_required
def mark_announcement_read(announcement_id):
    session.pop("just_logged_in", None)

    status = AnnouncementReadStatus.query.filter_by(
        user_id=current_user.id, announcement_id=announcement_id
    ).first()

    if not status:
        new_status = AnnouncementReadStatus(
            user_id=current_user.id, announcement_id=announcement_id
        )
        db.session.add(new_status)
        db.session.commit()

    return "", 204  # Retorna un status 204 No Contenido

@app.route("/exams")
@login_required
def exams_list():
    # 1. Seguridad
    if current_user.role != "student":
        return redirect(url_for("admin_panel"))

    # 2. IDs de exámenes ya terminados (para ocultarlos)
    completed_exam_ids = [r.exam_id for r in ExamResult.query.filter(
        ExamResult.user_id == current_user.id,
        ExamResult.score >= 0.0
    ).all()]

    # 3. FILTRO CORREGIDO (Objetos Exam directos)
    # Esto devuelve una lista de objetos [Exam1, Exam2], NO diccionarios.
    available_exams = Exam.query.filter(
        Exam.assigned_students.any(id=current_user.id), 
        ~Exam.id.in_(completed_exam_ids)
    ).all()

    # 4. Enviar al HTML
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
        return (
            jsonify(
                {"success": False, "message": "Faltan datos de pregunta o respuesta."}
            ),
            400,
        )

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"success": False, "message": "Pregunta no encontrada."}), 404

    active_session = ActiveExamSession.query.filter_by(
        user_id=current_user.id, exam_id=question.exam_id
    ).first()

    if not active_session:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Tu sesión de examen no está activa o ya ha terminado.",
                }
            ),
            403,
        )

    start_time = active_session.start_time
    time_added = active_session.time_added_sec
    BASE_DURATION_SEC = 3 * 60 * 60  # 10800 (3 horas)
    end_time = start_time + dt.timedelta(seconds=(BASE_DURATION_SEC + time_added))
    current_time_utc = datetime.utcnow()

    if current_time_utc > end_time:
        app.logger.warning(
            f"SECURITY: Rechazado auto-save TARDÍO de {current_user.username} para QID {question_id}."
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Tu tiempo ha expirado. No se pueden guardar más respuestas.",
                }
            ),
            403,
        )

    answer = Answer.query.filter_by(
        user_id=current_user.id, question_id=question_id
    ).first()

    if answer:
        answer.response = response
        action = "updated"
    else:
        answer = Answer(
            response=response, user_id=current_user.id, question_id=question_id
        )
        db.session.add(answer)
        action = "created"

    try:
        db.session.commit()
        return jsonify(
            {"success": True, "message": f"Respuesta {action} para QID {question_id}"}
        )
    except Exception as e:
        db.session.rollback()
        app.logger.error(
            f"Error saving answer (QID: {question_id}, User: {current_user.username}): {e}"
        )
        return (
            jsonify(
                {"success": False, "message": "Error interno al guardar los datos."}
            ),
            500,
        )

# =======================================================
#  FUNCIONES AUXILIARES (HELPER FUNCTIONS)
# =======================================================

def generar_orden_comipems(exam_id):
    """
    Genera una lista de IDs de preguntas ordenadas aleatoriamente
    pero agrupadas por Materia (Subject), estilo examen real.
    """
    # 1. Obtener todas las preguntas
    questions = Question.query.filter_by(exam_id=exam_id).all()
    
    if not questions:
        return []

    # 2. Agrupar por materia
    materias = {}
    for q in questions:
        # Usamos getattr para seguridad si la columna subject está vacía
        nombre_materia = getattr(q, 'subject', 'General') or 'General'
        
        if nombre_materia not in materias:
            materias[nombre_materia] = []
        materias[nombre_materia].append(q.id)
    
    # 3. Revolver el orden de las materias (ej: Primero Mate, luego Español...)
    nombres_materias = list(materias.keys())
    random.shuffle(nombres_materias)
    
    # 4. Crear la lista final plana
    orden_final = []
    for nombre in nombres_materias:
        ids_preguntas = materias[nombre]
        random.shuffle(ids_preguntas) # Revolver las preguntas DENTRO de la materia
        orden_final.extend(ids_preguntas)
        
    return orden_final
@app.route("/exam/<int:exam_id>/take", methods=["GET", "POST"])
@login_required
def take_exam(exam_id):
    # --- 1. SEGURIDAD Y DATOS BÁSICOS ---
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    exam = Exam.query.get_or_404(exam_id)
    current_time = datetime.now() # Hora local del sistema

    # --- 2. VALIDACIÓN DE FECHA (SALA DE ESPERA) ---
    is_locked = False
    seconds_until_start = 0

    # Si es futuro, activamos bloqueo
    if exam.start_datetime and exam.start_datetime > current_time:
        time_diff = exam.start_datetime - current_time
        seconds_until_start = int(time_diff.total_seconds())
        is_locked = True
        
        # RETORNO INMEDIATO: Renderizar Sala de Espera
        return render_template(
            "take_exam.html",
            exam=exam,
            is_locked=True,
            seconds_until_start=seconds_until_start,
            questions=[], 
            start_time_utc=0,
            saved_answers={},
            time_added_sec=0,
            is_cancelled=False,
            cancellation_reason="",
            active_result=None
        )

    # Si ya pasó la fecha fin
    if exam.end_datetime and exam.end_datetime < current_time:
        flash("El tiempo para tomar este examen ha expirado.", "danger")
        return redirect(url_for("exams_list"))

    # --- 3. VERIFICAR RESULTADO PREVIO (BLOQUEO DE REINTENTOS) ---
    existing_result = ExamResult.query.filter_by(
        user_id=current_user.id, exam_id=exam_id
    ).first()

    if existing_result:
        # 🔥 MODIFICACIÓN: Bloqueo agresivo si el examen ya tiene calificación final (>= 0)
        if existing_result.score is not None and existing_result.score >= 0.0:
            flash("Ya has completado este examen. No es posible realizarlo nuevamente.", "info")
            # Redirigimos al detalle del resultado para que vea su calificación anterior
            return redirect(url_for("student_exam_detail", exam_id=exam.id))
        
        # Si fue cancelado (-1)
        elif existing_result.score == -1.0:
            flash("Tu examen fue cancelado y el acceso ha sido bloqueado.", "danger")
            return redirect(url_for("dashboard"))

    # ==============================================================================
    #                                LÓGICA POST (ACCIONES)
    # ==============================================================================
    if request.method == "POST":
        
        # OPCIÓN A: INICIAR TIMER (AJAX)
        if request.form.get("action") == "start_timer_now":
            try:
                # 1. Limpiar sesiones rotas anteriores
                old_session = ActiveExamSession.query.filter_by(
                    user_id=current_user.id, exam_id=exam_id
                ).first()
                if old_session:
                    db.session.delete(old_session)
                    db.session.commit()
                
                # 2. Crear nueva sesión
                new_session = ActiveExamSession(
                    user_id=current_user.id,
                    exam_id=exam_id,
                    start_time=datetime.now(), 
                    time_added_sec=0,
                )
                db.session.add(new_session)

                # 3. Generar orden de preguntas si es nuevo
                if not existing_result:
                    result = ExamResult(
                        user_id=current_user.id, 
                        exam_id=exam_id,
                        score=-2.0  # -2 significa "En Curso/Iniciando"
                    )
                    # Asegúrate de importar la función generar_orden_comipems
                    result.question_order = generar_orden_comipems(exam_id) 
                    db.session.add(result)

                db.session.commit()
                
                # 4. Notificar al Admin
                socketio.emit("new_activity", {
                    "msg": f"🚀 {current_user.username} empezó {exam.title}!",
                    "type": "success",
                }, room="admin_pulse_room")

            except Exception as e:
                db.session.rollback()
                print(f"❌ ERROR AL INICIAR: {e}")
            
            return "", 204

        # OPCIÓN B: ENTREGAR EXAMEN (SUBMIT)
        submission_type = request.form.get("submission_type", "manual")
        
        active_session = ActiveExamSession.query.filter_by(
            user_id=current_user.id, exam_id=exam_id
        ).first()

        # Si no hay sesión activa, no puede entregar (evita envíos duplicados)
        if not active_session:
            return redirect(url_for("student_exam_detail", exam_id=exam_id))

        # --- LÓGICA DE CALIFICACIÓN OPTIMIZADA ---
        recording_json = request.form.get("recording_data")
        if recording_json and len(recording_json) > 500000:
            recording_json = '{"info": "Data too large, omitted to prevent error 400"}'
            
        final_proctoring_data = session.pop(f"proctoring_data_{exam_id}", None)

        # CALCULAR ACIERTOS (Directo en DB para mayor velocidad)
        total_score_sum = db.session.query(Answer).join(Question).filter(
            Answer.user_id == current_user.id,
            Question.exam_id == exam_id,
            Answer.response == Question.correct_option
        ).count()

        # ACTUALIZAR RESULTADO EXISTENTE (-2 a Score Real)
        result_to_update = ExamResult.query.filter_by(
            user_id=current_user.id, exam_id=exam_id
        ).first()
        
        if not result_to_update:
            result_to_update = ExamResult(user_id=current_user.id, exam_id=exam_id)
            db.session.add(result_to_update)

        result_to_update.score = float(total_score_sum)
        result_to_update.date_taken = datetime.now(pytz.utc)
        result_to_update.submission_type = submission_type
        result_to_update.proctoring_data = final_proctoring_data
        result_to_update.session_recording = recording_json

        # 4. LIMPIAR SESIÓN Y GUARDAR
        db.session.delete(active_session)
        
        try:
            db.session.commit()
            socketio.emit("new_activity", {
                "msg": f"✅ {current_user.username} terminó '{exam.title}'.", 
                "type": "success"
            }, room="admin_pulse_room")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error crítico al finalizar: {e}")
            flash("Hubo un problema al guardar, pero tus respuestas están seguras.", "warning")

        flash("Examen finalizado correctamente.", "success")
        return redirect(url_for("student_exam_detail", exam_id=exam.id))

    # ==============================================================================
    #                                LÓGICA GET (RENDERIZAR)
    # ==============================================================================
    
    # 1. Recuperar Sesión Activa
    active_session = ActiveExamSession.query.filter_by(
        user_id=current_user.id, exam_id=exam_id
    ).first()

    start_time = 0
    time_added_sec = 0

    if active_session:
        if active_session.start_time:
            if active_session.start_time.tzinfo is None:
                start_time = int(active_session.start_time.timestamp())
            else:
                start_time = int(active_session.start_time.timestamp())
        
        time_added_sec = active_session.time_added_sec if active_session.time_added_sec else 0

    # 2. Recuperar Preguntas en el orden guardado
    questions = []
    if existing_result and existing_result.question_order:
        ids_ordenados = existing_result.question_order
        todas = Question.query.filter(Question.id.in_(ids_ordenados)).all()
        q_map = {q.id: q for q in todas}
        for q_id in ids_ordenados:
            if q_id in q_map: questions.append(q_map[q_id])
        
        # Sincronizar si se añadieron preguntas extra después
        ids_set = set(ids_ordenados)
        nuevas = Question.query.filter_by(exam_id=exam_id).filter(~Question.id.in_(ids_set)).all()
        questions.extend(nuevas)
    else:
        questions = Question.query.filter_by(exam_id=exam_id).all()

    # 3. Cargar respuestas guardadas para reasumir
    saved_answers = Answer.query.filter_by(user_id=current_user.id).join(Question).filter(Question.exam_id == exam_id).all()
    saved_answers_dict = {a.question_id: a.response for a in saved_answers}

    # 4. Verificar si el usuario está cancelado localmente
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
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    session.pop("just_logged_in", None)

    exam = Exam.query.get_or_404(exam_id)

    result = ExamResult.query.filter_by(
        user_id=current_user.id, exam_id=exam_id
    ).first()

    answers = (
        Answer.query.join(Question)
        .filter(Answer.user_id == current_user.id, Question.exam_id == exam_id)
        .all()
    )

    answers_dict = {a.question_id: a for a in answers}

    if not result:
        flash("Aún no has completado este examen.", "danger")
        return redirect(url_for("student_exams"))

    return render_template(
        "student_exam_detail.html", exam=exam, answers_dict=answers_dict, result=result
    )

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
# ======================================================================
# --- INICIALIZACIÓN DE LA APLICACIÓN ---
# ======================================================================

if __name__ == "__main__":
    with app.app_context():
        # 1. Crea todas las tablas si no existen
        db.create_all()
        app.logger.info("Verificación de tablas completada.")

        # 2. Creación del usuario Admin 'Gus' si no existe
        from werkzeug.security import generate_password_hash

        # Busca si existe el usuario 'Gus'
        if User.query.filter_by(username="Gus").first() is None:
            hashed_password = generate_password_hash("241224", method="pbkdf2:sha256")

            admin_user = User(
                username="Gus", password=hashed_password, role="admin", is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Usuario Admin 'Gus' creado exitosamente.")
        else:
            app.logger.info("El usuario Admin 'Gus' ya existe.")

    # 3. Configuración del Puerto y Arranque con SocketIO
    import os

    # Intenta obtener el puerto del entorno (para Heroku/Render), si no usa 5000
    port = int(os.environ.get("PORT", 5000))

    print(f"🚀 Iniciando servidor SocketIO en http://0.0.0.0:{port}")
    # 🔥 ESTA LÍNEA HABILITA EL CHAT EN VIVO 🔥
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
