from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_babel import Babel, format_datetime
import datetime as dt
import os
import pytz # CLAVE: Para manejo de zonas horarias
import pyotp
import qrcode
import base64
from io import BytesIO
import time
import re
import logging
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from sqlalchemy import func as db_func
from sqlalchemy import case
from sqlalchemy.exc import IntegrityError
from flask_socketio import SocketIO, emit, join_room, leave_room, ConnectionRefusedError
from twilio.rest import Client # 🔑 AGREGADO: Importación de Twilio 🔑

load_dotenv()


# 🔑 CONFIGURACIÓN DE LOGGING 🔑
LOG_FILE = 'app.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- CONFIGURACIÓN DE PRODUCCIÓN (CLAVE SECRETA Y DB) ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///curso_ecoms.db')

# --- Configuración básica de la aplicación ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔑 AGREGADO: CONFIGURACIÓN DE TWILIO (Variables de Entorno) 🔑
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")

if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER:
    try:
        # Asegúrate de que el número de Twilio esté en formato E.164 (ej: +15017122661)
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        logging.info("Twilio client initialized successfully.")
    except Exception as e:
        logging.error(f"Error al inicializar cliente Twilio: {e}")
        twilio_client = None
else:
    logging.warning("Twilio no está configurado (faltan ENV vars). La funcionalidad de SMS/WhatsApp estará deshabilitada.")
    twilio_client = None
# -------------------------------------------------------------

# 🔑 SEGURIDAD: Configuración de Sesión y Fuerza Bruta 🔑
app.config['PERMANENT_SESSION_LIFETIME'] = dt.timedelta(minutes=30) # Timeout de 30 minutos
LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300 # 5 minutos en segundos

# Inicialización de extensiones (en este orden recomendado)
db = SQLAlchemy(app)
# 🚨 ELIMINADA LA INSTANCIA DE FLASK-MIGRATE 🚨
# migrate = Migrate(app, db) 

login_manager = LoginManager()
login_manager.init_app(app) 
login_manager.login_view = "login"

# 🔑 INICIALIZACIÓN DE SOCKETIO 🔑
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*") 

# ======================================================================
# 🚨 INTEGRACIÓN DE BABEL Y ZONA HORARIA (CONFIGURACIÓN FINAL Y ESTABLE) 🚨
# ======================================================================

# 1. Definimos la instancia de Babel para inicializarla inmediatamente
babel = Babel(app)

# 2. Funciones de selector de Babel (DEFINIMOS SIN DECORADOR, para evitar el AttributeError)
def get_locale_selector(): 
    """Intenta obtener el mejor locale del navegador, o usa 'es' por defecto."""
    if request and hasattr(request, 'accept_languages'):
        return request.accept_languages.best_match(['es', 'en'])
    return 'es'

def get_timezone_selector():
    """Retorna la zona horaria configurada en la aplicación."""
    return 'America/Mexico_City'


# 3. CONFIGURACIÓN DE BABEL
app.config['BABEL_DEFAULT_LOCALE'] = 'es'
app.config['BABEL_DEFAULT_TIMEZONE'] = 'America/Mexico_City'

# 4. EXPORTAR la función de formato a Jinja (Esto es seguro)
app.jinja_env.globals.update(format_datetime=format_datetime)

# 5. ASIGNACIÓN MANUAL (MÉTODO ROBUSTO)
try:
    babel.locale_selector_func = get_locale_selector
    babel.timezone_selector_func = get_timezone_selector
except Exception as e:
    logging.warning(f"WARN: Fallo la asignacion manual de selectores de Babel: {e}. Usando valores por defecto.")
    

# ======================================================================
# --- Modelos (Mantenidos del Código 2) ---
# ======================================================================
class User(db.Model, UserMixin):
# ... resto del código ...
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="student")
    two_factor_secret = db.Column(db.String(32), nullable=True) 
    is_active = db.Column(db.Boolean, default=True) 
    # 🔑 AGREGADO: Campo de número de teléfono 🔑
    phone_number = db.Column(db.String(20), nullable=True)
    # -----------------------------------------------------
    results = db.relationship("ExamResult", backref="user", lazy=True) 
    violation_logs = db.relationship("ViolationLog", backref="user", lazy=True) 

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_datetime = db.Column(db.DateTime, nullable=True)
    end_datetime = db.Column(db.DateTime, nullable=True)
    # Ya tenía cascada para Questions y Sessions
    questions = db.relationship("Question", backref="exam", cascade="all, delete-orphan")
    active_sessions = db.relationship("ActiveExamSession", backref="exam", cascade="all, delete-orphan") 
    
    # 🔑 CORRECCIÓN CLAVE: Añadimos cascade para ViolationLog 🔑
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

# 🔑 NUEVO MODELO PARA MONITOREO EN VIVO 🔑
class ActiveExamSession(db.Model):
    __tablename__ = 'active_exam_session'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    time_added_sec = db.Column(db.Integer, default=0) 
    user = db.relationship('User', backref=db.backref('active_session', uselist=False))

# 🔑 CAMBIO/ADICIÓN SOLICITADA: Definición de la clase ViolationLog 🔑
class ViolationLog(db.Model):
    __tablename__ = 'violation_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    violation_type = db.Column(db.String(100), nullable=False) # Ej: 'Tab Switch', 'Minimize'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True) # Detalles adicionales si es necesario
# -------------------------------------------------------------------

# ======================================================================
# --- AGREGADO: FUNCIÓN DE UTILIDAD: ENVÍO DE NOTIFICACIONES ---
# ======================================================================

def send_twilio_notification(to_number, body_message):
    """
    Intenta enviar un mensaje de Twilio (SMS o WhatsApp).
    Retorna True si tiene éxito, False si falla o no está configurado.
    """
    if twilio_client is None:
        logging.warning("Twilio no está configurado. Mensaje no enviado.")
        return False

    try:
        # 🔑 CLAVE PARA WHATSAPP: Usar el prefijo 'whatsapp:' en el número de origen y destino.
        # to_number debe ser el número del alumno, que Twilio necesita registrar.
        # from_ debe ser tu número de Twilio con el prefijo 'whatsapp:'.
        
        # 1. Adaptar el número de Twilio a formato WhatsApp (ej: +1234567 -> whatsapp:+1234567)
        whatsapp_from = f"whatsapp:{TWILIO_PHONE_NUMBER}"
        # 2. Adaptar el número del alumno a formato WhatsApp
        whatsapp_to = f"whatsapp:{to_number}"

        message = twilio_client.messages.create(
            to=whatsapp_to,
            from_=whatsapp_from,
            body=body_message
        )
        logging.info(f"Notificación Twilio (WhatsApp) enviada a {to_number}. SID: {message.sid}")
        return True
    except Exception as e:
        logging.error(f"Error al enviar notificación Twilio (WhatsApp) a {to_number}: {e}")
        # En caso de error de WhatsApp (plantillas o sandbox no configurados),
        # puedes intentar enviar un SMS como fallback aquí, pero lo mantendremos simple por ahora:
        return False
        
# ======================================================================
# --- MANEJADORES DE SOCKETIO (CHAT EN VIVO Y SEGURIDAD) ---
# ======================================================================

@socketio.on('connect')
def handle_connect():
    """
    Maneja la conexión inicial del cliente SocketIO.
    """
    logging.info("Socket CONNECTED. Attempting to get user context.")
    if current_user.is_authenticated:
        join_room(str(current_user.id))
        logging.info(f"Socket conectado y unido al room de usuario: User {current_user.username} (ID: {current_user.id})")


@socketio.on('disconnect')
def handle_disconnect():
    """Maneja la desconexión del cliente SocketIO."""
    if current_user.is_authenticated:
        leave_room(str(current_user.id))
        logging.info(f"Socket desconectado: User {current_user.username} (ID: {current_user.id})")


@socketio.on('join_room')
def on_join(data):
    """Permite al admin unirse a la sala del alumno (target_user_id)."""
    if not current_user.is_authenticated or current_user.role != 'admin':
        logging.warning("SECURITY: Unauthorized user tried to join admin chat.")
        return

    target_user_id = str(data.get('user_id'))
    join_room(target_user_id)
    logging.info(f"ADMIN CHAT: Admin {current_user.username} joined room {target_user_id}.")
    emit('status_update', 
          {'msg': f'Conectado a la sala del alumno ID {target_user_id}.'}, 
          room=str(current_user.id)
    )

@socketio.on('send_message_to_student')
def handle_admin_message(data):
    """
    Maneja el mensaje enviado por el Admin. 
    """
    if not current_user.is_authenticated or current_user.role != 'admin':
        logging.warning(f"SECURITY: Non-admin user {current_user.username} attempted to send chat message.")
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
        logging.info(f"CHAT: Admin {current_user.username} sent message to User ID {target_room}: {message_content[:30]}...")
        
@socketio.on('send_message_to_admin')
def handle_student_response(data):
    """
    Maneja el mensaje enviado por el Alumno (si está en take_exam). 
    """
    if not current_user.is_authenticated or current_user.role != 'student':
        return

    admin_room = str(data.get('target_admin_id'))
    message_content = data.get('message')
    
    if admin_room and message_content:
        emit('admin_message_received', 
              {
                  'message': message_content,
                  'timestamp': datetime.now().strftime("%H:%M:%S"),
                  'sender': current_user.username
              },
              room=admin_room,
              namespace='/'
        )
        logging.info(f"CHAT: Student {current_user.username} replied to Admin ID {admin_room}: {message_content[:30]}...")


@socketio.on('close_student_chat_remote')
def handle_close_chat(data):
    """
    Maneja la solicitud del Admin para cerrar el chat del alumno.
    """
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
        logging.info(f"CHAT: Admin {current_user.username} closed chat session for User ID {target_room}.")
        
# 🔑 CAMBIO/ADICIÓN SOLICITADA: Handler de SocketIO para guardar la violación 🔑
@socketio.on('exam_violation')
def handle_exam_violation(data):
    """
    Recibe la señal del cliente cuando el alumno realiza una acción prohibida,
    registra el log en la base de datos y notifica al panel de monitoreo del Admin.
    """
    if not current_user.is_authenticated or current_user.role != 'student':
        return
    
    violation_type = data.get('type', 'Unknown Violation')
    exam_id = data.get('exam_id')
    user_id = current_user.id
    
    if not exam_id or not user_id:
        logging.error(f"Error al registrar violación: Missing exam_id or user_id in data: {data}")
        return

    try:
        # 🚨 CORRECCIÓN CLAVE DE ZONA HORARIA: Guardar la hora local de México 🚨
        mexico_city_tz = pytz.timezone('America/Mexico_City')
        current_time_mexico = datetime.now(mexico_city_tz)
        
        # 1. Registrar la violación en la base de datos
        new_log = ViolationLog(
            user_id=user_id,
            exam_id=exam_id,
            violation_type=violation_type,
            # Usamos el objeto aware (consciente de la zona horaria)
            timestamp=current_time_mexico, 
            details=f"Violación de tipo: {violation_type}."
        )
        db.session.add(new_log)
        db.session.commit()
        
        logging.warning(f"🚨 SECURITY LOGGED: User: {current_user.username}, Exam ID: {exam_id}, Type: {violation_type}.")
        
        # 2. Notificar al panel de monitoreo de Admin
        socketio.emit('admin_violation_alert', 
                      {'user_id': user_id, 
                       'username': current_user.username, 
                       'exam_id': exam_id, 
                       'type': violation_type, 
                       'timestamp': datetime.now().strftime("%H:%M:%S")},
                      room='1', # Asume que el admin principal (ID 1) recibe todas las alertas
                      namespace='/')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error DB al registrar violación (User: {user_id}, Type: {violation_type}): {e}")


# ======================================================================
# --- HOOKS DE SEGURIDAD Y MANEJADORES ---
# ======================================================================

# 🔑 HOOK DE SEGURIDAD 1: Encabezados Anti-XSS y Anti-Clickjacking 🔑
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' 
    return response

# 🔑 HOOK DE SEGURIDAD 2: Actualizar actividad de la sesión (Para Timeout) y Soft Delete Check 🔑
@app.before_request
def before_request_hook():
    if current_user.is_authenticated:
        # 🔑 SOFT DELETE CHECK: Si el usuario activo es desactivado, forzamos el logout 🔑
        if not current_user.is_active:
            logging.warning(f"SECURITY ALERT: Active user {current_user.username} was deactivated. Forcing logout.")
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
                    # Intento de parsear sin microsegundos si falla el primero
                    try:
                        last_activity = datetime.strptime(last_activity.split('.')[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        # Si aún falla, forzamos un reset
                        last_activity = datetime.utcnow() - session_lifetime * 2 


            if (datetime.utcnow() - last_activity) > session_lifetime:
                logout_user()
                flash("Tu sesión ha expirado por inactividad. Vuelve a iniciar sesión.", "warning")
                return redirect(url_for('login'))
        
        # 2. Actualizar el tiempo de última actividad
        session['last_activity'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

# --- Login Manager ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================================================================
# --- RUTAS DE ACCESO PRINCIPAL (Index, Login, Logout, Dashboards) ---
# ======================================================================

# --- RUTA DE CIERRE DE SESIÓN ---
@app.route("/logout")
@login_required
def logout():
    logging.info(f"AUDIT LOG: User {current_user.username} logged out.")
    logout_user()
    flash("Has cerrado sesión exitosamente.", "success")
    return redirect(url_for("index"))


# --- PANEL ADMINISTRADOR ---
@app.route("/admin")
@login_required
def admin_panel():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
        
    if session.pop('just_logged_in', False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")

    exams = Exam.query.all()
    announcements_list = Announcement.query.order_by(Announcement.date_published.desc()).all() 
    
    # Se pasa esta variable vacía para evitar un error en el template Jinja2
    # La lógica real para contar los alumnos "en vivo" se implementa con SocketIO.
    active_exams_summary = []
    
    return render_template("admin.html", 
                           exams=exams, 
                           announcements_list=announcements_list,
                           active_exams_summary=active_exams_summary 
                           )


# --- PANEL ESTUDIANTE / DASHBOARD ---
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    if session.pop('just_logged_in', False):
        flash(f"Inicio de sesión exitoso. Bienvenido, {current_user.username}.", "success")
        
    # 1. CÁLCULO DE ANUNCIOS NO LEÍDOS
    total_announcements = Announcement.query.count()
    read_count = AnnouncementReadStatus.query.filter_by(user_id=current_user.id).count()
    unread_count = total_announcements - read_count
    
    # 2. WIDGET: Última Simulación/Resultado
    last_result = ExamResult.query.filter_by(user_id=current_user.id)\
                      .order_by(ExamResult.date_taken.desc()).first()
                      
    last_exam_questions_count = 0
    if last_result:
        exam = Exam.query.get(last_result.exam_id)
        if exam:
            last_exam_questions_count = len(exam.questions)


    # 3. WIDGET: Top 3 Materias a Reforzar 
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
    
    # 4. WIDGET: Historial de Reportes (Últimos 3) 🔑
    latest_reports = Report.query.filter_by(user_id=current_user.id)\
                              .order_by(Report.date_submitted.desc())\
                              .limit(3).all()
    
    # 5. Notificación de Respuesta del Admin
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


# --- RUTA DE INICIO (INDEX) ---
@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
            
    return render_template("index.html")

# 🔑 NUEVA RUTA: Aviso de Privacidad 🔑
@app.route("/privacy")
def privacy_notice():
    return render_template("privacy.html")

# --- RUTA DE LOGIN (CON FUERZA BRUTA Y AJUSTE DE REDIRECCIÓN) ---
@app.route("/login", methods=["GET", "POST"])
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
            logging.warning(f"SECURITY: Invalid username format attempted: {username}")
            flash("Formato de usuario inválido. Solo se permiten letras, números y '_'.", "danger")
            return redirect(url_for('index')) 
        
        lockout_end_time = session.get('lockout_end_time', 0)
        current_time = time.time()
        
        # VERIFICAR BLOQUEO POR FUERZA BRUTA
        if current_time < lockout_end_time:
            remaining_time = int(lockout_end_time - current_time)
            logging.warning(f"SECURITY: Login attempt blocked for user {username} (Lockout active)")
            flash(f"Demasiados intentos fallidos. Intenta de nuevo en {remaining_time} segundos.", "danger")
            return redirect(url_for('index')) 
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not check_password_hash(user.password, password):
            
            failed_attempts = session.get('failed_attempts', 0) + 1
            session['failed_attempts'] = failed_attempts
            
            logging.info(f"SECURITY: Failed password attempt for user: {username}")
            
            if failed_attempts >= LOGIN_ATTEMPTS:
                session['lockout_end_time'] = current_time + LOCKOUT_TIME
                session['failed_attempts'] = 0 
                logging.warning(f"SECURITY ALERT: User {username} locked out for {LOCKOUT_TIME} seconds.")
                flash(f"Demasiados intentos. Tu cuenta ha sido bloqueada por {LOCKOUT_TIME} segundos.", "danger")
            else:
                flash("Usuario o contraseña incorrectos", "danger")
            
            return redirect(url_for("index")) 
            
        # SOFT DELETE CHECK: Verificar si el usuario está activo
        if not user.is_active:
            logging.warning(f"SECURITY ALERT: Blocked inactive user {username} login attempt.")
            flash("Tu cuenta está inactiva. Contacta al administrador.", "danger")
            return redirect(url_for("index")) 
            
        # Si la contraseña es correcta, limpiar intentos fallidos y bloquear
        session.pop('failed_attempts', None)
        session.pop('lockout_end_time', None)
        
        # LÓGICA 2FA: Almacenar temporalmente la identidad después de la contraseña
        if user.two_factor_secret:
            session['temp_user_id'] = user.id
            return redirect(url_for('verify_2fa'))
            
        # Loguear directamente si no hay 2FA
        login_user(user)
        session.permanent = True 
        session['last_activity'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        session['just_logged_in'] = True 
        logging.info(f"AUDIT LOG: User {user.username} logged in successfully.")
        
        if user.role in ["admin", "ayudante"]:
            return redirect(url_for("admin_panel"))
        else:
            return redirect(url_for("dashboard"))
            
    return render_template("login.html")


# ======================================================================
# --- RUTAS DE SEGURIDAD (2FA) ---
# ======================================================================

# RUTA: Verificar 2FA
@app.route("/verify_2fa", methods=["GET", "POST"])
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
            logging.info(f"AUDIT LOG: User {user.username} verified 2FA successfully.")
            flash("Verificación 2FA exitosa. Bienvenido.", "success")
            
            if user.role in ["admin", "ayudante"]:
                return redirect(url_for("admin_panel"))
            else:
                return redirect(url_for("dashboard"))
        else:
            logging.warning(f"SECURITY ALERT: Failed 2FA code entered for user: {user.username}")
            flash("Código de verificación 2FA incorrecto.", "danger")

    return render_template('verify_2fa.html')

# RUTA: Configurar 2FA (Solo Admin)
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
            logging.info(f"AUDIT LOG: Admin user {current_user.username} activated 2FA successfully.")
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

# RUTA: Desactivar 2FA (Solo Admin)
@app.route("/disable_2fa", methods=["POST"])
@login_required
def disable_2fa():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    current_user.two_factor_secret = None
    db.session.commit()
    logging.info(f"AUDIT LOG: Admin user {current_user.username} disabled 2FA.")
    flash("✅ Autenticación de Dos Factores (2FA) ha sido desactivada.", "success")
    return redirect(url_for('admin_panel'))


# ======================================================================
# --- RUTAS DE ADMINISTRACIÓN Y GESTIÓN ---
# ======================================================================

# --- Admin: Interfaz de Chat en Vivo con Alumno ---
@app.route("/admin/chat/<int:user_id>")
@login_required
def admin_chat(user_id):
    # 🔑 CONTROL DE ACCESO: SOLO ADMIN 🔑 (Solo el admin puede iniciar el chat de soporte)
    if current_user.role != "admin":
        flash("Acceso denegado. Solo los administradores principales pueden iniciar el chat de soporte.", "danger")
        return redirect(url_for("dashboard"))
        
    target_user = User.query.get_or_404(user_id)
    
    # Renderizamos la interfaz de chat, pasándole el objeto del alumno
    return render_template("admin_chat.html", target_user=target_user)


# --- RUTA: Interfaz de Monitoreo de Examen (Etapa 1.2) ---
@app.route("/admin/exams/monitor/<int:exam_id>")
@login_required
def admin_exam_monitor_detail(exam_id):
    # 🔑 CONTROL DE ACCESO: ADMIN (Solo Admin puede ver el chat) 🔑
    if current_user.role != "admin":
        flash("Acceso denegado. Solo administradores principales pueden acceder al monitoreo.", "danger")
        return redirect(url_for("admin_panel"))
        
    exam = Exam.query.get_or_404(exam_id)
    
    # 1. Obtener todos los usuarios estudiantes activos
    # Es crucial listar a TODOS los estudiantes para mostrar los que 'No Han Iniciado'
    all_students = User.query.filter_by(role='student', is_active=True).all()
    
    monitoring_data = []
    
    for student in all_students:
        user_id = student.id
        
        # 2. Verificar si ya terminó el examen (ExamResult)
        is_finished = ExamResult.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        
        # 3. Verificar si está haciendo el examen ahora (ActiveExamSession)
        # SQLAlchemy es eficiente: hace la consulta por cada alumno.
        is_active = ActiveExamSession.query.filter_by(user_id=user_id, exam_id=exam_id).first()
        
        status = 'No Ha Iniciado'
        
        if is_active:
            status = 'Haciendo Examen'
        elif is_finished:
            status = 'Examen Terminado'
        
        monitoring_data.append({
            'user_id': user_id,
            'username': student.username,
            'status': status
        })
        
    return render_template("admin_exam_monitor.html", exam=exam, monitoring_data=monitoring_data)


# 🔑 RUTA NUEVA: Administrador añade tiempo extra a un examen en curso 🔑
@app.route('/admin/add_time_to_exam', methods=['POST'])
@login_required
def admin_add_time_to_exam():
    # Solo administradores pueden usar esta función
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403

    try:
        data = request.get_json()
        student_id = int(data.get('student_id'))
        # Nota: El tiempo siempre debe venir en segundos (ej. 600 para 10 minutos)
        time_to_add_sec = int(data.get('time_sec')) 
        
        # 1. Buscar la sesión del alumno
        session_db = ActiveExamSession.query.filter_by(user_id=student_id).first() 

        if not session_db:
            return jsonify({'success': False, 'message': 'Sesión de examen activa no encontrada.'}), 404

        # 2. Sumar el tiempo y guardar en DB
        session_db.time_added_sec += time_to_add_sec
        db.session.commit()

        # 3. Notificar al cliente (alumno) a través de SocketIO
        # Emitimos el tiempo adicional total y el ID del alumno
        socketio.emit('time_update', 
                      {'extra_time_sec': session_db.time_added_sec}, 
                      room=str(student_id)) # Enviamos a la sala privada del alumno (su ID)

        return jsonify({'success': True, 
                        'message': f'Se añadieron {time_to_add_sec/60} minutos al alumno {student_id}.',
                        'new_total_extra_sec': session_db.time_added_sec})

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al añadir tiempo: {e}")
        return jsonify({'success': False, 'message': f'Error interno: {str(e)}'}), 500

# 🔑 CAMBIO/ADICIÓN SOLICITADA: RUTA NUEVA: Ver Logs de Violación del Alumno 🔑
@app.route("/admin/monitor/logs/<int:exam_id>/<int:user_id>")
@login_required
def view_violation_logs(exam_id, user_id):
    if current_user.role != "admin":
        flash("Acceso denegado.", "danger")
        return redirect(url_for("dashboard"))
    
    student = User.query.get_or_404(user_id)
    exam = Exam.query.get_or_404(exam_id)
    
    # Obtener logs de violación para el alumno y el examen
    # Esto traerá objetos datetime sin zona horaria (naive datetime)
    logs = ViolationLog.query.filter_by(user_id=user_id, exam_id=exam_id).order_by(ViolationLog.timestamp.desc()).all()
    
    # --- 🚨 CORRECCIÓN DE ZONA HORARIA 🚨 ---
    # 1. Definir la zona horaria UTC (asumimos que la DB guardó en UTC)
    utc_tz = pytz.utc
    
    # 2. Iterar sobre los logs y "pegar" la información de UTC al objeto de tiempo
    # Esto convierte el objeto naive (sin zona horaria) en aware (consciente de la zona horaria)
    for log in logs:
        # Solo modificamos si es naive (no tiene tzinfo)
        if log.timestamp and not log.timestamp.tzinfo:
            log.timestamp = utc_tz.localize(log.timestamp)

    # ----------------------------------------
    
    return render_template("admin_violation_logs.html", 
                           student=student, 
                           exam=exam, 
                           logs=logs)
# 🔑 FIN DE CAMBIO/ADICIÓN SOLICITADA 🔑


# --- Admin: Crear Anuncio ---
@app.route("/admin/announcements/new", methods=["GET", "POST"])
@login_required
def new_announcement():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]

        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(url_for("new_announcement"))

        mexico_city_tz = pytz.timezone('America/Mexico_City')
        current_time_mexico = datetime.now(mexico_city_tz).replace(tzinfo=None)

        announcement = Announcement(
            title=title,
            content=content,
            admin_id=current_user.id, 
            date_published=current_time_mexico
        )
        db.session.add(announcement)
        db.session.commit()

        logging.info(f"AUDIT LOG: Admin user {current_user.username} created new announcement '{title}'.")
        
        # 🔑 AGREGADO: LÓGICA DE NOTIFICACIÓN SMS/WHATSAPP DE TWILIO 🔑
        all_students = User.query.filter_by(role='student', is_active=True).all()
        notification_body = f"📣 Nuevo Anuncio Crítico: '{title}'. Revisa la plataforma para leer el mensaje completo."
        
        for student in all_students:
            # Solo enviar si el usuario tiene un número de teléfono registrado
            if student.phone_number:
                send_twilio_notification(student.phone_number, notification_body)
        # ------------------------------------------------------------

        flash("Anuncio creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_announcement.html")

# --- Admin: Editar Anuncio ---
@app.route("/admin/announcements/edit/<int:announcement_id>", methods=["GET", "POST"])
@login_required
def edit_announcement(announcement_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    announcement = Announcement.query.get_or_404(announcement_id)

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        
        if len(title.strip()) == 0:
            flash("El título del anuncio no puede estar vacío.", "danger")
            return redirect(url_for("edit_announcement", announcement_id=announcement_id))
            
        announcement.title = title
        announcement.content = content
        announcement.is_active = 'is_active' in request.form 
        
        db.session.commit()
        logging.info(f"AUDIT LOG: Admin user {current_user.username} edited announcement ID {announcement_id}.")
        flash("✅ Anuncio actualizado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("edit_announcement.html", announcement=announcement)

# --- Admin: Eliminar Anuncio ---
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
        logging.info(f"AUDIT LOG: Admin user {current_user.username} deleted announcement '{announcement_to_delete.title}' (ID: {announcement_id}).")
        flash(f"✅ Anuncio '{announcement_to_delete.title}' ha sido eliminado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error al eliminar el anuncio: {e}", "danger")

    return redirect(url_for("admin_panel"))


# 🔑 RUTA: Editar Examen (Permite modificar título, descripción y horario) 🔑
@app.route("/admin/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@login_required
def edit_exam(exam_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    exam = Exam.query.get_or_404(exam_id)

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")
        
        start_dt = None
        end_dt = None
        
        try:
            if start_date_str:
                start_dt = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Formato de fecha y hora inválido. Usa el formato YYYY-MM-DD HH:MM.", "danger")
            return redirect(url_for("edit_exam", exam_id=exam_id))

        if len(title.strip()) == 0:
            flash("El título del examen no puede estar vacío.", "danger")
            return redirect(url_for("edit_exam", exam_id=exam_id))

        exam.title = title
        exam.description = description
        exam.start_datetime = start_dt
        exam.end_datetime = end_dt
        
        db.session.commit()
        
        logging.info(f"User {current_user.username} edited exam '{title}' (ID: {exam.id}).")

        flash("✅ Examen actualizado correctamente.", "success")
        return redirect(url_for("admin_panel"))

    def format_datetime_local(dt_obj):
        if dt_obj:
            return dt_obj.strftime('%Y-%m-%dT%H:%M')
        return ''

    return render_template(
        "edit_exam.html", 
        exam=exam,
        start_date_str=format_datetime_local(exam.start_datetime),
        end_date_str=format_datetime_local(exam.end_datetime)
    )

# --- Admin: crear examen ---
@app.route("/admin/exams/new", methods=["GET", "POST"])
@login_required
def new_exam():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop('just_logged_in', None) 

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        
        start_date_str = request.form.get("start_datetime")
        end_date_str = request.form.get("end_datetime")
        
        start_dt = None
        end_dt = None
        
        try:
            if start_date_str:
                start_dt = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Formato de fecha y hora inválido. Usa el formato YYYY-MM-DD HH:MM.", "danger")
            return redirect(url_for("new_exam"))
        
        if len(title.strip()) == 0:
            flash("El título del examen no puede estar vacío.", "danger")
            return redirect(url_for("new_exam"))

        exam = Exam(
            title=title, 
            description=description,
            start_datetime=start_dt, 
            end_datetime=end_dt
        )
        db.session.add(exam)
        db.session.commit()
        
        logging.info(f"AUDIT LOG: Admin user {current_user.username} created new exam '{title}'.")

        flash("Examen creado correctamente", "success")
        return redirect(url_for("admin_panel"))

    return render_template("new_exam.html")


# 🔑 RUTA: Duplicar Examen 🔑
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
            end_datetime=original_exam.end_datetime
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
                exam_id=new_exam.id 
            )
            db.session.add(new_question)
            
        db.session.commit()
        
        logging.info(f"AUDIT LOG: Admin user {current_user.username} duplicated exam '{original_exam.title}' to '{new_exam.title}'.")
        flash(f"✅ Examen '{original_exam.title}' duplicado correctamente a '{new_exam.title}'.", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error al duplicar el examen: {e}", "danger")

    return redirect(url_for("admin_panel"))


# --- Admin: agregar preguntas ---
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
        
        if not text or not correct_option:
            flash("El texto de la pregunta y la opción correcta son obligatorios.", "danger")
            return redirect(url_for("add_question", exam_id=exam_id))

        image_filename = None

        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename:
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
            exam_id=exam_id
        )
        db.session.add(question)
        db.session.commit()
        
        flash("✅ Pregunta agregada correctamente", "success")

    questions = Question.query.filter_by(exam_id=exam_id).all()
    return render_template("add_question.html", exam=exam, questions=questions)


# --- Admin: Editar Pregunta Específica ---
@app.route("/admin/questions/edit/<int:question_id>", methods=["GET", "POST"])
@login_required
def edit_question(question_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id

    if request.method == "POST":
        question.text = request.form["text"]
        question.subject = request.form.get("subject")
        question.option_a = request.form.get("option_a")
        question.option_b = request.form.get("option_b")
        question.option_c = request.form.get("option_c")
        question.option_d = request.form.get("option_d")
        question.correct_option = request.form.get("correct_option")
        
        # Lógica de actualización de imagen omitida para no repetir el código.

        db.session.commit()
        logging.info(f"AUDIT LOG: User {current_user.username} edited question ID {question_id} in Exam ID {exam_id}.")
        flash("✅ Pregunta actualizada correctamente", "success")
        return redirect(url_for("add_question", exam_id=exam_id))

    return render_template("edit_question.html", question=question, exam_id=exam_id) 

# --- Admin: Eliminar Pregunta ---
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
        logging.info(f"AUDIT LOG: User {current_user.username} deleted question ID {question_id} from Exam ID {exam_id}.")
        flash("✅ Pregunta eliminada correctamente.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error al eliminar la pregunta: {e}", "danger")

    return redirect(url_for("add_question", exam_id=exam_id))


# --- Admin: Eliminar Examen ---
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
        logging.info(f"AUDIT LOG: Admin user {current_user.username} deleted exam '{exam_to_delete.title}' (ID: {exam_id}).")
        flash(f"✅ Examen '{exam_to_delete.title}' y todos sus datos han sido eliminados.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error al eliminar el examen: {e}", "danger")

    return redirect(url_for("admin_panel"))

# --- Admin: Exportar Todos los Resultados a CSV ---
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

# --- Admin: Lista de ALUMNOS que tomaron el examen ---
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
        User.id.label('user_id')
    ).join(ExamResult, User.id == ExamResult.user_id
    ).filter(ExamResult.exam_id == exam_id
    ).order_by(ExamResult.date_taken.desc()
    ).all()
    
    return render_template("review_results.html", exam=exam, results=results)


# --- Admin: Revisión DETALLADA del Examen de un Alumno ---
@app.route("/admin/exams/<int:exam_id>/review/<int:user_id>")
@login_required
def review_student_exam(exam_id, user_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    exam = Exam.query.get_or_404(exam_id)
    student = User.query.get_or_404(user_id)
    
    review_data = db.session.query(
        Question, 
        Answer
    ).join(Answer, Question.id == Answer.question_id
    ).filter(
        Question.exam_id == exam_id,
        Answer.user_id == user_id
    ).order_by(Question.id
    ).all()
    
    return render_template("review_detail.html", exam=exam, student=student, review_data=review_data)


# --- Admin: Reiniciar Intento de Examen ---
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
    
    logging.info(f"AUDIT LOG: Admin user {current_user.username} reset exam '{exam.title}' attempt for user ID {user_id}.")
    
    flash(f"El intento de examen de '{exam.title}' para el alumno '{student.username}' ha sido reiniciado. Puede presentarlo de nuevo.", "success")
    return redirect(url_for('view_answers', exam_id=exam_id))

# --- Gestión de usuarios (Soft Delete) ---
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))

    session.pop('just_logged_in', None) 
    
    show_inactive = request.args.get('show_inactive', '0') == '1'
    
    query = User.query.order_by(User.username)
    
    # Filtro aplicado de manera sencilla
    if not show_inactive:
            query = query.filter_by(is_active=True) 

    users = query.all()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "student")
        
        # 🔑 AGREGADO: Obtener el campo phone_number 🔑
        phone_number = request.form.get("phone_number")
        
        if not username or not password:
            flash("El nombre de usuario y la contraseña son obligatorios.", "danger")
            return redirect(url_for("manage_users"))
        
        if not re.match(r'^[a-zA-Z0-9_]{3,150}$', username):
            flash("El nombre de usuario debe tener entre 3 y 150 caracteres y solo contener letras, números y '_'.", "danger")
            return redirect(url_for("manage_users"))
        
        # 🔑 AGREGADO: Validación básica del número de teléfono (E.164) 🔑
        if phone_number and not re.match(r'^\+[1-9]\d{7,14}$', phone_number):
            flash("Formato de número de teléfono inválido. Debe incluir el código de país (ej: +52XXXXXXXXXX).", "danger")
            return redirect(url_for("manage_users"))
        
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(
            username=username, 
            password=hashed_password, 
            role=role, 
            is_active=True,
            # 🔑 AGREGADO: Asignar el nuevo campo 🔑
            phone_number=phone_number if phone_number else None
        )
        db.session.add(new_user)
        
        try:
            db.session.commit()
            
            logging.info(f"AUDIT LOG: Admin user {current_user.username} created new user '{username}' ({role}).")

            flash(f"Usuario {username} ({role}) creado exitosamente.", "success")
            
        except IntegrityError:
            db.session.rollback()
            flash(f"❌ Error: El usuario '{username}' ya existe. Por favor, elige otro nombre.", "danger")
        
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error desconocido al crear el usuario: {e}", "danger")


        return redirect(url_for("manage_users"))

    return render_template("manage_users.html", users=users, show_inactive=show_inactive)


@app.route("/admin/users/toggle_status/<int:user_id>", methods=["POST"])
@login_required
def toggle_user_status(user_id):
    if current_user.role != "admin":
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    user_to_toggle = User.query.get_or_404(user_id)
    
    if user_to_toggle.username == "admin":
        flash("No puedes desactivar/eliminar al usuario administrador principal.", "danger")
    else:
        new_status = not user_to_toggle.is_active
        user_to_toggle.is_active = new_status
        db.session.commit()
        
        action = "activado" if new_status else "desactivado"
        
        logging.info(f"AUDIT LOG: Admin user {current_user.username} {action} user '{user_to_toggle.username}' (ID: {user_id}).")
        
        flash(f"✅ Usuario {user_to_toggle.username} ha sido {action}.", "success")
        
        if user_to_toggle.id == current_user.id and not new_status:
             logout_user()
             flash("Tu propia cuenta ha sido desactivada. Debes volver a iniciar sesión.", "warning")
             return redirect(url_for('login'))
        
    return redirect(url_for("manage_users"))


# --- GESTIÓN DE USUARIOS (HARD DELETE) ---
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """
    Elimina permanentemente un usuario del sistema, incluyendo todas sus
    respuestas y datos asociados, basándose en el ID.
    
    Requiere el rol 'admin'.
    """
    # 1. Verificación de Rol
    if current_user.role != 'admin':
        flash('Acceso denegado. Solo administradores pueden eliminar usuarios.', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Usar .get_or_404() para buscar el usuario y manejar el error si no existe
    user = db.session.get(User, user_id)
    
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('manage_users'))

    # 2. Protección del Administrador Principal
    if user.username == 'admin':
        flash('No se puede eliminar el usuario administrador principal.', 'danger')
        return redirect(url_for('manage_users'))
        
    try:
        # 3. Eliminar datos relacionados (CLAVE para evitar errores de Foreign Key)
        
        # Eliminar resultados de exámenes
        ExamResult.query.filter_by(user_id=user_id).delete()
        
        # Eliminar respuestas de preguntas (Answers)
        Answer.query.filter_by(user_id=user_id).delete()
        
        # Eliminar reportes creados por el usuario
        Report.query.filter_by(user_id=user_id).delete()
        
        # Eliminar estados de anuncios leídos
        AnnouncementReadStatus.query.filter_by(user_id=user_id).delete()
        
        # Eliminar sesiones activas de examen
        ActiveExamSession.query.filter_by(user_id=user_id).delete()
        
        # Eliminar logs de violación 
        ViolationLog.query.filter_by(user_id=user_id).delete()
        
        # 4. Eliminar el usuario y confirmar
        db.session.delete(user)
        db.session.commit()
        logging.info(f'AUDIT LOG: Admin {current_user.username} permanently deleted user {user.username} (ID: {user_id}).')
        flash(f'✅ Usuario {user.username} (ID: {user_id}) eliminado permanentemente junto con todos sus datos.', 'success')
        
    except Exception as e:
        db.session.rollback()
        # Muestra el error específico para debug
        logging.error(f'Error al eliminar usuario {user_id}: {e}')
        flash(f'❌ Error crítico al eliminar el usuario: {e}', 'danger')
        
    return redirect(url_for('manage_users'))


# --- Admin: Ver y Gestionar Reportes ---
@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    reports = Report.query.join(User, Report.user_id == User.id).order_by(Report.date_submitted.desc()).all()
    
    return render_template("admin_reports.html", reports=reports)


# --- Admin: Ver Detalle, Responder y Cerrar Reporte ---
@app.route("/admin/reports/<int:report_id>", methods=["GET", "POST"])
@login_required
def view_report_detail(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)

    # Lógica de POST es manejada por las rutas send_report_response y close_report
    if request.method == "POST":
        return redirect(url_for("view_report_detail", report_id=report_id))

    return render_template("report_detail.html", report=report)

# --- Admin: Enviar Respuesta SIN Cerrar ---
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
    
    # Marcamos la fecha de resolución para la notificación del alumno
    mexico_city_tz = pytz.timezone('America/Mexico_City')
    report.date_resolved = datetime.now(mexico_city_tz).replace(tzinfo=None)
    
    db.session.commit()
    flash(f"✅ Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for("view_report_detail", report_id=report_id))


# --- Admin: Cerrar Reporte ---
@app.route("/admin/reports/close/<int:report_id>", methods=["POST"])
@login_required
def close_report(report_id):
    if current_user.role not in ["admin", "ayudante"]:
        flash("Acceso denegado", "danger")
        return redirect(url_for("dashboard"))
    
    report = Report.query.get_or_404(report_id)
    
    if report.status != 'Cerrado':
        report.status = 'Cerrado'
        mexico_city_tz = pytz.timezone('America/Mexico_City')
        report.date_resolved = datetime.now(mexico_city_tz).replace(tzinfo=None)
        db.session.commit()
        flash(f"✅ Reporte #{report_id} marcado como CERRADO.", "success")
    
    return redirect(url_for("admin_reports"))

# --- Admin: Reabrir Reporte ---
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
        flash(f"✅ Reporte #{report_id} REABIERTO correctamente.", "success")
    
    return redirect(url_for("view_report_detail", report_id=report_id))


# --- Admin: Trazabilidad de Lectura de Anuncios ---
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

# 🔑 AGREGADO: RUTA AJAX: Guardar/Actualizar Número de Teléfono del Alumno 🔑
@app.route("/update_phone_number", methods=["POST"])
@login_required
def update_phone_number():
    if current_user.role != "student":
        # Usamos 403 Forbidden para acceso no autorizado
        return jsonify({'success': False, 'message': 'Acceso denegado.'}), 403
    
    # 1. Obtenemos los datos JSON
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
    except Exception:
        return jsonify({'success': False, 'message': 'Datos JSON inválidos.'}), 400

    # 2. Validación de formato básica para Twilio: debe empezar con + y tener 8 a 15 dígitos.
    # El HTML ya hace una pre-validación, pero el servidor es la última defensa.
    if not phone_number or not re.match(r'^\+[1-9]\d{7,14}$', phone_number):
        return jsonify({'success': False, 'message': 'Formato de número inválido. Debe incluir código de país (ej: +52XXXXXXXXXX).'}), 400

    # 3. Guardar el número en la base de datos
    try:
        current_user.phone_number = phone_number
        db.session.commit()
        logging.info(f"AUDIT LOG: User {current_user.username} updated phone number to {phone_number}.")
        return jsonify({'success': True, 'message': 'Número de teléfono guardado correctamente.'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al guardar número de teléfono para user {current_user.username}: {e}")
        # Usamos 500 Internal Server Error para problemas de DB
        return jsonify({'success': False, 'message': 'Error interno al guardar los datos.'}), 500
# ----------------------------------------------------------------------

# --- Alumno: Crear Nuevo Reporte ---
@app.route("/reports/new", methods=["GET", "POST"])
@login_required
def new_report():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        title = request.form["title"]
        request.form.get("content")
        image_filename = None

        if len(title.strip()) == 0 or len(title) > 255:
            flash("El título del reporte es inválido o excede el límite de 255 caracteres.", "danger")
            return redirect(url_for("new_report"))

        if 'image_file' in request.files:
            # Lógica para guardar imagen
            file = request.files['image_file']
            if file.filename:
                image_filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'images')
                os.makedirs(upload_folder, exist_ok=True)
                file.save(os.path.join(upload_folder, image_filename))

        mexico_city_tz = pytz.timezone('America/Mexico_City')
        current_time_mexico = datetime.now(mexico_city_tz).replace(tzinfo=None)

        report = Report(
            title=title,
            content="content", 
            user_id=current_user.id,
            image_filename=image_filename,
            status='Abierto',
            date_submitted=current_time_mexico
        )
        db.session.add(report)
        db.session.commit()

        flash("Reporte enviado correctamente. Pronto el administrador dará una solución.", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_report.html", user=current_user)

# --- Alumno: Ver Historial y Respuestas de Reportes ---
@app.route("/student/reports") 
@login_required
def student_reports():
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    session.pop('just_logged_in', None) 
    
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).all()
    
    # Marcar reportes con respuesta como "visto" en la sesión
    for report in reports:
        if report.admin_response and report.date_resolved:
            session_key = f'report_seen_{report.id}_{report.date_resolved.strftime("%Y%m%d%H%M")}'
            session[session_key] = True 
            
    
    return render_template("student_reports.html", reports=reports)

# --- Alumno: Responder a un Reporte Existente ---
@app.route("/reports/reply/<int:report_id>", methods=["POST"])
@login_required
def reply_to_report(report_id):
    report = Report.query.get_or_404(report_id)

    if report.status == 'Cerrado':
        flash("❌ No puedes responder a un reporte cerrado.", "danger")
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
        
    if report.status == 'En Proceso':
        report.status = 'Abierto'
    
    db.session.commit()
    flash(f"✅ Tu respuesta al Reporte #{report_id} ha sido enviada.", "success")
    return redirect(url_for('student_reports'))


# --- Alumno: Ver Anuncios ---
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

# --- Alumno: Marcar Anuncio como Leído ---
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


# --- Alumno: lista de exámenes (Filtro por horario) ---
@app.route("/exams")
@login_required
def exams_list():
    session.pop('just_logged_in', None) 
    current_time = datetime.utcnow()
    
    # FILTRO CLAVE: Solo mostrar exámenes que cumplen con el horario
    exams = Exam.query.filter(
        (Exam.start_datetime == None) | (Exam.start_datetime <= current_time)
    ).filter(
        (Exam.end_datetime == None) | (Exam.end_datetime >= current_time)
    ).all()
    
    # También pasamos la hora actual al template para que pueda hacer el cálculo
    return render_template("exams.html", exams=exams, current_time=current_time)


# 🔑 RUTA AJAX: Guardado Automático de Respuesta (Auto-Save) 🔑
@app.route("/exam/save_answer", methods=["POST"])
@login_required
def save_answer():
    if current_user.role != "student":
        return jsonify({'status': 'error', 'message': 'Acceso denegado'}), 403
    
    data = request.get_json()
    question_id = data.get('question_id')
    response = data.get('response')
    
    if not question_id or response is None:
        return jsonify({'status': 'error', 'message': 'Faltan datos de pregunta o respuesta.'}), 400

    question = Question.query.get(question_id)
    if not question:
        return jsonify({'status': 'error', 'message': 'Pregunta no encontrada.'}), 404

    # 1. Buscar si ya existe una respuesta para esta pregunta y usuario
    answer = Answer.query.filter_by(
        user_id=current_user.id, 
        question_id=question_id
    ).first()

    # 2. Si existe, actualizar la respuesta
    if answer:
        answer.response = response
        action = 'updated'
    # 3. Si no existe, crear una nueva
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
        return jsonify({'status': 'success', 'message': f'Respuesta {action} para QID {question_id}'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving answer (QID: {question_id}, User: {current_user.username}): {e}")
        return jsonify({'status': 'error', 'message': 'Error interno al guardar la respuesta.'}), 500


# --- Alumno: Tomar Examen (Actualizado para usar Auto-Save) ---
@app.route("/exam/<int:exam_id>/take", methods=["GET", "POST"])
@login_required
def take_exam(exam_id):
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
    
    exam = Exam.query.get_or_404(exam_id)
    current_time = datetime.utcnow()

    # VALIDACIÓN DE TIEMPO DE ACCESO
    if exam.start_datetime and exam.start_datetime > current_time:
        flash("❌ El examen aún no está disponible. Vuelve más tarde.", "danger")
        return redirect(url_for('exams_list'))
    
    if exam.end_datetime and exam.end_datetime < current_time:
        flash("❌ El tiempo para tomar este examen ha expirado.", "danger")
        return redirect(url_for('exams_list'))


    # VERIFICACIÓN CLAVE: Bloquear si ya existe un resultado
    existing_result = ExamResult.query.filter_by(
        user_id=current_user.id, 
        exam_id=exam_id
    ).first()
    
    if existing_result:
        flash("Ya has completado este examen. No se permiten múltiples intentos.", "warning")
        return redirect(url_for('student_exam_detail', exam_id=exam.id)) 


    if request.method == "POST":
        
        session_key = f'exam_start_time_{exam_id}'
        
        # 🔑 LÓGICA DE INICIO DEL CRONÓMETRO Y REGISTRO DE SESIÓN ACTIVA 🔑
        if request.form.get('action') == 'start_timer_now':
            
            # 1. ACTUALIZAR SESIÓN DE FLASK (Cronómetro)
            # Solo guardamos el timestamp si no existe (la primera vez que hace clic).
            if session_key not in session or session.get(session_key) == 0:
                session[session_key] = int(datetime.utcnow().timestamp()) 
            
            # 2. CREAR/ACTUALIZAR REGISTRO DE MONITOREO EN DB
            try:
                active_session = ActiveExamSession.query.filter_by(
                    user_id=current_user.id,
                    exam_id=exam_id
                ).first()

                if not active_session:
                    # 2a. Si no existe, creamos la sesión (registro de monitoreo)
                    new_session = ActiveExamSession(
                        user_id=current_user.id,
                        exam_id=exam_id,
                        start_time=datetime.utcnow()
                    )
                    db.session.add(new_session)
                    db.session.commit()
                # Si ya existe (lo cual es normal si recarga la página), no hacemos nada
                
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error al registrar sesión ACTIVA (start_timer_now) para user {current_user.id}: {e}")
                
            return '', 204 
            
        
        # 🔑 LÓGICA DE ENVÍO Y CALIFICACIÓN FINAL (POST del formulario) 🔑
        session.pop(session_key, None) 
        
        total_score_sum = 0.0 
        
        # Recuperar las respuestas guardadas por el Auto-Save
        final_answers = Answer.query.join(Question).filter(
            Answer.user_id == current_user.id,
            Question.exam_id == exam_id
        ).all()
        
        if not final_answers:
            flash("Error: No se encontraron respuestas para calificar. Asegúrate de haber respondido al menos una pregunta.", "danger")
            return redirect(url_for('exams_list'))
        
        for answer in final_answers:
            question = Question.query.get(answer.question_id)
            
            grade = 0.0
            feedback_text = None
            
            if answer.response:
                # LÓGICA DE CALIFICACIÓN AUTOMÁTICA
                if question.correct_option:
                    
                    if answer.response == question.correct_option:
                        grade = 1.0
                        total_score_sum += 1.0
                        feedback_text = "¡Correcto!" 
                    else:
                        grade = 0.0
                        feedback_text = f"Incorrecto. La respuesta correcta era la opción {question.correct_option}."
                        
                else:
                    grade = None
                    
                # Actualizar la calificación en el registro de respuesta
                answer.grade = grade
                answer.feedback = feedback_text
        
        # GUARDAR EL RESULTADO FINAL DEL EXAMEN
        current_time_utc = datetime.now(pytz.utc)

        result = ExamResult(
            user_id=current_user.id, 
            exam_id=exam_id, 
            score=total_score_sum, 
            date_taken=current_time_utc
        )
        db.session.add(result)
        
        # 3. Eliminación de la sesión activa al finalizar el examen
        active_session = ActiveExamSession.query.filter_by(
            user_id=current_user.id,
            exam_id=exam_id
        ).first()

        if active_session:
            db.session.delete(active_session)
        
        # Un solo commit para guardar resultados y eliminar la sesión de monitoreo
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error al finalizar y registrar resultado para user {current_user.id}: {e}")
            flash("Error al registrar el resultado final. Inténtalo de nuevo.", "danger")
            return redirect(url_for('exams_list'))

        flash("✅ Examen finalizado y calificado correctamente. Revisa tu reporte.", "success")
        return redirect(url_for('student_exam_detail', exam_id=exam.id))


    if request.method == "GET":
        session.pop('just_logged_in', None) 
        
        session_key = f'exam_start_time_{exam_id}'
        start_time = session.get(session_key, 0)
        
        # Obtener respuestas guardadas previamente para precargar el formulario
        saved_answers = Answer.query.filter_by(user_id=current_user.id).join(
            Question, Answer.question_id == Question.id
        ).filter(
            Question.exam_id == exam_id
        ).all()
        
        saved_answers_dict = {a.question_id: a.response for a in saved_answers}
        
        # Obtenemos el tiempo extra del modelo
        active_session = ActiveExamSession.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
        time_added_sec = active_session.time_added_sec if active_session else 0

        return render_template(
            "take_exam.html", 
            exam=exam,
            start_time_utc=start_time,
            saved_answers=saved_answers_dict, 
            time_added_sec=time_added_sec 
        )


# --- Alumno: historial de resultados (Tabla de Historial) ---
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


# --- Alumno: ver respuestas detalladas y feedback (Detalle Pregunta por Pregunta) ---
@app.route("/student/exam/<int:exam_id>/detail")
@login_required
def student_exam_detail(exam_id):
    if current_user.role != "student":
        flash("Acceso denegado", "danger")
        return redirect(url_for("admin_panel"))
        
    session.pop('just_logged_in', None) 
    
    exam = Exam.query.get_or_404(exam_id)
    
    answers = Answer.query.join(Question).filter(
        Answer.user_id == current_user.id,
        Question.exam_id == exam_id
    ).all()
    
    answers_dict = {a.question_id: a for a in answers}
    
    return render_template("student_exam_detail.html", exam=exam, answers_dict=answers_dict)


# ======================================================================
# --- INICIALIZACIÓN DE LA APLICACIÓN ---
# ======================================================================

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    # Esto solo se ejecuta cuando se llama directamente a python app.py (i.e., localmente)
    # En Render, se usa el Procfile para ejecutar Gunicorn, que llama directamente al objeto 'app'.
    # 🔑 CORRECCIÓN CLAVE: Usamos socketio.run solo para el desarrollo local.
    # En Render, la línea del Procfile llamará a gunicorn directamente.
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
