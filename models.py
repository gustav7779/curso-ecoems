from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Inicializar la base de datos
db = SQLAlchemy()

# Modelo de usuarios
class User(db.Model):
    __tablename__ = 'user'   # 👈 si en tu app usaste 'users', cambia esto también en todo
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin o alumno

    # Relación con respuestas y resultados
    answers = db.relationship('Answer', backref='user', lazy=True)
    results = db.relationship('ExamResult', backref='user', lazy=True)


# Modelo de exámenes
class Exam(db.Model):
    __tablename__ = 'exam'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    questions = db.relationship('Question', backref='exam', lazy=True)
    results = db.relationship('ExamResult', backref='exam', lazy=True)


# Modelo de preguntas
class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    answers = db.relationship('Answer', backref='question', lazy=True)
    image_a = db.Column(db.String(200), nullable=True)
    image_b = db.Column(db.String(200), nullable=True)
    image_c = db.Column(db.String(200), nullable=True)
    image_d = db.Column(db.String(200), nullable=True)


# Modelo de respuestas
class Answer(db.Model):
    __tablename__ = 'answer'
    id = db.Column(db.Integer, primary_key=True)
    response = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    grade = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.String(300), nullable=True)


# 📝 Modelo para historial de exámenes (nuevo)
class ExamResult(db.Model):
    __tablename__ = 'exam_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)
