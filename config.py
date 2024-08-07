import os

class Config:
    SECRET_KEY = '8S2cd12ya3d1ofd6f1cec5Sbb02afe2cbd8c6ff1f'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///productos.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuración de correo electrónico
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'wilberin53@gmail.com'
    MAIL_PASSWORD = 'pefj psze okfx akcl'
    MAIL_DEFAULT_SENDER = 'wilberin53@gmail.com'

    # Configuración para la subida de archivos
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
