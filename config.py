class Config:
    SECRET_KEY = b'8S2\xcd\x12y\xa3\xd1o\xd6\xf1c\xec\xd5S\xbb\x02\xaf\xe2\xcb\xd8\xc6\xff\x1f'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///productos.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuración de correo electrónico
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'wilberin53@gmail.com'
    MAIL_PASSWORD = 'pefj psze okfx akcl'
    MAIL_DEFAULT_SENDER = 'wilberin53@gmail.com'  # Añade esta línea
