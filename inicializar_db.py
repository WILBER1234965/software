from app import db, app, User
from werkzeug.security import generate_password_hash

# Configura el contexto de la aplicación
with app.app_context():
    # Eliminar todas las tablas existentes
    db.drop_all()
    
    # Crear todas las tablas con la estructura actual del modelo
    db.create_all()
    
    # Crear un nuevo usuario
    email = 'wilberin53@gmail.com'
    password = 'wcy9521721WCY.'
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Añadir y guardar el nuevo usuario
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
