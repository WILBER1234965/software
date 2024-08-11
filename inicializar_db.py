from app import db, app, User
from werkzeug.security import generate_password_hash

# Configura el contexto de la aplicación
with app.app_context():
    # Verificar si ya existe un superadministrador con el correo especificado
    email = 'wilberin53@gmail.com'
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        print(f"El usuario con el correo {email} ya existe.")
    else:
        # Crear y añadir un nuevo superadministrador
        password = 'wcy9521721WCY.'
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_superadmin = User(email=email, password=hashed_password, is_superadmin=True)
        db.session.add(new_superadmin)
        db.session.commit()

        print(f"Superadministrador creado: {email}")
