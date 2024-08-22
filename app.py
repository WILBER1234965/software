from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
from flask_migrate import Migrate  # Importa Migrate
from functools import wraps
import os
from datetime import datetime
import random
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO
from flask import send_file


# Inicialización de la aplicación
app = Flask(__name__)
app.config.from_object('config.Config')

# Inicialización de extensiones
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Inicializa Migrate después de SQLAlchemy
mail = Mail(app)

# El resto de tu código...


# Decorador para requerir superadministrador
def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or not user.is_superadmin:
            flash('Acceso denegado. Privilegios de superadministrador requeridos.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Asegurarse de que la carpeta de subida exista
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Función para verificar si la extensión del archivo es permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Función para enviar el correo de verificación
def send_verification_email(user):
    verification_code = ''.join(random.choices('0123456789', k=6))
    user.verification_code = verification_code
    user.verification_code_sent_at = datetime.utcnow()  # Guardar la hora de envío del código
    db.session.commit()
    
    msg = Message('Código de Verificación', recipients=[user.email])
    msg.body = f'Hola {user.full_name},\n\nTu código de verificación es: {verification_code}\n\nPor favor, ingrésalo en la página para completar tu registro.'
    mail.send(msg)

# Modelos de la base de datos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    full_name = db.Column(db.String(150), nullable=True, default="Administrador")
    bio = db.Column(db.Text, nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True, default="default_profile.png")

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

# Modelos de la base de datos
class RegularUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True, default="default_profile.png")
    bio = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_sent_at = db.Column(db.DateTime, nullable=True)  # Hora en que se envió el código
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return RegularUser.query.get(user_id)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


@app.route('/download_links/<int:product_id>')
def download_links(product_id):
    product = Product.query.get_or_404(product_id)
    download_links = DownloadLink.query.filter_by(product_id=product_id).all()
    return render_template('download_links.html', product=product, download_links=download_links)


class DownloadLink(db.Model):
    __tablename__ = 'download_link'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    download_count = db.Column(db.Integer, default=0)  # Contador de descargas

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    product_type = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relaciones
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    user = db.relationship('User', backref=db.backref('products', lazy=True))
    download_links = db.relationship('DownloadLink', backref='product', lazy=True)

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir login de usuario regular
def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            flash('Debes iniciar sesión para acceder a esta función.', 'warning')
            return redirect(url_for('login_user'))
        return f(*args, **kwargs)
    return decorated_function

# Rutas de la aplicación
@app.route('/')
@app.route('/category/<int:category_id>')
def index(category_id=None):
    categories = Category.query.all()
    if category_id:
        products = Product.query.filter_by(category_id=category_id).all()
    else:
        products = Product.query.all()

    user = None
    if 'user_id' in session and session.get('user_type') == 'regular':
        user = RegularUser.query.get(session['user_id'])

    return render_template('index.html', products=products, categories=categories, user=user)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    comments = Comment.query.filter_by(product_id=product_id).all()

    # Crear el diccionario de admin_emails
    admin_users = User.query.all()
    admin_emails = {admin.email: admin for admin in admin_users}

    user = None
    if 'user_id' in session and session.get('user_type') == 'regular':
        user = RegularUser.query.get(session['user_id'])

    return render_template('product_detail.html', product=product, categories=categories, comments=comments, user=user, admin_emails=admin_emails)

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_type'] = 'admin'
            next_page = session.pop('next', None)
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Credenciales incorrectas.', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            msg = Message('Restablece tu contraseña',
                          recipients=[email])
            msg.body = f'''Para restablecer tu contraseña, haz clic en el siguiente enlace:
{url_for('reset_password', token=token, _external=True)}

Si no solicitaste este correo, simplemente ignóralo y no se realizarán cambios.
'''
            mail.send(msg)
            flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'info')
            return redirect(url_for('login'))
        else:
            flash('El correo electrónico ingresado no está registrado.', 'warning')
    return render_template('admin/forgot_password.html')

@app.route('/admin/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('El token es inválido o ha expirado', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()
        flash('Tu contraseña ha sido actualizada. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('admin/reset_password.html', token=token)

@app.route('/admin/dashboard')
@login_required
def dashboard():
    user = User.query.get(session.get('user_id'))
    
    if not user:
        flash('Usuario no encontrado. Por favor, inicia sesión nuevamente.', 'danger')
        return redirect(url_for('login'))
    
    if user.is_superadmin:
        products = Product.query.all()
        for product in products:
            # Calcular el total de descargas para el producto
            product.total_downloads = sum(link.download_count for link in product.download_links)
        admins = User.query.filter_by(is_superadmin=False).all()
        return render_template('admin/dashboard.html', products=products, admins=admins, admin=user, is_superadmin=True)
    else:
        products = Product.query.filter_by(user_id=user.id).all()
        for product in products:
            # Calcular el total de descargas para el producto
            product.total_downloads = sum(link.download_count for link in product.download_links)
        return render_template('admin/dashboard.html', products=products, admin=user, is_superadmin=False)


@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    user = User.query.get(session['user_id'])
    categories = Category.query.all()
    selected_category = request.args.get('selected_category', None)
    
    if request.method == 'POST':
        title = request.form['title']
        short_description = request.form['short_description']
        full_description = request.form['full_description']
        category_id = request.form['category_id']
        
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('uploaded_file', filename=filename)
        else:
            image_url = ''

        product_type = request.form['product_type']
        
        new_product = Product(
            title=title, 
            short_description=short_description, 
            full_description=full_description,
            image_url=image_url, 
            product_type=product_type, 
            category_id=category_id,
            user_id=user.id
        )
        db.session.add(new_product)
        db.session.commit()
        
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=new_product.id)
                db.session.add(new_link)
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/add_product.html', categories=categories, is_superadmin=user.is_superadmin, selected_category=selected_category, admin=user)

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    if request.method == 'POST':
        product.title = request.form['title']
        product.short_description = request.form['short_description']
        product.full_description = request.form['full_description']
        product.category_id = request.form['category_id']
        
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product.image_url = url_for('uploaded_file', filename=filename)

        product.product_type = request.form['product_type']
        
        DownloadLink.query.filter_by(product_id=product.id).delete()
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=product.id)
                db.session.add(new_link)

        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_product.html', product=product, categories=categories, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    Comment.query.filter_by(product_id=product.id).delete()
    
    DownloadLink.query.filter_by(product_id=product.id).delete()
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Producto, sus enlaces de descarga y comentarios asociados han sido eliminados exitosamente.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/add_category', methods=['POST'])
@login_required
@superadmin_required
def add_category():
    category_name = request.form['category_name']
    existing_category = Category.query.filter_by(name=category_name).first()

    if existing_category:
        flash('La categoría ya existe.', 'danger')
    else:
        if category_name:
            new_category = Category(name=category_name)
            db.session.add(new_category)
            db.session.commit()
            flash('Categoría creada exitosamente', 'success')
            return redirect(url_for('add_product', selected_category=new_category.id))
        else:
            flash('El nombre de la categoría no puede estar vacío', 'danger')
    
    return redirect(url_for('add_product'))

@app.route('/admin/manage_categories', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_categories():
    if request.method == 'POST':
        category_name = request.form['name']
        existing_category = Category.query.filter_by(name=category_name).first()

        if existing_category:
            flash('La categoría ya existe.', 'danger')
        else:
            if category_name:
                new_category = Category(name=category_name)
                db.session.add(new_category)
                db.session.commit()
                flash('Categoría creada exitosamente.', 'success')
            else:
                flash('El nombre de la categoría no puede estar vacío.', 'danger')
    
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories, is_superadmin=True, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_category/<int:category_id>')
@login_required
@superadmin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.products:
        flash('No se puede eliminar una categoría que tiene productos asociados.', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Categoría eliminada exitosamente.', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/manage_admins', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_admins():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        existing_admin = User.query.filter_by(email=email).first()

        if existing_admin:
            flash('El usuario ya existe.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_admin = User(email=email, password=hashed_password, is_superadmin=False)
            db.session.add(new_admin)
            db.session.commit()
            flash('Administrador añadido exitosamente.', 'success')
        return redirect(url_for('manage_admins'))

    admins = User.query.filter_by(is_superadmin=False).all()
    return render_template('admin/manage_admins.html', admins=admins, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_admin(admin_id):
    admin = User.query.get_or_404(admin_id)
    if admin.is_superadmin:
        flash('No puedes eliminar al superadministrador.', 'danger')
    else:
        db.session.delete(admin)
        db.session.commit()
        flash('Administrador eliminado exitosamente.', 'success')
    return redirect(url_for('manage_admins'))

@app.route('/admin/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_type', None)
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name']

        # Validación de campos vacíos
        if not email or not password or not confirm_password or not full_name:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Todos los campos son obligatorios.')

        # Validación de formato de email
        if "@" not in email or "." not in email:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Por favor ingrese un correo electrónico válido.')

        # Validación de longitud de la contraseña
        if len(password) < 6:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='La contraseña debe tener al menos 6 caracteres.')

        # Validación de coincidencia de contraseñas
        if password != confirm_password:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Las contraseñas no coinciden.')

        # Verificación de si el correo ya está registrado
        existing_user = RegularUser.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.email_verified:
                session['user_id'] = existing_user.id  # Guardar el ID del usuario en sesión para verificar después
                flash('Este correo ya está registrado, pero no ha sido verificado. Por favor verifica tu correo.', 'warning')
                return redirect(url_for('verify_email'))
            return render_template('register_user.html', alert_type='error', alert_title='Error', alert_message='El correo electrónico ya está registrado.')

        # Crear un nuevo usuario pero no confirmarlo hasta que verifique el correo
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = RegularUser(email=email, password=hashed_password, full_name=full_name)
        db.session.add(new_user)
        db.session.commit()

        # Guardar ID del usuario en la sesión
        session['user_id'] = new_user.id

        # Enviar código de verificación
        send_verification_email(new_user)

        return redirect(url_for('verify_email'))

    return render_template('register_user.html')




@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        regular_user = RegularUser.query.filter_by(email=email).first()

        if regular_user and check_password_hash(regular_user.password, password):
            if not regular_user.email_verified:
                flash('Debes verificar tu correo electrónico antes de iniciar sesión.', 'warning')
                return redirect(url_for('verify_email', user_id=regular_user.id))
            session['user_id'] = regular_user.id
            session['user_type'] = 'regular'
            return redirect(url_for('index'))
        else:
            return render_template('login_user.html', alert_type='error', alert_title='Error', alert_message='Correo electrónico o contraseña incorrectos.')
    return render_template('login_user.html')



@app.route('/logout_user')
def logout_user():
    session.pop('user_id', None)
    session.pop('user_type', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('index'))

# Ruta para servir archivos subidos
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/search')
def search():
    query = request.args.get('query')
    category_id = request.args.get('category')
    
    # Inicializa la consulta de productos
    products = Product.query
    
    # Si hay una consulta de búsqueda
    if query:
        products = products.filter(
            Product.title.contains(query)
        )
        
        # Si no se encuentran productos por título, buscar por descripción
        if not products.all():
            products = Product.query.filter(
                Product.short_description.contains(query) | 
                Product.full_description.contains(query)
            )
    
    # Filtrar por categoría si se especifica
    if category_id:
        products = products.filter_by(category_id=category_id)

    products = products.all()
    
    # Si no se encuentran productos, mostrar todos y lanzar un aviso
    if not products:
        products = Product.query.all()
        flash('No se encontraron resultados exactos para tu búsqueda, pero aquí tienes otros productos que podrían interesarte.', 'warning')
    
    categories = Category.query.all()
    
    return render_template('index.html', products=products, categories=categories)


@app.route('/purchase/<int:product_id>', methods=['GET'])
@user_login_required
def purchase_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('purchase.html', product=product)

@app.route('/download/<int:link_id>')
@user_login_required
def download(link_id):
    download_link = DownloadLink.query.get_or_404(link_id)
    download_link.download_count += 1  # Incrementar el contador de descargas del enlace
    db.session.commit()
    return redirect(download_link.url)  # Redirige al enlace de descarga

@app.route('/edit_profile_user', methods=['GET', 'POST'])
@user_login_required
def edit_profile_user():
    user = RegularUser.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        if not check_password_hash(user.password, current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
            return redirect(url_for('edit_profile_user'))

        user.full_name = request.form['full_name']

        new_password = request.form['new_password']
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        db.session.commit()
        flash('Perfil actualizado con éxito.', 'success')
        return redirect(url_for('index'))

    return render_template('edit_profile_user.html', user=user)

@app.route('/admin/edit_profile_admin', methods=['GET', 'POST'])
@login_required
def edit_profile_admin():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_picture = filename
                db.session.commit()
                flash('Foto de perfil actualizada con éxito.', 'success')
                return redirect(url_for('edit_profile_admin'))

        else:
            user.full_name = request.form['full_name']
            user.bio = request.form['bio']
            user.contact_number = request.form['contact_number']
            db.session.commit()
            flash('Perfil actualizado con éxito.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('edit_profile_admin.html', user=user, admin=user)

@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    
    if user_id:
        if user_type == 'admin':
            admin = User.query.get(user_id)
            if admin:
                return {'admin': admin}
        elif user_type == 'regular':
            user = RegularUser.query.get(user_id)
            if user:
                return {'user': user}
    return {}

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_profile_picture = db.Column(db.String(200), nullable=True, default='default_user.png')

    product = db.relationship('Product', backref=db.backref('comments', lazy=True))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)

@app.route('/product/<int:product_id>/comment', methods=['POST'])
@user_login_required
def add_comment(product_id):
    parent_id = request.form.get('parent_id', None)
    comment_text = request.form['comment_text']
    
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    user = None

    if user_type == 'admin':
        user = User.query.get(user_id)
    elif user_type == 'regular':
        user = RegularUser.query.get(user_id)
    
    if user:
        name = user.full_name or "Usuario"
        email = user.email
        profile_picture = user.profile_picture if hasattr(user, 'profile_picture') else "default_user.png"
    else:
        name = "JHON"
        email = "default@default.com"
        profile_picture = "default_user.png"

    new_comment = Comment(
        name=name,
        email=email,
        comment_text=comment_text,
        product_id=product_id,
        parent_id=parent_id if parent_id else None,
        user_profile_picture=profile_picture
    )

    db.session.add(new_comment)
    db.session.commit()

    flash('Comentario añadido con éxito.', 'success')

    # Verificar el tipo de usuario y redirigir apropiadamente
    if user_type == 'admin':
        # Redirigir de vuelta al panel de comentarios del administrador
        return redirect(url_for('view_comments', product_id=product_id))
    else:
        # Redirigir al detalle del producto como usuario regular
        return redirect(url_for('product_detail', product_id=product_id))


@app.route('/admin/view_comments/<int:product_id>', methods=['GET'])
@login_required
@superadmin_required
def view_comments(product_id):
    product = Product.query.get_or_404(product_id)
    comments = Comment.query.filter_by(product_id=product_id).all()
    
    admin = User.query.get(session.get('user_id'))  # Obtener el usuario administrador actual
    
    return render_template('admin/view_comments.html', product=product, comments=comments, admin=admin)

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comentario eliminado exitosamente.', 'success')
    return redirect(request.referrer)


@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_users():
    # Obtener todos los usuarios registrados
    users = RegularUser.query.all()
    
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_user(user_id):
    user = RegularUser.query.get_or_404(user_id)
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Usuario eliminado exitosamente.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin/add_user', methods=['POST'])
@superadmin_required
def add_user():
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']

    # Verificar si el correo ya está registrado
    if RegularUser.query.filter_by(email=email).first():
        flash('El correo electrónico ya está registrado. Por favor, usa uno diferente.', 'danger')
        return redirect(url_for('manage_users'))

    # Crear el nuevo usuario
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = RegularUser(full_name=full_name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Usuario añadido exitosamente.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('user_id')  # Obtén el ID de usuario desde la sesión
    if not user_id:
        flash('No hay usuario en sesión para verificar.', 'danger')
        return redirect(url_for('register'))
    
    user = RegularUser.query.get_or_404(user_id)  # Obtén el usuario desde la base de datos
    
    seconds_remaining = 0
    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        total_seconds = elapsed_time.total_seconds()
        seconds_remaining = max(0, 120 - int(total_seconds))  # 120 segundos = 2 minutos

    if request.method == 'POST':
        verification_code = request.form['verification_code']

        if verification_code == user.verification_code:
            user.email_verified = True
            user.verification_code = None  # Limpia el código de verificación
            db.session.commit()

            # Limpiar la sesión
            session.pop('verification_code', None)

            flash('Correo electrónico verificado exitosamente. Ahora estás autenticado.', 'success')

            # Autenticar automáticamente al usuario
            session['user_id'] = user.id
            session['user_type'] = 'regular'

            return redirect(url_for('index'))
        else:
            flash('Código de verificación incorrecto. Por favor, intenta nuevamente.', 'danger')
    
    return render_template('verify_email.html', user=user, seconds_remaining=seconds_remaining)

@app.route('/resend_verification_code', methods=['GET'])
def resend_verification_code():
    user_id = session.get('user_id')
    if not user_id:
        flash('No hay usuario en sesión para verificar.', 'danger')
        return redirect(url_for('register'))
    
    user = RegularUser.query.get_or_404(user_id)

    # Calcular el tiempo desde que se envió el último código
    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        if elapsed_time < timedelta(minutes=2):
            flash('Debes esperar al menos 2 minutos antes de solicitar un nuevo código.', 'warning')
            return redirect(url_for('verify_email'))

    send_verification_email(user)
    flash('Se ha reenviado un nuevo código de verificación a tu correo electrónico.', 'success')
    return redirect(url_for('verify_email'))


@app.route('/admin/export_products_json', methods=['GET'])
@login_required
@superadmin_required
def export_products_json():
    products = Product.query.all()
    products_data = []

    for product in products:
        product_data = {
            'id': product.id,
            'title': product.title,
            'short_description': product.short_description,
            'full_description': product.full_description,
            'product_type': product.product_type,
            'category_id': product.category_id,
            'user_id': product.user_id,
            'download_links': [{'title': link.title, 'url': link.url} for link in product.download_links]
        }
        products_data.append(product_data)

    # Escribir los datos a un archivo JSON
    export_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'products_export.json')
    with open(export_file_path, 'w', encoding='utf-8') as f:
        json.dump(products_data, f, ensure_ascii=False, indent=4)

    return send_from_directory(directory=app.config['UPLOAD_FOLDER'], path='products_export.json', as_attachment=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
from flask_migrate import Migrate  # Importa Migrate
from functools import wraps
import os
from datetime import datetime
import random
from datetime import datetime, timedelta
import json


# Inicialización de la aplicación
app = Flask(__name__)
app.config.from_object('config.Config')

# Inicialización de extensiones
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Inicializa Migrate después de SQLAlchemy
mail = Mail(app)

# El resto de tu código...


# Decorador para requerir superadministrador
def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or not user.is_superadmin:
            flash('Acceso denegado. Privilegios de superadministrador requeridos.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Asegurarse de que la carpeta de subida exista
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Función para verificar si la extensión del archivo es permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Función para enviar el correo de verificación
def send_verification_email(user):
    verification_code = ''.join(random.choices('0123456789', k=6))
    user.verification_code = verification_code
    user.verification_code_sent_at = datetime.utcnow()  # Guardar la hora de envío del código
    db.session.commit()
    
    msg = Message('Código de Verificación', recipients=[user.email])
    msg.body = f'Hola {user.full_name},\n\nTu código de verificación es: {verification_code}\n\nPor favor, ingrésalo en la página para completar tu registro.'
    mail.send(msg)

# Modelos de la base de datos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    full_name = db.Column(db.String(150), nullable=True, default="Administrador")
    bio = db.Column(db.Text, nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True, default="default_profile.png")

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

# Modelos de la base de datos
class RegularUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True, default="default_profile.png")
    bio = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_sent_at = db.Column(db.DateTime, nullable=True)  # Hora en que se envió el código
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return RegularUser.query.get(user_id)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


@app.route('/download_links/<int:product_id>')
def download_links(product_id):
    product = Product.query.get_or_404(product_id)
    download_links = DownloadLink.query.filter_by(product_id=product_id).all()
    return render_template('download_links.html', product=product, download_links=download_links)


class DownloadLink(db.Model):
    __tablename__ = 'download_link'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    download_count = db.Column(db.Integer, default=0)  # Contador de descargas

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    product_type = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relaciones
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    user = db.relationship('User', backref=db.backref('products', lazy=True))
    download_links = db.relationship('DownloadLink', backref='product', lazy=True)

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir login de usuario regular
def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            flash('Debes iniciar sesión para acceder a esta función.', 'warning')
            return redirect(url_for('login_user'))
        return f(*args, **kwargs)
    return decorated_function

# Rutas de la aplicación
@app.route('/')
@app.route('/category/<int:category_id>')
def index(category_id=None):
    query = request.args.get('query')  # Obtener la consulta de búsqueda
    categories = Category.query.all()

    # Filtrar productos por categoría o mostrar todos los productos si no hay categoría seleccionada
    if category_id:
        products = Product.query.filter_by(category_id=category_id)
    else:
        products = Product.query

    # Si hay una consulta de búsqueda, filtrar productos por título, descripción corta o descripción completa
    if query:
        products = products.filter(
            (Product.title.ilike(f'%{query}%')) |
            (Product.short_description.ilike(f'%{query}%')) |
            (Product.full_description.ilike(f'%{query}%'))
        )
    
    # Ejecutar la consulta y obtener todos los productos filtrados
    products = products.all()

    # Si no se encuentran productos, mostrar todos los productos y un mensaje de advertencia
    if not products:
        flash('No se encontraron productos que coincidan con tu búsqueda, pero aquí tienes otros que podrían interesarte.', 'warning')
        products = Product.query.all()

    user = None
    if 'user_id' in session and session.get('user_type') == 'regular':
        user = RegularUser.query.get(session['user_id'])

    return render_template('index.html', products=products, categories=categories, user=user)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    comments = Comment.query.filter_by(product_id=product_id).all()

    # Crear el diccionario de admin_emails
    admin_users = User.query.all()
    admin_emails = {admin.email: admin for admin in admin_users}

    user = None
    if 'user_id' in session and session.get('user_type') == 'regular':
        user = RegularUser.query.get(session['user_id'])

    return render_template('product_detail.html', product=product, categories=categories, comments=comments, user=user, admin_emails=admin_emails)

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_type'] = 'admin'
            next_page = session.pop('next', None)
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Credenciales incorrectas.', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            msg = Message('Restablece tu contraseña',
                          recipients=[email])
            msg.body = f'''Para restablecer tu contraseña, haz clic en el siguiente enlace:
{url_for('reset_password', token=token, _external=True)}

Si no solicitaste este correo, simplemente ignóralo y no se realizarán cambios.
'''
            mail.send(msg)
            flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'info')
            return redirect(url_for('login'))
        else:
            flash('El correo electrónico ingresado no está registrado.', 'warning')
    return render_template('admin/forgot_password.html')

@app.route('/admin/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('El token es inválido o ha expirado', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()
        flash('Tu contraseña ha sido actualizada. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('admin/reset_password.html', token=token)

@app.route('/admin/dashboard')
@login_required
def dashboard():
    user = User.query.get(session.get('user_id'))
    
    if not user:
        flash('Usuario no encontrado. Por favor, inicia sesión nuevamente.', 'danger')
        return redirect(url_for('login'))
    
    if user.is_superadmin:
        products = Product.query.all()
        for product in products:
            # Calcular el total de descargas para el producto
            product.total_downloads = sum(link.download_count for link in product.download_links)
        admins = User.query.filter_by(is_superadmin=False).all()
        return render_template('admin/dashboard.html', products=products, admins=admins, admin=user, is_superadmin=True)
    else:
        products = Product.query.filter_by(user_id=user.id).all()
        for product in products:
            # Calcular el total de descargas para el producto
            product.total_downloads = sum(link.download_count for link in product.download_links)
        return render_template('admin/dashboard.html', products=products, admin=user, is_superadmin=False)


@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    user = User.query.get(session['user_id'])
    categories = Category.query.all()
    selected_category = request.args.get('selected_category', None)
    
    if request.method == 'POST':
        title = request.form['title']
        short_description = request.form['short_description']
        full_description = request.form['full_description']
        category_id = request.form['category_id']
        
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('uploaded_file', filename=filename)
        else:
            image_url = ''

        product_type = request.form['product_type']
        
        new_product = Product(
            title=title, 
            short_description=short_description, 
            full_description=full_description,
            image_url=image_url, 
            product_type=product_type, 
            category_id=category_id,
            user_id=user.id
        )
        db.session.add(new_product)
        db.session.commit()
        
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=new_product.id)
                db.session.add(new_link)
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/add_product.html', categories=categories, is_superadmin=user.is_superadmin, selected_category=selected_category, admin=user)

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    if request.method == 'POST':
        product.title = request.form['title']
        product.short_description = request.form['short_description']
        product.full_description = request.form['full_description']
        product.category_id = request.form['category_id']
        
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product.image_url = url_for('uploaded_file', filename=filename)

        product.product_type = request.form['product_type']
        
        DownloadLink.query.filter_by(product_id=product.id).delete()
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=product.id)
                db.session.add(new_link)

        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_product.html', product=product, categories=categories, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    Comment.query.filter_by(product_id=product.id).delete()
    
    DownloadLink.query.filter_by(product_id=product.id).delete()
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Producto, sus enlaces de descarga y comentarios asociados han sido eliminados exitosamente.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/add_category', methods=['POST'])
@login_required
@superadmin_required
def add_category():
    category_name = request.form['category_name']
    existing_category = Category.query.filter_by(name=category_name).first()

    if existing_category:
        flash('La categoría ya existe.', 'danger')
    else:
        if category_name:
            new_category = Category(name=category_name)
            db.session.add(new_category)
            db.session.commit()
            flash('Categoría creada exitosamente', 'success')
            return redirect(url_for('add_product', selected_category=new_category.id))
        else:
            flash('El nombre de la categoría no puede estar vacío', 'danger')
    
    return redirect(url_for('add_product'))

@app.route('/admin/manage_categories', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_categories():
    if request.method == 'POST':
        category_name = request.form['name']
        existing_category = Category.query.filter_by(name=category_name).first()

        if existing_category:
            flash('La categoría ya existe.', 'danger')
        else:
            if category_name:
                new_category = Category(name=category_name)
                db.session.add(new_category)
                db.session.commit()
                flash('Categoría creada exitosamente.', 'success')
            else:
                flash('El nombre de la categoría no puede estar vacío.', 'danger')
    
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories, is_superadmin=True, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_category/<int:category_id>')
@login_required
@superadmin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.products:
        flash('No se puede eliminar una categoría que tiene productos asociados.', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Categoría eliminada exitosamente.', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/manage_admins', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_admins():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        existing_admin = User.query.filter_by(email=email).first()

        if existing_admin:
            flash('El usuario ya existe.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_admin = User(email=email, password=hashed_password, is_superadmin=False)
            db.session.add(new_admin)
            db.session.commit()
            flash('Administrador añadido exitosamente.', 'success')
        return redirect(url_for('manage_admins'))

    admins = User.query.filter_by(is_superadmin=False).all()
    return render_template('admin/manage_admins.html', admins=admins, admin=User.query.get(session['user_id']))

@app.route('/admin/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_admin(admin_id):
    admin = User.query.get_or_404(admin_id)
    if admin.is_superadmin:
        flash('No puedes eliminar al superadministrador.', 'danger')
    else:
        db.session.delete(admin)
        db.session.commit()
        flash('Administrador eliminado exitosamente.', 'success')
    return redirect(url_for('manage_admins'))

@app.route('/admin/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_type', None)
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name']

        # Validación de campos vacíos
        if not email or not password or not confirm_password or not full_name:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Todos los campos son obligatorios.')

        # Validación de formato de email
        if "@" not in email or "." not in email:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Por favor ingrese un correo electrónico válido.')

        # Validación de longitud de la contraseña
        if len(password) < 6:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='La contraseña debe tener al menos 6 caracteres.')

        # Validación de coincidencia de contraseñas
        if password != confirm_password:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Las contraseñas no coinciden.')

        # Verificación de si el correo ya está registrado
        existing_user = RegularUser.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.email_verified:
                session['user_id'] = existing_user.id  # Guardar el ID del usuario en sesión para verificar después
                flash('Este correo ya está registrado, pero no ha sido verificado. Por favor verifica tu correo.', 'warning')
                return redirect(url_for('verify_email'))
            return render_template('register_user.html', alert_type='error', alert_title='Error', alert_message='El correo electrónico ya está registrado.')

        # Crear un nuevo usuario pero no confirmarlo hasta que verifique el correo
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = RegularUser(email=email, password=hashed_password, full_name=full_name)
        db.session.add(new_user)
        db.session.commit()

        # Guardar ID del usuario en la sesión
        session['user_id'] = new_user.id

        # Enviar código de verificación
        send_verification_email(new_user)

        return redirect(url_for('verify_email'))

    return render_template('register_user.html')




@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        regular_user = RegularUser.query.filter_by(email=email).first()

        if regular_user and check_password_hash(regular_user.password, password):
            if not regular_user.email_verified:
                flash('Debes verificar tu correo electrónico antes de iniciar sesión.', 'warning')
                return redirect(url_for('verify_email', user_id=regular_user.id))
            session['user_id'] = regular_user.id
            session['user_type'] = 'regular'
            return redirect(url_for('index'))
        else:
            return render_template('login_user.html', alert_type='error', alert_title='Error', alert_message='Correo electrónico o contraseña incorrectos.')
    return render_template('login_user.html')



@app.route('/logout_user')
def logout_user():
    session.pop('user_id', None)
    session.pop('user_type', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('index'))

# Ruta para servir archivos subidos
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/search')
def search():
    query = request.args.get('query')
    category_id = request.args.get('category')
    products = Product.query
    
    if query:
        products = products.filter(
            Product.title.contains(query) | 
            Product.short_description.contains(query) | 
            Product.full_description.contains(query)
        )
    
    if category_id:
        products = products.filter_by(category_id=category_id)

    # Obtener todos los productos si la búsqueda no arroja resultados exactos
    products = products.all()
    
    if not products:
        products = Product.query.all()
        flash('No se encontraron resultados exactos para tu búsqueda, pero aquí tienes otros productos que podrían interesarte.', 'warning')
    
    categories = Category.query.all()
    
    return render_template('index.html', products=products, categories=categories)


@app.route('/purchase/<int:product_id>', methods=['GET'])
@user_login_required
def purchase_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('purchase.html', product=product)

@app.route('/download/<int:link_id>')
@user_login_required
def download(link_id):
    download_link = DownloadLink.query.get_or_404(link_id)
    download_link.download_count += 1  # Incrementar el contador de descargas del enlace
    db.session.commit()
    return redirect(download_link.url)  # Redirige al enlace de descarga

@app.route('/edit_profile_user', methods=['GET', 'POST'])
@user_login_required
def edit_profile_user():
    user = RegularUser.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        if not check_password_hash(user.password, current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
            return redirect(url_for('edit_profile_user'))

        user.full_name = request.form['full_name']

        new_password = request.form['new_password']
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        db.session.commit()
        flash('Perfil actualizado con éxito.', 'success')
        return redirect(url_for('index'))

    return render_template('edit_profile_user.html', user=user)

@app.route('/admin/edit_profile_admin', methods=['GET', 'POST'])
@login_required
def edit_profile_admin():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_picture = filename
                db.session.commit()
                flash('Foto de perfil actualizada con éxito.', 'success')
                return redirect(url_for('edit_profile_admin'))

        else:
            user.full_name = request.form['full_name']
            user.bio = request.form['bio']
            user.contact_number = request.form['contact_number']
            db.session.commit()
            flash('Perfil actualizado con éxito.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('edit_profile_admin.html', user=user, admin=user)

@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    
    if user_id:
        if user_type == 'admin':
            admin = User.query.get(user_id)
            if admin:
                return {'admin': admin}
        elif user_type == 'regular':
            user = RegularUser.query.get(user_id)
            if user:
                return {'user': user}
    return {}

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_profile_picture = db.Column(db.String(200), nullable=True, default='default_user.png')

    product = db.relationship('Product', backref=db.backref('comments', lazy=True))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)

@app.route('/product/<int:product_id>/comment', methods=['POST'])
@user_login_required
def add_comment(product_id):
    parent_id = request.form.get('parent_id', None)
    comment_text = request.form['comment_text']
    
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    user = None

    if user_type == 'admin':
        user = User.query.get(user_id)
    elif user_type == 'regular':
        user = RegularUser.query.get(user_id)
    
    if user:
        name = user.full_name or "Usuario"
        email = user.email
        profile_picture = user.profile_picture if hasattr(user, 'profile_picture') else "default_user.png"
    else:
        name = "JHON"
        email = "default@default.com"
        profile_picture = "default_user.png"

    new_comment = Comment(
        name=name,
        email=email,
        comment_text=comment_text,
        product_id=product_id,
        parent_id=parent_id if parent_id else None,
        user_profile_picture=profile_picture
    )

    db.session.add(new_comment)
    db.session.commit()

    flash('Comentario añadido con éxito.', 'success')

    # Verificar el tipo de usuario y redirigir apropiadamente
    if user_type == 'admin':
        # Redirigir de vuelta al panel de comentarios del administrador
        return redirect(url_for('view_comments', product_id=product_id))
    else:
        # Redirigir al detalle del producto como usuario regular
        return redirect(url_for('product_detail', product_id=product_id))


@app.route('/admin/view_comments/<int:product_id>', methods=['GET'])
@login_required
@superadmin_required
def view_comments(product_id):
    product = Product.query.get_or_404(product_id)
    comments = Comment.query.filter_by(product_id=product_id).all()
    
    admin = User.query.get(session.get('user_id'))  # Obtener el usuario administrador actual
    
    return render_template('admin/view_comments.html', product=product, comments=comments, admin=admin)

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comentario eliminado exitosamente.', 'success')
    return redirect(request.referrer)


@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
@superadmin_required
def manage_users():
    # Obtener todos los usuarios registrados
    users = RegularUser.query.all()
    
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@superadmin_required
def delete_user(user_id):
    user = RegularUser.query.get_or_404(user_id)
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Usuario eliminado exitosamente.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin/add_user', methods=['POST'])
@superadmin_required
def add_user():
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']

    # Verificar si el correo ya está registrado
    if RegularUser.query.filter_by(email=email).first():
        flash('El correo electrónico ya está registrado. Por favor, usa uno diferente.', 'danger')
        return redirect(url_for('manage_users'))

    # Crear el nuevo usuario
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = RegularUser(full_name=full_name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Usuario añadido exitosamente.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('user_id')  # Obtén el ID de usuario desde la sesión
    if not user_id:
        flash('No hay usuario en sesión para verificar.', 'danger')
        return redirect(url_for('register'))
    
    user = RegularUser.query.get_or_404(user_id)  # Obtén el usuario desde la base de datos
    
    seconds_remaining = 0
    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        total_seconds = elapsed_time.total_seconds()
        seconds_remaining = max(0, 120 - int(total_seconds))  # 120 segundos = 2 minutos

    if request.method == 'POST':
        verification_code = request.form['verification_code']

        if verification_code == user.verification_code:
            user.email_verified = True
            user.verification_code = None  # Limpia el código de verificación
            db.session.commit()

            # Limpiar la sesión
            session.pop('verification_code', None)

            flash('Correo electrónico verificado exitosamente. Ahora estás autenticado.', 'success')

            # Autenticar automáticamente al usuario
            session['user_id'] = user.id
            session['user_type'] = 'regular'

            return redirect(url_for('index'))
        else:
            flash('Código de verificación incorrecto. Por favor, intenta nuevamente.', 'danger')
    
    return render_template('verify_email.html', user=user, seconds_remaining=seconds_remaining)

@app.route('/resend_verification_code', methods=['GET'])
def resend_verification_code():
    user_id = session.get('user_id')
    if not user_id:
        flash('No hay usuario en sesión para verificar.', 'danger')
        return redirect(url_for('register'))
    
    user = RegularUser.query.get_or_404(user_id)

    # Calcular el tiempo desde que se envió el último código
    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        if elapsed_time < timedelta(minutes=2):
            flash('Debes esperar al menos 2 minutos antes de solicitar un nuevo código.', 'warning')
            return redirect(url_for('verify_email'))

    send_verification_email(user)
    flash('Se ha reenviado un nuevo código de verificación a tu correo electrónico.', 'success')
    return redirect(url_for('verify_email'))

import pandas as pd
from io import BytesIO
from flask import send_file

@app.route('/admin/export_all_data_excel', methods=['GET'])
@login_required
@superadmin_required
def export_all_data_excel():
    # Cargar los datos de cada tabla
    users = User.query.all()
    regular_users = RegularUser.query.all()
    products = Product.query.all()
    categories = Category.query.all()
    download_links = DownloadLink.query.all()
    
    # Convertir los datos a DataFrames de pandas
    users_df = pd.DataFrame([{
        'ID': user.id,
        'Email': user.email,
        'Contraseña': user.password,
        'Es Superadmin': user.is_superadmin,
        'Nombre Completo': user.full_name,
        'Bio': user.bio,
        'Número de Contacto': user.contact_number,
        'Foto de Perfil': user.profile_picture,
    } for user in users])
    
    regular_users_df = pd.DataFrame([{
        'ID': user.id,
        'Email': user.email,
        'Contraseña': user.password,
        'Nombre Completo': user.full_name,
        'Bio': user.bio,
        'Foto de Perfil': user.profile_picture,
        'Activo': user.is_active,
        'Email Verificado': user.email_verified,
        'Fecha de Creación': user.created_at,
    } for user in regular_users])
    
    products_df = pd.DataFrame([{
        'ID': product.id,
        'Título': product.title,
        'Descripción Corta': product.short_description,
        'Descripción Completa': product.full_description,
        'URL de Imagen': product.image_url,
        'Tipo de Producto': product.product_type,
        'Categoría ID': product.category_id,
        'Usuario ID': product.user_id,
    } for product in products])
    
    categories_df = pd.DataFrame([{
        'ID': category.id,
        'Nombre': category.name,
    } for category in categories])
    
    download_links_df = pd.DataFrame([{
        'ID': link.id,
        'Título': link.title,
        'URL': link.url,
        'Producto ID': link.product_id,
        'Número de Descargas': link.download_count,
    } for link in download_links])

    # Crear un archivo Excel en memoria
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        users_df.to_excel(writer, sheet_name='Usuarios Admin', index=False)
        regular_users_df.to_excel(writer, sheet_name='Usuarios Regulares', index=False)
        products_df.to_excel(writer, sheet_name='Productos', index=False)
        categories_df.to_excel(writer, sheet_name='Categorías', index=False)
        download_links_df.to_excel(writer, sheet_name='Enlaces de Descarga', index=False)

    # Preparar el archivo para ser descargado
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='todos_los_datos.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
