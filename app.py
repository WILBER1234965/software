from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from functools import wraps
import os
from datetime import datetime, timedelta
import random
import pandas as pd
from io import BytesIO
from sqlalchemy import func, asc, desc

# Inicialización de la aplicación
app = Flask(__name__)
app.config.from_object('config.Config')

# Inicialización de extensiones
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)


# Asegurarse de que las carpetas de subida existan
def ensure_upload_folder():
    product_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'products')
    profile_pictures_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')

    os.makedirs(product_folder, exist_ok=True)
    os.makedirs(profile_pictures_folder, exist_ok=True)

ensure_upload_folder()


# Función para verificar si la extensión del archivo es permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Decoradores de acceso
def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or not user.is_superadmin:
            flash('Acceso denegado. Privilegios de superadministrador requeridos.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'admin':
            session['next'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'regular':
            session['next'] = request.url
            flash('Debes iniciar sesión para acceder a esta función.', 'warning')
            return redirect(url_for('login_user'))
        return f(*args, **kwargs)
    return decorated_function

# Función para enviar el correo de verificación
def send_verification_email(user):
    verification_code = ''.join(random.choices('0123456789', k=6))
    user.verification_code = verification_code
    user.verification_code_sent_at = datetime.utcnow()
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

    def __repr__(self):
        return f"<User {self.email}>"

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
    verification_code_sent_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<RegularUser {self.email}>"

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

    def __repr__(self):
        return f"<Category {self.name}>"

class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    download_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<DownloadLink {self.title} for product {self.product_id}>"

class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

    def __repr__(self):
        return f"<ProductImage {self.image_url}>"

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    product_type = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    images = db.relationship('ProductImage', backref='product', lazy=True, cascade="all, delete-orphan")
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    user = db.relationship('User', backref=db.backref('products', lazy=True))
    download_links = db.relationship('DownloadLink', backref='product', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Product {self.title}>"

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

    def __repr__(self):
        return f"<Comment {self.id} on product {self.product_id}>"

@app.route('/')
@app.route('/category/<int:category_id>')
def index(category_id=None):
    query = request.args.get('query')
    categories = Category.query.all()

    products = Product.query.filter_by(active=True)

    if category_id:
        products = products.filter_by(category_id=category_id)
    
    if query:
        products = products.filter(
            (Product.title.ilike(f'%{query}%')) |
            (Product.short_description.ilike(f'%{query}%')) |
            (Product.full_description.ilike(f'%{query}%'))
        )

    products = products.order_by(Product.created_at.desc()).all()

    if not products:
        flash('No se encontraron productos que coincidan con tu búsqueda, pero aquí tienes otros que podrían interesarte.', 'warning')
        products = Product.query.filter_by(active=True).order_by(Product.created_at.desc()).all()

    user = RegularUser.query.get(session['user_id']) if 'user_id' in session and session.get('user_type') == 'regular' else None

    return render_template('index.html', products=products, categories=categories, user=user)

@app.route('/product/<int:product_id>')
@user_login_required
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    comments = Comment.query.filter_by(product_id=product_id).all()

    author = User.query.get(product.user_id)

    user = RegularUser.query.get(session['user_id']) if 'user_id' in session else None

    # Modificación para asegurar que la URL de las imágenes sea correcta
    for image in product.images:
        image.image_url = url_for('uploaded_file', filename=f'products/{product.id}/{image.image_url.split("/")[-1]}')

    return render_template('product_detail.html', product=product, categories=categories, comments=comments, user=user, author=author)

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_type'] = 'admin'
            return redirect(session.pop('next', url_for('dashboard')))
        flash('Credenciales incorrectas.', 'danger')
    return render_template('admin/login.html')

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = RegularUser.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                flash('Debes verificar tu correo electrónico antes de iniciar sesión.', 'warning')
                return redirect(url_for('verify_email', user_id=user.id))
            session['user_id'] = user.id
            session['user_type'] = 'regular'
            return redirect(session.pop('next', url_for('index')))
        flash('Credenciales incorrectas.', 'danger')
    return render_template('login_user.html')

@app.route('/admin/dashboard')
@admin_login_required
def dashboard():
    user = User.query.get(session.get('user_id'))
    if not user:
        flash('Usuario no encontrado. Por favor, inicia sesión nuevamente.', 'danger')
        return redirect(url_for('login'))

    search = request.args.get('search', '')
    sort_option = request.args.get('sort', 'recent')

    products_query = Product.query if user.is_superadmin else Product.query.filter_by(user_id=user.id)

    if search:
        products_query = products_query.filter(Product.title.ilike(f'%{search}%'))

    if sort_option == 'recent':
        products_query = products_query.order_by(desc(Product.created_at))
    elif sort_option == 'oldest':
        products_query = products_query.order_by(asc(Product.created_at))
    elif sort_option == 'title_asc':
        products_query = products_query.order_by(asc(Product.title))
    elif sort_option == 'title_desc':
        products_query = products_query.order_by(desc(Product.title))
    elif sort_option == 'category':
        products_query = products_query.join(Category).order_by(asc(Category.name))
    elif sort_option == 'downloads':
        products_query = products_query.outerjoin(DownloadLink)\
                                       .group_by(Product.id)\
                                       .order_by(desc(func.sum(DownloadLink.download_count)))

    products = products_query.all()

    for product in products:
        product.total_downloads = sum(link.download_count for link in product.download_links)

    admins = User.query.filter_by(is_superadmin=False).all() if user.is_superadmin else []

    return render_template('admin/dashboard.html', products=products, admins=admins, admin=user, is_superadmin=user.is_superadmin)

@app.route('/download_links/<int:product_id>')
@user_login_required
def download_links(product_id):
    product = Product.query.get_or_404(product_id)
    download_links = product.download_links
    return render_template('download_links.html', product=product, download_links=download_links)

@app.route('/purchase/<int:product_id>', methods=['GET'])
@user_login_required
def purchase_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('purchase.html', product=product)

@app.route('/download/<int:link_id>')
@user_login_required
def download(link_id):
    download_link = DownloadLink.query.get_or_404(link_id)
    download_link.download_count += 1
    db.session.commit()
    return redirect(download_link.url)

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
        
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Tu contraseña ha sido actualizada. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('admin/reset_password.html', token=token)

# Modificar la función `add_product` y `edit_product` para guardar imágenes en la subcarpeta correspondiente
@app.route('/admin/add_product', methods=['GET', 'POST'])
@admin_login_required
def add_product():
    user = User.query.get(session['user_id'])
    categories = Category.query.all()
    
    if request.method == 'POST':
        title = request.form['title']
        short_description = request.form['short_description']
        full_description = request.form['full_description']
        recommendations = request.form.get('recommendations', '')
        category_id = request.form['category_id']

        new_product = Product(
            title=title,
            short_description=short_description,
            full_description=full_description,
            recommendations=recommendations,
            product_type=request.form['product_type'],
            category_id=category_id,
            user_id=user.id
        )
        db.session.add(new_product)
        db.session.commit()

        # Crear la subcarpeta del producto
        product_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'products', str(new_product.id))
        os.makedirs(product_folder, exist_ok=True)

        files = request.files.getlist('main_image') + request.files.getlist('additional_images[]')
        valid_images = [file for file in files if file and allowed_file(file.filename)]
        
        if not valid_images:
            flash('Debes subir al menos una imagen válida.', 'danger')
            return redirect(url_for('add_product'))

        for file in valid_images:
         filename = secure_filename(file.filename)
         file.save(os.path.join(product_folder, filename))
         # Aquí solo guardamos el nombre del archivo
         new_image = ProductImage(image_url=filename, product_id=new_product.id)
         db.session.add(new_image)


        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=new_product.id)
                db.session.add(new_link)

        db.session.commit()

        flash('Producto añadido exitosamente.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('admin/add_product.html', categories=categories, is_superadmin=user.is_superadmin, admin=user)

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@admin_login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()

    if request.method == 'POST':
        product.title = request.form['title']
        product.short_description = request.form['short_description']
        product.full_description = request.form['full_description']
        product.recommendations = request.form.get('recommendations', '')
        product.category_id = request.form['category_id']
        product.product_type = request.form['product_type']

        # Crear la subcarpeta del producto si no existe
        product_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'products', str(product.id))
        os.makedirs(product_folder, exist_ok=True)

        # Gestionar la imagen principal
        main_image = request.files.get('main_image')
        if main_image and allowed_file(main_image.filename):
            if product.images:
                if len(product.images) > 0:
                    old_main_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.images[0].image_url.split('/')[-1])
                    if os.path.exists(old_main_image_path):
                        os.remove(old_main_image_path)

                    filename = secure_filename(main_image.filename)
                    main_image.save(os.path.join(product_folder, filename))
                    product.images[0].image_url = url_for('uploaded_file', filename=f'products/{product.id}/{filename}')
            else:
                filename = secure_filename(main_image.filename)
                main_image.save(os.path.join(product_folder, filename))
                image_url = url_for('uploaded_file', filename=f'products/{product.id}/{filename}')
                new_image = ProductImage(image_url=image_url, product_id=product.id)
                db.session.add(new_image)

        # Gestionar imágenes adicionales
        for file in request.files.getlist('additional_images[]'):
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(product_folder, filename))
                image_url = url_for('uploaded_file', filename=f'products/{product.id}/{filename}')
                new_image = ProductImage(image_url=image_url, product_id=product.id)
                db.session.add(new_image)

        # Eliminar imágenes seleccionadas
        images_to_delete = request.form.getlist('delete_images[]')
        for image_id in images_to_delete:
            image = ProductImage.query.get(image_id)
            if image:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url.split('/')[-1])
                if os.path.exists(image_path):
                    os.remove(image_path)
                db.session.delete(image)

        # Gestionar enlaces de descarga
        DownloadLink.query.filter_by(product_id=product.id).delete()
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=product.id)
                db.session.add(new_link)

        db.session.commit()
        flash('Producto actualizado exitosamente.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('admin/edit_product.html', product=product, categories=categories, admin=User.query.get(session['user_id']))
@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Ruta de la subcarpeta del producto
    product_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'products', str(product.id))

    # Eliminar las imágenes del producto
    for image in product.images:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url.split('/')[-1])
        if os.path.exists(image_path):
            os.remove(image_path)

    # Eliminar la subcarpeta del producto si existe
    if os.path.exists(product_folder) and os.path.isdir(product_folder):
        try:
            os.rmdir(product_folder)  # Elimina la carpeta si está vacía
        except OSError:
            import shutil
            shutil.rmtree(product_folder)  # Elimina la carpeta y todos sus contenidos

    # Eliminar los comentarios y enlaces de descarga asociados al producto
    Comment.query.filter_by(product_id=product.id).delete()
    DownloadLink.query.filter_by(product_id=product.id).delete()

    # Eliminar el producto de la base de datos
    db.session.delete(product)
    db.session.commit()

    flash('Producto, sus enlaces de descarga, imágenes y comentarios asociados han sido eliminados exitosamente.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/add_category', methods=['POST'])
@admin_login_required
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
        flash('El nombre de la categoría no puede estar vacío', 'danger')
    
    return redirect(url_for('add_product'))

@app.route('/admin/manage_categories', methods=['GET', 'POST'])
@admin_login_required
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
@admin_login_required
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
@admin_login_required
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
@admin_login_required
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
@admin_login_required
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

        if not email or not password or not confirm_password or not full_name:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Todos los campos son obligatorios.')

        if "@" not in email or "." not in email:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Por favor ingrese un correo electrónico válido.')

        if len(password) < 6:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='La contraseña debe tener al menos 6 caracteres.')

        if password != confirm_password:
            return render_template('register_user.html', alert_type='warning', alert_title='Advertencia', alert_message='Las contraseñas no coinciden.')

        existing_user = RegularUser.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.email_verified:
                session['user_id'] = existing_user.id
                flash('Este correo ya está registrado, pero no ha sido verificado. Por favor verifica tu correo.', 'warning')
                return redirect(url_for('verify_email'))
            return render_template('register_user.html', alert_type='error', alert_title='Error', alert_message='El correo electrónico ya está registrado.')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = RegularUser(email=email, password=hashed_password, full_name=full_name)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
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

            next_url = session.pop('next', url_for('index'))
            return redirect(next_url)
        
        flash('Credenciales incorrectas.', 'danger')
    return render_template('login_user.html')

@app.route('/logout_user')
def logout_user():
    session.pop('user_id', None)
    session.pop('user_type', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('index'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/search')
def search():
    query = request.args.get('query')
    category_id = request.args.get('category')
    products = Product.query.filter_by(active=True)
    
    if query:
        products = products.filter(
            Product.title.contains(query) | 
            Product.short_description.contains(query) | 
            Product.full_description.contains(query)
        )
    
    if category_id:
        products = products.filter_by(category_id=category_id)

    products = products.order_by(Product.created_at.desc()).all()
    
    if not products:
        products = Product.query.filter_by(active=True).order_by(Product.created_at.desc()).all()
        flash('No se encontraron resultados exactos para tu búsqueda, pero aquí tienes otros productos que podrían interesarte.', 'warning')
    
    categories = Category.query.all()
    
    return render_template('index.html', products=products, categories=categories)

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
@admin_login_required
def edit_profile_admin():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                profile_pictures_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')
                filename = secure_filename(file.filename)
                file.save(os.path.join(profile_pictures_folder, filename))
                user.profile_picture = f'profile_pictures/{filename}'
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

@app.route('/product/<int:product_id>/comment', methods=['POST'])
@user_login_required
def add_comment(product_id):
    parent_id = request.form.get('parent_id', None)
    comment_text = request.form['comment_text'].strip()
    
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    user = None

    if user_type == 'admin':
        user = User.query.get(user_id)
    elif user_type == 'regular':
        user = RegularUser.query.get(user_id)
    
    if user and comment_text:
        name = user.full_name or "Usuario"
        email = user.email
        profile_picture = user.profile_picture if hasattr(user, 'profile_picture') else "default_user.png"

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
    else:
        flash('No puedes enviar un comentario vacío.', 'danger')

    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/admin/view_comments/<int:product_id>', methods=['GET'])
@admin_login_required
@superadmin_required
def view_comments(product_id):
    product = Product.query.get_or_404(product_id)
    comments = Comment.query.filter_by(product_id=product_id).all()
    
    admin = User.query.get(session.get('user_id'))
    
    return render_template('admin/view_comments.html', product=product, comments=comments, admin=admin)

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@admin_login_required
@superadmin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comentario eliminado exitosamente.', 'success')
    return redirect(request.referrer)

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_login_required
@superadmin_required
def manage_users():
    users = RegularUser.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_login_required
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

    if RegularUser.query.filter_by(email=email).first():
        flash('El correo electrónico ya está registrado. Por favor, usa uno diferente.', 'danger')
        return redirect(url_for('manage_users'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = RegularUser(full_name=full_name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Usuario añadido exitosamente.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('user_id')
    if not user_id:
        flash('No hay usuario en sesión para verificar.', 'danger')
        return redirect(url_for('register'))
    
    user = RegularUser.query.get_or_404(user_id)
    
    seconds_remaining = 0
    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        total_seconds = elapsed_time.total_seconds()
        seconds_remaining = max(0, 120 - int(total_seconds))

    if request.method == 'POST':
        verification_code = request.form['verification_code']

        if verification_code == user.verification_code:
            user.email_verified = True
            user.verification_code = None
            db.session.commit()

            session.pop('verification_code', None)

            flash('Correo electrónico verificado exitosamente. Ahora estás autenticado.', 'success')

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

    if user.verification_code_sent_at:
        elapsed_time = datetime.utcnow() - user.verification_code_sent_at
        if elapsed_time < timedelta(minutes=2):
            flash('Debes esperar al menos 2 minutos antes de solicitar un nuevo código.', 'warning')
            return redirect(url_for('verify_email'))

    send_verification_email(user)
    flash('Se ha reenviado un nuevo código de verificación a tu correo electrónico.', 'success')
    return redirect(url_for('verify_email'))

@app.route('/admin/export_all_data_excel', methods=['GET'])
@admin_login_required
@superadmin_required
def export_all_data_excel():
    users = User.query.all()
    regular_users = RegularUser.query.all()
    products = Product.query.all()
    categories = Category.query.all()
    download_links = DownloadLink.query.all()
    
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

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        users_df.to_excel(writer, sheet_name='Usuarios Admin', index=False)
        regular_users_df.to_excel(writer, sheet_name='Usuarios Regulares', index=False)
        products_df.to_excel(writer, sheet_name='Productos', index=False)
        categories_df.to_excel(writer, sheet_name='Categorías', index=False)
        download_links_df.to_excel(writer, sheet_name='Enlaces de Descarga', index=False)

    output.seek(0)
    return send_file(output, as_attachment=True, download_name='todos_los_datos.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/admin/toggle_product/<int:product_id>', methods=['POST'])
def toggle_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.active = not product.active
    db.session.commit()
    flash(f'Producto {"activado" if product.active else "desactivado"} exitosamente.', 'success')
    return redirect(url_for('dashboard'))



import paypalrestsdk
from flask import redirect, url_for, render_template, flash

# Configurar PayPal SDK
paypalrestsdk.configure({
  "mode": "sandbox",  # Cambiar a 'live' en producción
  "client_id": "TU_CLIENT_ID_DE_PAYPAL",
  "client_secret": "TU_CLIENT_SECRET_DE_PAYPAL"
})

@app.route('/buy/<int:product_id>', methods=['GET', 'POST'])
def buy_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Crear un pago de PayPal
    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": url_for('payment_completed', product_id=product.id, _external=True),
            "cancel_url": url_for('payment_cancelled', _external=True)
        },
        "transactions": [{
            "item_list": {
                "items": [{
                    "name": product.title,
                    "sku": "item",
                    "price": "1.50",
                    "currency": "USD",
                    "quantity": 1
                }]
            },
            "amount": {
                "total": "1.50",
                "currency": "USD"
            },
            "description": f"Compra del producto {product.title}"
        }]
    })
    
    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                approval_url = str(link.href)
                return redirect(approval_url)
    else:
        flash('Ocurrió un error al procesar el pago. Inténtalo de nuevo.', 'danger')
        return redirect(url_for('product_detail', product_id=product.id))

@app.route('/payment_completed/<int:product_id>')
def payment_completed(product_id):
    # Aquí puedes manejar la confirmación del pago y entregar el producto
    flash('Pago completado exitosamente. Puedes descargar tu producto.', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/payment_cancelled')
def payment_cancelled():
    flash('El pago fue cancelado. Inténtalo de nuevo.', 'warning')
    return redirect(url_for('index'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
