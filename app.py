from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
from functools import wraps
import os
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
mail = Mail(app)

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

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # Título del enlace
    url = db.Column(db.String(200), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    product_type = db.Column(db.String(20), nullable=False)  # 'venta' o 'descarga_gratuita'
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Relación con el usuario que creó el producto
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    user = db.relationship('User', backref=db.backref('products', lazy=True))  # Establecer relación con el usuario
    download_links = db.relationship('DownloadLink', backref='product', lazy=True)

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rutas de la aplicación
@app.route('/')
@app.route('/category/<int:category_id>')
def index(category_id=None):
    categories = Category.query.all()  # Obteniendo todas las categorías
    if category_id:
        products = Product.query.filter_by(category_id=category_id).all()
    else:
        products = Product.query.all()
    return render_template('index.html', products=products, categories=categories)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()  # Obtener todas las categorías
    comments = Comment.query.filter_by(product_id=product_id).all()

    # Mapear los correos electrónicos de los administradores y superadministradores
    admin_emails = {user.email: user for user in User.query.filter((User.is_superadmin == True) | (User.is_superadmin == False)).all()}

    return render_template('product_detail.html', product=product, categories=categories, comments=comments, admin_emails=admin_emails)

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
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
    
    # Verificar si el usuario existe
    if not user:
        flash('Usuario no encontrado. Por favor, inicia sesión nuevamente.', 'danger')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search')
    
    if user.is_superadmin:
        products = Product.query.all()  # Superadministrador ve todos los productos
        admins = User.query.filter_by(is_superadmin=False).all()  # Lista de administradores
        return render_template('admin/dashboard.html', products=products, admins=admins, is_superadmin=True)
    else:
        products = Product.query.filter_by(user_id=user.id).all()  # Administradores solo ven sus productos
        return render_template('admin/dashboard.html', products=products, is_superadmin=False)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    user = User.query.get(session['user_id'])  # Obtener el usuario actual
    categories = Category.query.all()
    selected_category = request.args.get('selected_category', None)
    
    if request.method == 'POST':
        title = request.form['title']
        short_description = request.form['short_description']
        full_description = request.form['full_description']
        category_id = request.form['category_id']
        
        # Manejo de la subida de la imagen
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
            user_id=user.id  # Asignar el producto al usuario actual
        )
        db.session.add(new_product)
        db.session.commit()
        
        # Manejo de múltiples enlaces de descarga con títulos
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=new_product.id)
                db.session.add(new_link)
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/add_product.html', categories=categories, is_superadmin=user.is_superadmin, selected_category=selected_category)

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
        
        # Manejo de la subida de la imagen
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product.image_url = url_for('uploaded_file', filename=filename)

        product.product_type = request.form['product_type']
        
        # Eliminar los enlaces de descarga actuales y añadir los nuevos
        DownloadLink.query.filter_by(product_id=product.id).delete()
        link_titles = request.form.getlist('link_titles[]')
        download_links = request.form.getlist('download_links[]')
        for title, url in zip(link_titles, download_links):
            if title and url:
                new_link = DownloadLink(title=title, url=url, product_id=product.id)
                db.session.add(new_link)

        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_product.html', product=product, categories=categories)

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Eliminar todos los comentarios asociados al producto
    Comment.query.filter_by(product_id=product.id).delete()
    
    # Eliminar todos los enlaces de descarga asociados al producto
    DownloadLink.query.filter_by(product_id=product.id).delete()
    
    # Ahora eliminar el producto
    db.session.delete(product)
    db.session.commit()
    
    flash('Producto, sus enlaces de descarga y comentarios asociados han sido eliminados exitosamente.', 'success')
    return redirect(url_for('dashboard'))

# Ruta para gestionar categorías en el modal de añadir productos
@app.route('/admin/add_category', methods=['POST'])
@login_required
@superadmin_required  # Solo el superadministrador puede agregar categorías
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
            return redirect(url_for('add_product', selected_category=new_category.id))  # Redirigir al formulario con la categoría seleccionada
        else:
            flash('El nombre de la categoría no puede estar vacío', 'danger')
    
    return redirect(url_for('add_product'))  # Redirige de nuevo al formulario de añadir producto

@app.route('/admin/manage_categories', methods=['GET', 'POST'])
@login_required
@superadmin_required  # Solo el superadministrador puede gestionar categorías
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
                flash('Categoría creada exitosamente', 'success')
            else:
                flash('El nombre de la categoría no puede estar vacío', 'danger')
    
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories, is_superadmin=True)

@app.route('/admin/delete_category/<int:category_id>')
@login_required
@superadmin_required  # Solo el superadministrador puede eliminar categorías
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
    return render_template('admin/manage_admins.html', admins=admins)

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
    return redirect(url_for('login'))

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
def purchase_product(product_id):
    product = Product.query.get_or_404(product_id)
    # Aquí podrías agregar la lógica para manejar el proceso de compra
    return render_template('purchase.html', product=product)

@app.route('/download_links/<int:product_id>')
def download_links(product_id):
    product = Product.query.get_or_404(product_id)
    download_links = DownloadLink.query.filter_by(product_id=product_id).all()
    return render_template('download_links.html', product=product, download_links=download_links)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
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
                return redirect(url_for('edit_profile'))

        # Esto asegura que solo se actualicen los otros campos cuando no se sube una imagen
        else:
            user.full_name = request.form['full_name']
            user.bio = request.form['bio']
            user.contact_number = request.form['contact_number']
            db.session.commit()
            flash('Perfil actualizado con éxito.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', user=user)


@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return {'user': user}
    return {}

# Modelo para los comentarios
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)  # Comentario padre (opcional)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    product = db.relationship('Product', backref=db.backref('comments', lazy=True))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)

@app.route('/product/<int:product_id>/comment', methods=['POST'])
@login_required
def add_comment(product_id):
    user = User.query.get(session['user_id'])
    parent_id = request.form.get('parent_id', None)
    comment_text = request.form['comment_text']

    if parent_id:
        # Es una respuesta a un comentario existente
        name = user.full_name
        email = user.email
    else:
        # Es un nuevo comentario
        name = request.form['name']
        email = request.form['email']

    new_comment = Comment(
        name=name, 
        email=email, 
        comment_text=comment_text, 
        product_id=product_id,
        parent_id=parent_id if parent_id else None  # Añadir el ID del comentario padre si existe
    )

    db.session.add(new_comment)
    db.session.commit()

    flash('Comentario añadido con éxito.', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/admin/view_comments/<int:product_id>', methods=['GET'])
@login_required
@superadmin_required
def view_comments(product_id):
    product = Product.query.get_or_404(product_id)
    comments = Comment.query.filter_by(product_id=product_id).all()
    return render_template('admin/view_comments.html', product=product, comments=comments)

# Ruta para eliminar comentarios
@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
@superadmin_required  # Solo el superadministrador o administrador puede eliminar comentarios
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comentario eliminado exitosamente.', 'success')
    return redirect(request.referrer)  # Redirige a la página anterior

if __name__ == '__main__':
    # Crear la base de datos y las tablas dentro del contexto de la aplicación
    with app.app_context():
        db.create_all()
    app.run(debug=True)
