from flask import Flask, render_template, redirect, url_for, request, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
from functools import wraps
import os

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
mail = Mail(app)

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

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    download_link = db.Column(db.String(200), nullable=False)
    product_type = db.Column(db.String(20), nullable=False)  # 'venta' o 'descarga_gratuita'
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('products', lazy=True))

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
    return render_template('product_detail.html', product=product, categories=categories)

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
            flash('Credenciales incorrectas.')
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
    search_query = request.args.get('search')
    products = Product.query
    
    if search_query:
        products = products.filter(Product.title.contains(search_query) | Product.short_description.contains(search_query))
    
    products = products.all()
    
    return render_template('admin/dashboard.html', products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    categories = Category.query.all()
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

        download_link = request.form['download_link']
        product_type = request.form['product_type']
        
        new_product = Product(title=title, short_description=short_description, full_description=full_description,
                              image_url=image_url, download_link=download_link, product_type=product_type, category_id=category_id)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/add_product.html', categories=categories)

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

        product.download_link = request.form['download_link']
        product.product_type = request.form['product_type']
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_product.html', product=product, categories=categories)

@app.route('/admin/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('dashboard'))

# Ruta para gestionar categorías en el modal de añadir productos
@app.route('/admin/add_category', methods=['POST'])
@login_required
def add_category():
    category_name = request.form['category_name']
    if category_name:
        new_category = Category(name=category_name)
        db.session.add(new_category)
        db.session.commit()
        flash('Categoría creada exitosamente', 'success')
    else:
        flash('El nombre de la categoría no puede estar vacío', 'danger')
    return redirect(url_for('add_product'))

@app.route('/admin/manage_categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if request.method == 'POST':
        category_name = request.form['name']
        if category_name:
            new_category = Category(name=category_name)
            db.session.add(new_category)
            db.session.commit()
            flash('Categoría creada exitosamente', 'success')
        else:
            flash('El nombre de la categoría no puede estar vacío', 'danger')
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories)

@app.route('/admin/delete_category/<int:category_id>')
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.products:
        flash('No se puede eliminar una categoría que tiene productos asociados.', 'danger')
    else:
        db.session.delete(category)
        db.session.commit()
        flash('Categoría eliminada exitosamente.', 'success')
    return redirect(url_for('manage_categories'))

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



if __name__ == '__main__':
    # Crear la base de datos y las tablas dentro del contexto de la aplicación
    with app.app_context():
        db.create_all()
    app.run(debug=True)
