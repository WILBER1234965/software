from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from functools import wraps

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
mail = Mail(app)

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

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=False)
    full_description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    download_link = db.Column(db.String(200), nullable=False)
    product_type = db.Column(db.String(20), nullable=False)  # 'venta' o 'descarga_gratuita'

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
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

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
    products = Product.query.all()
    return render_template('admin/dashboard.html', products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        title = request.form['title']
        short_description = request.form['short_description']
        full_description = request.form['full_description']
        image_url = request.form['image_url']
        download_link = request.form['download_link']
        product_type = request.form['product_type']
        
        new_product = Product(title=title, short_description=short_description, full_description=full_description,
                              image_url=image_url, download_link=download_link, product_type=product_type)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/add_product.html')

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        product.title = request.form['title']
        product.short_description = request.form['short_description']
        product.full_description = request.form['full_description']
        product.image_url = request.form['image_url']
        product.download_link = request.form['download_link']
        product.product_type = request.form['product_type']
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
