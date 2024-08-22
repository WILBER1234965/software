from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Importar los modelos desde app.py
from app import User, RegularUser, Category, Product, Comment, DownloadLink

if __name__ == "__main__":
    app.run(debug=True)
