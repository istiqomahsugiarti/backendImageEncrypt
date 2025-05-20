from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from config import Config
from extensions import db, jwt, mail
from auth import auth_bp
from routes import routes_bp
from flask_mail import Mail
from user_management import user_mgmt_bp
from faq_managament import faq_bp



# Load environment variables from .env
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Setup extensions

db.init_app(app)
jwt.init_app(app)
mail.init_app(app)
CORS(app, origins=["https://picrypt.vercel.app", "http://localhost:3000"], supports_credentials=True)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(routes_bp)
app.register_blueprint(user_mgmt_bp)
app.register_blueprint(faq_bp)

# Create tables (jika belum ada)
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
