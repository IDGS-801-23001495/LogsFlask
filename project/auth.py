from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

from flask import current_app

auth = Blueprint('auth', __name__, url_prefix='/security')

@auth.route('/login/')
def login():
    return render_template('/security/login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    #Consultamos si existe un usuario con ese email
    user = User.query.filter_by(email=email).first()

    #Verifica,os si existe el usuario
    #if not user or not check_password_hash(user.password, password):
    #    flash('el usuario y/o la contraseña son incorrectos')
    #    return redirect(url_for('auth.login'))
    
    if not user or not check_password_hash(user.password, password):
        current_app.logger.warning(f'Intento de acceso fallido para el correo: {email}')
        flash('el usuario y/o la contraseña son incorrectos')
        return redirect(url_for('auth.login'))
    
    current_app.logger.info(f'Acceso exitoso: Usuario ID {user.id} ({email})')
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))
    
    #creamos una sesion y logueamos al usuario
    #login_user(user, remember=remember)

    #return redirect(url_for('main.profile'))

@auth.route('/register')
def register():
    return render_template('security/register.html')

@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    #consultamos si existe un usuario con ese email
    user = User.query.filter_by(email=email).first()

    #if user:
    #    flash('ya existe un usuario con ese email')
    #    return redirect(url_for('auth.register'))
    
    if user:
        current_app.logger.error(f'ERROR DE REGISTRO: El correo {email} ya está en uso.')
        flash('ya existe un usuario con ese email')
        return redirect(url_for('auth.register'))
    
    #creamos un nuevo usuario
    password_hashed = generate_password_hash(password, method='pbkdf2:sha512')

    user_datastore.create_user(name=name, email=email, password=password_hashed)

    current_app.logger.info(f'Nuevo usuario registrado: {email} - Nombre: {name}')
    
    db.session.commit()
    return redirect(url_for('auth.login'))

    #db.session.commit()

    #return redirect(url_for('auth.login'))

@auth.route('/logout')
def logout():
    #cerramos session
    logout_user()
    return redirect(url_for('main.index'))
