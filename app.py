import eventlet
eventlet.monkey_patch()
import os
import uuid
import smtplib
import ssl
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de subidas
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
PROFILE_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile_pics')
CONTRIB_FOLDER = os.path.join(UPLOAD_FOLDER, 'contributions')

os.makedirs(PROFILE_FOLDER, exist_ok=True)
os.makedirs(CONTRIB_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_pic = db.Column(db.String(200), default='default.png')
    points = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    # Silenciado: evita que el usuario publique comentarios
    is_muted = db.Column(db.Boolean, default=False)
    contributions = db.relationship('Contribution', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    # Campos de perfil extendido
    bio = db.Column(db.Text, default='')
    location = db.Column(db.String(120), default='')
    website = db.Column(db.String(120), default='')
    # Relaciones de seguidores
    followers = db.relationship('Follower', foreign_keys='Follower.followed_id', backref='followed', lazy='dynamic')
    following = db.relationship('Follower', foreign_keys='Follower.follower_id', backref='follower', lazy='dynamic')
    notifications = db.relationship('Notification', backref='recipient', lazy=True)
    # Confirmación de correo
    is_confirmed = db.Column(db.Boolean, default=False)
    confirmation_token = db.Column(db.String(100), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Contribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(300), nullable=True)
    image = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=None)  # None = pendiente, True = aprobado, False = rechazado
    votes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='contribution', lazy=True)
    contribution_votes = db.relationship('ContributionVote', backref='contribution', lazy=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contribution_id = db.Column(db.Integer, db.ForeignKey('contribution.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    votes = db.Column(db.Integer, default=0)
    comment_votes = db.relationship('CommentVote', backref='comment', lazy=True)


class CommentVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    value = db.Column(db.Integer, nullable=False)  # 1 o -1


class ContributionVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contribution_id = db.Column(db.Integer, db.ForeignKey('contribution.id'), nullable=False)
    value = db.Column(db.Integer, nullable=False)  # 1 o -1

class Follower(db.Model):
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Funciones auxiliares

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def save_file(file_obj, folder):
    """Guarda un archivo subido en la carpeta indicada y devuelve el nombre."""
    if file_obj and allowed_file(file_obj.filename):
        filename = secure_filename(file_obj.filename)
        base, ext = os.path.splitext(filename)
        counter = 1
        save_name = filename
        while os.path.exists(os.path.join(folder, save_name)):
            save_name = f"{base}_{counter}{ext}"
            counter += 1
        file_obj.save(os.path.join(folder, save_name))
        return save_name
    return None

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def add_notification(user_id: int, message: str):
    """Crea y guarda una notificación nueva."""
    notification = Notification(user_id=user_id, message=message, is_read=False)
    db.session.add(notification)
    db.session.commit()

def send_email(to_email: str, subject: str, body: str) -> None:
    """
    Envía un correo usando SMTP según variables de entorno. Si falla, imprime el error.
    """
    server = os.getenv('MAIL_SERVER', 'localhost')
    port = int(os.getenv('MAIL_PORT', '25'))
    username = os.getenv('MAIL_USERNAME')
    password = os.getenv('MAIL_PASSWORD')
    use_tls = os.getenv('MAIL_USE_TLS', 'False').lower() == 'true'
    message = f"Subject: {subject}\nTo: {to_email}\nFrom: {username or 'noreply@localhost'}\n\n{body}"
    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            if use_tls:
                context = ssl.create_default_context()
                smtp.starttls(context=context)
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(username or 'noreply@localhost', [to_email], message)
    except Exception as e:
        print('Error sending email:', e)

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    """Hace que current_user esté disponible en todas las plantillas."""
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            unread_notifications = Notification.query.filter_by(user_id=user.id, is_read=False).count()
            return dict(current_user=user, unread_notifications=unread_notifications)
        # Si el usuario ya no existe, limpia la sesión
        session.pop('user_id', None)
    return dict(current_user=None, unread_notifications=0)

# Rutas
@app.route('/')
def home():
    contributions = Contribution.query.filter_by(approved=True).order_by(Contribution.created_at.desc()).all()
    return render_template('home.html', contributions=contributions)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if not username or not email or not password:
            flash('Por favor completa todos los campos.', 'danger')
        elif password != confirm:
            flash('Las contraseñas no coinciden.', 'danger')
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            flash('El nombre de usuario o email ya existe.', 'danger')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            profile_pic = request.files.get('profile_pic')
            if profile_pic and allowed_file(profile_pic.filename):
                filename = save_file(profile_pic, PROFILE_FOLDER)
                user.profile_pic = filename
            token = str(uuid.uuid4())
            user.confirmation_token = token
            user.is_confirmed = False
            db.session.add(user)
            db.session.commit()
            confirmation_link = url_for('confirm_email', token=token, _external=True)
            subject = 'Confirma tu cuenta en HumorAportes'
            body = f"Hola {username},\n\nPor favor confirma tu cuenta haciendo clic en el siguiente enlace:\n{confirmation_link}\n\nSi no has creado una cuenta en nuestro sitio, ignora este correo."
            try:
                send_email(user.email, subject, body)
                flash('Registro exitoso. Hemos enviado un correo de confirmación.', 'success')
            except Exception:
                flash(f'Registro exitoso. No se pudo enviar el correo. Usa este enlace para confirmar tu cuenta: {confirmation_link}', 'warning')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password')

        # Busca el usuario por email o username sin diferenciar mayúsculas
        user = User.query.filter(
            or_(
                User.email.ilike(username_or_email),
                User.username.ilike(username_or_email)
            )
        ).first()

        if user and user.check_password(password):
            if not user.is_confirmed:
                flash('Debes confirmar tu cuenta por correo electrónico antes de iniciar sesión.', 'warning')
                return redirect(url_for('login'))
            session['user_id'] = user.id
            flash('Has iniciado sesión correctamente.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Credenciales inválidas.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('home'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    contributions = Contribution.query.filter_by(user_id=user.id, approved=True).order_by(Contribution.created_at.desc()).all()
    return render_template('profile.html', user=user, contributions=contributions)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    categories = Category.query.order_by(Category.name.asc()).all()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        link = request.form.get('link', '').strip()
        image_file = request.files.get('image')
        category_id = request.form.get('category_id')
        if not title:
            flash('El título es obligatorio.', 'danger')
            return render_template('submit.html', categories=categories)
        if not link and (not image_file or image_file.filename == ''):
            flash('Debe proporcionar un enlace o una imagen.', 'danger')
            return render_template('submit.html', categories=categories)
        new_contrib = Contribution(user_id=session['user_id'], title=title, description=description)
        if category_id:
            try:
                new_contrib.category_id = int(category_id)
            except ValueError:
                pass
        if link:
            new_contrib.link = link
        if image_file and allowed_file(image_file.filename):
            filename = save_file(image_file, CONTRIB_FOLDER)
            new_contrib.image = filename
        db.session.add(new_contrib)
        db.session.commit()
        flash('Tu aporte ha sido enviado y está pendiente de aprobación.', 'success')
        return redirect(url_for('home'))
    return render_template('submit.html', categories=categories)

@app.route('/contribution/<int:contrib_id>', methods=['GET', 'POST'])
def view_contribution(contrib_id):
    contrib = Contribution.query.get_or_404(contrib_id)
    if contrib.approved is not True and (not session.get('user_id') or not User.query.get(session['user_id']).is_admin):
        abort(404)
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Debes iniciar sesión para comentar.', 'danger')
            return redirect(url_for('login'))
        current_user = User.query.get(session['user_id'])
        if current_user.is_muted:
            flash('Has sido silenciado y no puedes comentar en este momento.', 'danger')
            return redirect(url_for('view_contribution', contrib_id=contrib.id))
        content = request.form.get('content', '').strip()
        if not content:
            flash('El comentario no puede estar vacío.', 'danger')
        else:
            comment = Comment(user_id=current_user.id, contribution_id=contrib.id, content=content)
            db.session.add(comment)
            db.session.commit()
            flash('Comentario enviado.', 'success')
            return redirect(url_for('view_contribution', contrib_id=contrib.id))
    comments = Comment.query.filter_by(contribution_id=contrib.id).order_by(Comment.created_at.asc()).all()
    return render_template('contribution.html', contribution=contrib, comments=comments)

@app.route('/comment/<int:comment_id>/vote/<int:value>', methods=['POST'])
@login_required
def vote_comment(comment_id, value):
    comment = Comment.query.get_or_404(comment_id)
    if value not in (1, -1):
        abort(400)
    voter_id = session['user_id']
    if comment.user_id == voter_id:
        flash('No puedes votar tus propios comentarios.', 'danger')
        return redirect(url_for('view_contribution', contrib_id=comment.contribution_id))
    existing_vote = CommentVote.query.filter_by(user_id=voter_id, comment_id=comment.id).first()
    if existing_vote:
        if existing_vote.value == value:
            flash('Ya has votado de esta manera.', 'info')
            return redirect(url_for('view_contribution', contrib_id=comment.contribution_id))
        delta = value - existing_vote.value
        existing_vote.value = value
    else:
        existing_vote = CommentVote(user_id=voter_id, comment_id=comment.id, value=value)
        db.session.add(existing_vote)
        delta = value
    comment.votes += delta
    comment.author.points += delta
    db.session.commit()
    if delta != 0:
        sign = 'positivo' if value > 0 else 'negativo'
        add_notification(comment.author.id, f'Tu comentario en \"{comment.contribution.title}\" ha recibido un voto {sign}.')
    flash('Voto registrado.', 'success')
    return redirect(url_for('view_contribution', contrib_id=comment.contribution_id))

# Rutas administrativas
@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@admin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    contrib_id = comment.contribution_id
    db.session.delete(comment)
    db.session.commit()
    flash('Comentario eliminado.', 'success')
    return redirect(url_for('view_contribution', contrib_id=contrib_id))

@app.route('/admin/mute/<int:user_id>')
@admin_required
def mute_user(user_id):
    target_user = User.query.get_or_404(user_id)
    current_admin_id = session.get('user_id')
    if target_user.id == current_admin_id:
        flash('No puedes cambiar tu propio estado de silencio.', 'danger')
        return redirect(url_for('profile', username=target_user.username))
    target_user.is_muted = not target_user.is_muted
    db.session.commit()
    action = 'silenciado' if target_user.is_muted else 'habilitado para comentar'
    flash(f'El usuario {target_user.username} ha sido {action}.', 'success')
    return redirect(url_for('profile', username=target_user.username))

@app.route('/admin')
@admin_required
def admin_dashboard():
    pending_contribs = Contribution.query.filter_by(approved=None).order_by(Contribution.created_at.asc()).all()
    return render_template('admin_dashboard.html', pending_contribs=pending_contribs)

@app.route('/admin/approve/<int:contrib_id>')
@admin_required
def approve_contribution(contrib_id):
    contrib = Contribution.query.get_or_404(contrib_id)
    if contrib.approved is not None:
        flash('Este aporte ya ha sido revisado.', 'info')
    else:
        contrib.approved = True
        contrib.author.points += 10
        db.session.commit()
        flash('Aporte aprobado.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:contrib_id>')
@admin_required
def reject_contribution(contrib_id):
    contrib = Contribution.query.get_or_404(contrib_id)
    if contrib.approved is not None:
        flash('Este aporte ya ha sido revisado.', 'info')
    else:
        contrib.approved = False
        db.session.commit()
        flash('Aporte rechazado.', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/ranking')
def ranking():
    users = User.query.order_by(User.points.desc()).all()
    return render_template('ranking.html', users=users)

@app.route('/follow/<username>')
@login_required
def follow_user(username):
    target = User.query.filter_by(username=username).first_or_404()
    current = User.query.get(session['user_id'])
    if target.id == current.id:
        flash('No puedes seguirte a ti mismo.', 'danger')
        return redirect(url_for('profile', username=target.username))
    existing = Follower.query.filter_by(follower_id=current.id, followed_id=target.id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        flash(f'Has dejado de seguir a {target.username}.', 'info')
    else:
        rel = Follower(follower_id=current.id, followed_id=target.id)
        db.session.add(rel)
        db.session.commit()
        add_notification(target.id, f'{current.username} ha empezado a seguirte.')
        flash(f'Ahora sigues a {target.username}.', 'success')
    return redirect(url_for('profile', username=target.username))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        location = request.form.get('location', '').strip()
        website = request.form.get('website', '').strip()
        user.bio = bio
        user.location = location
        user.website = website
        profile_pic = request.files.get('profile_pic')
        if profile_pic and allowed_file(profile_pic.filename):
            filename = save_file(profile_pic, PROFILE_FOLDER)
            user.profile_pic = filename
        db.session.commit()
        flash('Perfil actualizado.', 'success')
        return redirect(url_for('profile', username=user.username))
    return render_template('edit_profile.html', user=user)

@app.route('/notifications')
@login_required
def notifications():
    user = User.query.get(session['user_id'])
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.timestamp.desc()).all()
    for n in notifications:
        n.is_read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notifications)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    contributions = []
    if query:
        like_query = f"%{query}%"
        contributions = Contribution.query.filter(
            Contribution.approved == True,
            or_(Contribution.title.ilike(like_query), Contribution.description.ilike(like_query))
        ).order_by(Contribution.created_at.desc()).all()
    return render_template('search_results.html', contributions=contributions, query=query)

@app.route('/categories')
def categories_list():
    cats = Category.query.order_by(Category.name.asc()).all()
    return render_template('categories.html', categories=cats)

@app.route('/category/<int:category_id>')
def category_view(category_id):
    category = Category.query.get_or_404(category_id)
    contributions = Contribution.query.filter_by(category_id=category.id, approved=True).order_by(Contribution.created_at.desc()).all()
    return render_template('category.html', category=category, contributions=contributions)

@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(confirmation_token=token).first()
    if not user:
        flash('Enlace de confirmación inválido o caducado.', 'danger')
        return redirect(url_for('login'))
    if user.is_confirmed:
        flash('Tu cuenta ya ha sido confirmada.', 'info')
        return redirect(url_for('login'))
    user.is_confirmed = True
    user.confirmation_token = None
    db.session.commit()
    print("Nuevo usuario registrado:", user.email, "Token:", token)
    flash('¡Cuenta confirmada! Ahora puedes iniciar sesión.', 'success')
    return redirect(url_for('login'))

@app.route('/contribution/<int:contrib_id>/vote/<int:value>', methods=['POST'])
@login_required
def vote_contribution(contrib_id, value):
    if value not in (1, -1):
        abort(400)
    contrib = Contribution.query.get_or_404(contrib_id)
    if contrib.approved is not True:
        flash('Solo puedes votar aportes aprobados.', 'danger')
        return redirect(url_for('view_contribution', contrib_id=contrib.id))
    user_id = session['user_id']
    if contrib.user_id == user_id:
        flash('No puedes votar tu propio aporte.', 'danger')
        return redirect(url_for('view_contribution', contrib_id=contrib.id))
    existing_vote = ContributionVote.query.filter_by(user_id=user_id, contribution_id=contrib.id).first()
    if existing_vote:
        if existing_vote.value == value:
            flash('Ya has votado de esta manera.', 'info')
            return redirect(url_for('view_contribution', contrib_id=contrib.id))
        delta = value - existing_vote.value
        existing_vote.value = value
    else:
        existing_vote = ContributionVote(user_id=user_id, contribution_id=contrib.id, value=value)
        db.session.add(existing_vote)
        delta = value
    contrib.votes += delta
    contrib.author.points += delta
    db.session.commit()
    if delta != 0:
        sign = 'positivo' if value > 0 else 'negativo'
        add_notification(contrib.author.id, f'Tu aporte \"{contrib.title}\" ha recibido un voto {sign}.')
    flash('Voto registrado.', 'success')
    return redirect(url_for('view_contribution', contrib_id=contrib.id))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/chat')
@login_required
def chat():
    cutoff = datetime.utcnow() - timedelta(hours=24)
    messages = ChatMessage.query.filter(ChatMessage.timestamp >= cutoff).order_by(ChatMessage.timestamp.asc()).all()
    return render_template('chat.html', messages=messages)

@app.route('/privacidad')
def privacy():
    return render_template('privacy.html')


@app.template_filter('embed_video')
def embed_video(link: str) -> str:
    if not link:
        return ''
    try:
        if 'youtu.be/' in link:
            video_id = link.split('youtu.be/')[-1].split('?')[0]
            return f'https://www.youtube.com/embed/{video_id}'
        if 'youtube.com' in link:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            video_id = None
            if 'v' in qs:
                video_id = qs['v'][0]
            else:
                parts = parsed.path.split('/')
                if 'embed' in parts:
                    idx = parts.index('embed')
                    if idx + 1 < len(parts):
                        video_id = parts[idx + 1]
            if video_id:
                return f'https://www.youtube.com/embed/{video_id}'
        return link
    except Exception:
        return link


from flask_socketio import SocketIO, emit

socketio = SocketIO(app)

from datetime import datetime

@socketio.on('chat_message')
def handle_chat_message(message):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if user:
        # Eliminar mensajes antiguos
        cutoff = datetime.utcnow() - timedelta(hours=24)
        ChatMessage.query.filter(ChatMessage.timestamp < cutoff).delete()
        db.session.commit()

        # Guardar nuevo mensaje
        chat_entry = ChatMessage(username=user.username, message=message)
        db.session.add(chat_entry)
        db.session.commit()

        now = datetime.now().strftime("%H:%M")
        emit('chat_message', {
            'username': user.username,
            'message': message,
            'time': now
        }, broadcast=True)



class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    contributions = db.relationship('Contribution', backref='category', lazy=True)


def init_db():
    db.create_all()
    if Category.query.first() is None:
        default_categories = [
            'General', 'Cabras, gatos y otros bichos', 'Foticos',
            'Memes', 'WTF', 'Melafo', 'Darwin', 'Coño un enano', 'Mono con pistola'
        ]
        for cat_name in default_categories:
            db.session.add(Category(name=cat_name))
        db.session.commit()
# BLOQUE PRINCIPAL
if __name__ == '__main__':
    from eventlet import monkey_patch; monkey_patch()  # necesario en Render
    with app.app_context():
        db.create_all()
        init_db()
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))






