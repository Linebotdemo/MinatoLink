import os
import secrets
import pyotp
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SelectField, FileField, TextAreaField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from apscheduler.schedulers.background import BackgroundScheduler
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import smtplib
from email.mime.text import MIMEText
from weasyprint import HTML
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import requests
from io import BytesIO
import base64
import cloudinary
import cloudinary.uploader
import cloudinary.api
from flask import send_from_directory, redirect
from flask import after_this_request
from flask import request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user
from flask_login import login_required, current_user
from flask import request, redirect, url_for, flash
# 環境変数の読み込み
load_dotenv()

# Flaskアプリケーションの設定
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///isms.db')  # デフォルトはSQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'Uploads'  # ローカルファイル保存用（開発環境）
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'png', 'csv'}
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['ADMIN_EMAIL'] = os.getenv('ADMIN_EMAIL', 'admin@example.com')

# Cloudinary設定
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# データベースとログイン管理
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
jwt = JWTManager(app)
oauth = OAuth(app)

# Jinjaフィルタ
@app.template_filter('datetimeformat')
def datetimeformat(value):
    return value.strftime('%Y-%m-%d') if value else ''

# Google OAuth設定
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Slackクライアント
slack_client = WebClient(token=os.getenv('SLACK_TOKEN'))

# モデル
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    two_factor_secret = db.Column(db.String(100))
    subscription_plan = db.Column(db.String(50), default='free')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    github_token = db.Column(db.String(255))
    support_requests = db.relationship('SupportRequest', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='organization', lazy=True)
    policies = db.relationship('Policy', backref='organization', lazy=True)
    tasks = db.relationship('Task', backref='organization', lazy=True)
    evidences = db.relationship('Evidence', backref='organization', lazy=True)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    version = db.Column(db.Float, nullable=False, default=1.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    tags = db.relationship('Tag', secondary='policy_tag', backref='policies')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='未開始')
    assignee = db.Column(db.String(120))
    deadline = db.Column(db.DateTime)
    notify = db.Column(db.Boolean, default=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    comments = db.relationship('TaskComment', backref='task', lazy=True, cascade='all, delete-orphan', passive_deletes=True)

class TaskComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(255), nullable=False)  # CloudinaryのURLまたはローカルのパス
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(120), nullable=False)
    comment = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    tags = db.relationship('Tag', secondary='evidence_tag', backref='evidences')

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

class SupportRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255))  # CloudinaryのURLまたはローカルのパス
    status = db.Column(db.String(50), default='未対応')
    reply = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    answer = db.Column(db.Text, nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

policy_tag = db.Table('policy_tag',
    db.Column('policy_id', db.Integer, db.ForeignKey('policy.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

evidence_tag = db.Table('evidence_tag',
    db.Column('evidence_id', db.Integer, db.ForeignKey('evidence.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

# フォーム
class LoginForm(FlaskForm):
    email = StringField('メールアドレス', validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    totp = StringField('2FAコード')

class UserForm(FlaskForm):
    email = StringField('メールアドレス', validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    role = SelectField('役割', choices=[('user', 'ユーザー'), ('admin', '管理者'), ('auditor', '監査人')])
    organization_id = SelectField('組織', coerce=int)

class PolicyForm(FlaskForm):
    title = StringField('タイトル', validators=[DataRequired()])
    content = TextAreaField('内容', validators=[DataRequired()])
    tags = StringField('タグ')

class TaskForm(FlaskForm):
    control_id = StringField('管理策ID', validators=[DataRequired()])
    description = TextAreaField('説明', validators=[DataRequired()])
    status = SelectField('ステータス', choices=[('未開始', '未開始'), ('進行中', '進行中'), ('完了', '完了')])
    assignee = StringField('担当者')
    deadline = StringField('期限', validators=[DataRequired()])
    notify = BooleanField('リマインダー通知')

class TaskCommentForm(FlaskForm):
    content = TextAreaField('コメント', validators=[DataRequired()])

class EvidenceForm(FlaskForm):
    file = FileField('ファイル', validators=[FileRequired(), FileAllowed(['pdf', 'doc', 'docx', 'txt', 'png', 'csv'], '許可されたファイル形式のみ')])
    tags = StringField('タグ')
    comment = TextAreaField('コメント')

class OrganizationForm(FlaskForm):
    name = StringField('名前', validators=[DataRequired()])

class SupportForm(FlaskForm):
    subject = StringField('件名', validators=[DataRequired()])
    message = TextAreaField('メッセージ', validators=[DataRequired()])
    file = FileField('ファイル', validators=[FileAllowed(['pdf', 'doc', 'docx', 'txt', 'png', 'csv'], '許可されたファイル形式のみ')])

class ReplySupportForm(FlaskForm):
    request_id = IntegerField('リクエストID', validators=[DataRequired()])
    reply = TextAreaField('返信', validators=[DataRequired()])
    status = SelectField('ステータス', choices=[('未対応', '未対応'), ('対応中', '対応中'), ('対応済', '対応済')])

class ImportTasksForm(FlaskForm):
    file = FileField('CSVファイル', validators=[FileRequired(), FileAllowed(['csv'], 'CSVファイルのみ')])

class TagForm(FlaskForm):
    name = StringField('タグ名', validators=[DataRequired()])

# ログイン管理
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# HTTPSとヘッダー強制
def force_https_and_headers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.debug and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            return redirect(request.url.replace('http://', 'https://'))
        response = make_response(f(*args, **kwargs))
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://res.cloudinary.com; "  # Cloudinaryの画像対応
            "frame-src 'self';"
        )
        return response
    return decorated_function

# ファイル拡張子のチェック
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ローカルファイル保存（開発環境用）
def save_file_local(file, filename):
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    return file_path

# Cloudinaryファイルアップロード（本番環境用）
def upload_file_to_cloudinary(file):
    try:
        upload_result = cloudinary.uploader.upload(file, resource_type="auto")
        return upload_result['secure_url']
    except Exception as e:
        raise Exception(f"Cloudinaryへのアップロードに失敗しました: {str(e)}")

# Cloudinaryファイル削除（本番環境用）
def delete_file_from_cloudinary(public_id):
    try:
        cloudinary.uploader.destroy(public_id)
    except Exception as e:
        raise Exception(f"Cloudinaryからのファイル削除に失敗しました: {str(e)}")

@app.after_request
def remove_x_frame_options(response):
    response.headers.pop('X-Frame-Options', None)
    response.headers['Content-Security-Policy'] = (
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
    )
    return response


# ルート
@app.route('/')
@force_https_and_headers
def index():
    if current_user.is_authenticated:
        if current_user.email == app.config['ADMIN_EMAIL']:
            return redirect(url_for('manage_users'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@force_https_and_headers
def login():
    if current_user.is_authenticated:
        if current_user.email == app.config['ADMIN_EMAIL']:
            return redirect(url_for('manage_users'))
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.two_factor_secret:
                totp = pyotp.TOTP(user.two_factor_secret)
                if not totp.verify(form.totp.data):
                    flash('無効な2FAコードです')
                    return render_template('base.html', form=form, page='login')
            login_user(user)
            db.session.add(AuditLog(user_id=user.id, action='login', details=f'ユーザー {user.email} がログインしました'))
            db.session.commit()
            if user.email == app.config['ADMIN_EMAIL']:
                return redirect(url_for('manage_users'))
            return redirect(url_for('dashboard'))
        flash('メールアドレスまたはパスワードが無効です')
    return render_template('base.html', form=form, page='login')

@app.route('/google_login')
@force_https_and_headers
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/authorize')
@force_https_and_headers
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    user = User.query.filter_by(email=user_info['email']).first()
    if user:
        login_user(user)
        db.session.add(AuditLog(user_id=user.id, action='google_login', details=f'ユーザー {user.email} がGoogleでログインしました'))
        db.session.commit()
        if user.email == app.config['ADMIN_EMAIL']:
            return redirect(url_for('manage_users'))
        return redirect(url_for('dashboard'))
    flash('アカウントが見つかりません。運営者にユーザー作成を依頼してください。')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
@force_https_and_headers
def logout():
    db.session.add(AuditLog(user_id=current_user.id, action='logout', details=f'ユーザー {current_user.email} がログアウトしました'))
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def setup_2fa():
    if current_user.two_factor_secret:
        flash('2FAはすでに設定されています')
        return redirect(url_for('dashboard'))
    secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(current_user.email, issuer_name='ISMSサービス')
    if request.method == 'POST':
        totp = pyotp.TOTP(secret)
        if totp.verify(request.form['totp']):
            current_user.two_factor_secret = secret
            db.session.add(AuditLog(user_id=current_user.id, action='setup_2fa', details=f'ユーザー {current_user.email} が2FAを設定しました'))
            db.session.commit()
            flash('2FAが設定されました')
            return redirect(url_for('dashboard'))
        flash('無効なコードです')
    return render_template('base.html', totp_uri=totp_uri, page='setup_2fa')

@app.route('/dashboard')
@login_required
@force_https_and_headers
def dashboard():
    tasks = Task.query.filter_by(organization_id=current_user.organization_id).all()
    policies = Policy.query.filter_by(organization_id=current_user.organization_id).all()
    evidences = Evidence.query.filter_by(organization_id=current_user.organization_id).all()
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(5).all()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).limit(5).all()
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == '完了'])
    stats = {
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'in_progress_tasks': len([t for t in tasks if t.status == '進行中']),
        'not_started_tasks': len([t for t in tasks if t.status == '未開始']),
        'completed_percent': round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 1)
    }
    calendar_attributes = [
        {
            'key': task.id,
            'highlight': 'green' if task.status == '完了' else 'red' if task.status == '未開始' else 'yellow',
            'dates': task.deadline,
            'popover': {'label': f"{task.control_id}: {task.description}"}
        }
        for task in tasks if task.deadline
    ]
    return render_template('base.html', tasks=tasks, policies=policies, evidences=evidences, stats=stats,
                           calendar_attributes=calendar_attributes, recent_logs=recent_logs, notifications=notifications,
                           page='dashboard', form=EvidenceForm())

@app.route('/policies', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def policies():
    form = PolicyForm()
    if current_user.role == 'auditor':
        flash('監査人はポリシーを編集できません')
        return redirect(url_for('policies'))
    if form.validate_on_submit():
        existing_policy = Policy.query.filter_by(title=form.title.data, organization_id=current_user.organization_id).first()
        version = 1.0
        if existing_policy:
            version = existing_policy.version + 0.1
        tags = [Tag.query.filter_by(name=tag.strip()).first() or Tag(name=tag.strip()) for tag in form.tags.data.split(',') if tag.strip()]
        for tag in tags:
            if tag not in db.session:
                db.session.add(tag)
        policy = Policy(
            title=form.title.data,
            content=form.content.data,
            version=version,
            organization_id=current_user.organization_id,
            tags=tags
        )
        db.session.add(policy)
        db.session.add(AuditLog(user_id=current_user.id, action='create_policy', details=f'ポリシー {policy.title} (v{policy.version}) を作成しました'))
        db.session.commit()
        flash('ポリシーが作成されました')
        return redirect(url_for('policies'))
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'title')
    policies_query = Policy.query.filter_by(organization_id=current_user.organization_id)
    if search:
        policies_query = policies_query.filter(Policy.title.ilike(f'%{search}%') | Policy.content.ilike(f'%{search}%'))
    if sort == 'created_at':
        policies_query = policies_query.order_by(Policy.created_at.desc())
    elif sort == 'version':
        policies_query = policies_query.order_by(Policy.version.desc())
    else:
        policies_query = policies_query.order_by(Policy.title)
    policies = policies_query.all()
    sample_policy = "# サンプルポリシー\nこのポリシーは例です。ISO27001に基づく情報セキュリティ管理策を定義します。"
    return render_template('base.html', form=form, policies=policies, sample_policy=sample_policy, page='policies')

@app.route('/edit_policy/<int:policy_id>', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def edit_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('policies'))
    if current_user.role == 'auditor':
        flash('監査人はポリシーを編集できません')
        return redirect(url_for('policies'))
    form = PolicyForm()
    if form.validate_on_submit():
        policy.title = form.title.data
        policy.content = form.content.data
        policy.version += 0.1
        policy.tags = [Tag.query.filter_by(name=tag.strip()).first() or Tag(name=tag.strip()) for tag in form.tags.data.split(',') if tag.strip()]
        for tag in policy.tags:
            if tag not in db.session:
                db.session.add(tag)
        db.session.add(AuditLog(user_id=current_user.id, action='edit_policy', details=f'ポリシー {policy.title} (v{policy.version}) を編集しました'))
        db.session.commit()
        flash('ポリシーが更新されました')
        return redirect(url_for('policies'))
    return render_template('base.html', form=form, policy=policy, page='edit_policy')

@app.route('/delete_policy/<int:policy_id>')
@login_required
@force_https_and_headers
def delete_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('policies'))
    if current_user.role == 'auditor':
        flash('監査人はポリシーを削除できません')
        return redirect(url_for('policies'))
    db.session.delete(policy)
    db.session.add(AuditLog(user_id=current_user.id, action='delete_policy', details=f'ポリシー {policy.title} を削除しました'))
    db.session.commit()
    flash('ポリシーが削除されました')
    return redirect(url_for('policies'))

@app.route('/download_policy_pdf/<int:policy_id>')
@login_required
@force_https_and_headers
def download_policy_pdf(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('policies'))

    html_content = render_template('policy_pdf.html', policy=policy)
    pdf_file = f'policy_{policy.id}.pdf'
    HTML(string=html_content).write_pdf(pdf_file)

    db.session.add(AuditLog(
        user_id=current_user.id,
        action='download_policy_pdf',
        details=f'ポリシー {policy.title} のPDFを生成しました'
    ))
    db.session.commit()

    @after_this_request
    def remove_file(response):
        try:
            os.remove(pdf_file)
        except Exception as e:
            app.logger.warning(f"一時PDF削除失敗: {e}")
        return response

    return send_file(pdf_file, as_attachment=True)

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def tasks():
    form = TaskForm()
    import_form = ImportTasksForm()
    comment_form = TaskCommentForm()
    if current_user.role == 'auditor':
        flash('監査人はタスクを編集できません')
        return redirect(url_for('tasks'))
    if form.validate_on_submit():
        task = Task(
            control_id=form.control_id.data,
            description=form.description.data,
            status=form.status.data,
            assignee=form.assignee.data,
            deadline=datetime.strptime(form.deadline.data, '%Y-%m-%d') if form.deadline.data else None,
            notify=form.notify.data,
            organization_id=current_user.organization_id
        )
        db.session.add(task)
        db.session.add(AuditLog(user_id=current_user.id, action='create_task', details=f'タスク {task.control_id} を作成しました'))
        db.session.commit()
        flash('タスクが作成されました')
        return redirect(url_for('tasks'))
    if import_form.validate_on_submit():
        file = import_form.file.data
        if allowed_file(file.filename):
            try:
                df = pd.read_csv(file)
                for _, row in df.iterrows():
                    task = Task(
                        control_id=row['control_id'],
                        description=row['description'],
                        status=row['status'],
                        assignee=row.get('assignee'),
                        deadline=datetime.strptime(row['deadline'], '%Y-%m-%d') if pd.notnull(row.get('deadline')) else None,
                        notify=row.get('notify', False),
                        organization_id=current_user.organization_id
                    )
                    db.session.add(task)
                db.session.add(AuditLog(user_id=current_user.id, action='import_tasks', details=f'CSVからタスクをインポートしました'))
                db.session.commit()
                flash('タスクがインポートされました')
            except Exception as e:
                flash(f'CSVインポートに失敗しました: {str(e)}')
            return redirect(url_for('tasks'))
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    sort = request.args.get('sort', 'control_id')
    tasks_query = Task.query.filter_by(organization_id=current_user.organization_id)
    if search:
        tasks_query = tasks_query.filter(Task.control_id.ilike(f'%{search}%') | Task.description.ilike(f'%{search}%'))
    if status:
        tasks_query = tasks_query.filter_by(status=status)
    if sort == 'deadline':
        tasks_query = tasks_query.order_by(Task.deadline.desc())
    elif sort == 'status':
        tasks_query = tasks_query.order_by(Task.status)
    else:
        tasks_query = tasks_query.order_by(Task.control_id)
    tasks = tasks_query.all()
    return render_template('base.html', form=form, import_form=import_form, comment_form=comment_form, tasks=tasks, page='tasks')

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('tasks'))
    if current_user.role == 'auditor':
        flash('監査人はタスクを編集できません')
        return redirect(url_for('tasks'))
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.control_id = form.control_id.data
        task.description = form.description.data
        task.status = form.status.data
        task.assignee = form.assignee.data
        task.deadline = datetime.strptime(form.deadline.data, '%Y-%m-%d') if form.deadline.data else None
        task.notify = form.notify.data
        db.session.add(AuditLog(user_id=current_user.id, action='edit_task', details=f'タスク {task.control_id} を編集しました'))
        db.session.commit()
        flash('タスクが更新されました')
        return redirect(url_for('tasks'))
    return render_template('base.html', form=form, task=task, page='edit_task')

@app.route('/delete_task/<int:task_id>')
@login_required
@force_https_and_headers
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('tasks'))
    if current_user.role == 'auditor':
        flash('監査人はタスクを削除できません')
        return redirect(url_for('tasks'))
    db.session.delete(task)
    db.session.add(AuditLog(user_id=current_user.id, action='delete_task', details=f'タスク {task.control_id} を削除しました'))
    db.session.commit()
    flash('タスクが削除されました')
    return redirect(url_for('tasks'))

@app.route('/add_task_comment/<int:task_id>', methods=['POST'])
@login_required
@force_https_and_headers
def add_task_comment(task_id):
    task = Task.query.get_or_404(task_id)
    if task.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('tasks'))
    if current_user.role == 'auditor':
        flash('監査人はコメントを追加できません')
        return redirect(url_for('tasks'))
    form = TaskCommentForm()
    if form.validate_on_submit():
        comment = TaskComment(
            task_id=task_id,
            content=form.content.data,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.add(AuditLog(user_id=current_user.id, action='add_task_comment', details=f'タスク {task.control_id} にコメントを追加しました'))
        db.session.commit()
        flash('コメントが追加されました')
    return redirect(url_for('tasks'))

@app.route('/evidence', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def evidence():
    form = EvidenceForm()
    tag_form = TagForm()
    if current_user.role == 'auditor':
        flash('監査人は証跡をアップロードできません')
        return redirect(url_for('evidence'))
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
                # 開発環境: ローカルファイル保存
                file_path = save_file_local(file, filename)
            else:
                # 本番環境: Cloudinaryにアップロード
                file_path = upload_file_to_cloudinary(file)
            tags = [Tag.query.filter_by(name=tag.strip()).first() or Tag(name=tag.strip()) for tag in form.tags.data.split(',') if tag.strip()]
            for tag in tags:
                if tag not in db.session:
                    db.session.add(tag)
            evidence = Evidence(
                file_path=file_path,
                uploaded_by=current_user.email,
                comment=form.comment.data,
                organization_id=current_user.organization_id,
                tags=tags
            )
            db.session.add(evidence)
            db.session.add(AuditLog(user_id=current_user.id, action='upload_evidence', details=f'証跡 {filename} をアップロードしました'))
            db.session.commit()
            try:
                slack_client.chat_postMessage(
                    channel='#evidence_uploads',
                    text=f'新しい証跡がアップロードされました: {filename} by {current_user.email}'
                )
            except SlackApiError:
                flash('Slack通知に失敗しました')
            flash('証跡がアップロードされました')
            return redirect(url_for('evidence'))
    search = request.args.get('search', '')
    tags = request.args.get('tags', '')
    sort = request.args.get('sort', 'file_path')
    evidences_query = Evidence.query.filter_by(organization_id=current_user.organization_id)
    if search:
        evidences_query = evidences_query.filter(Evidence.file_path.ilike(f'%{search}%') | Evidence.comment.ilike(f'%{search}%'))
    if tags:
        tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]
        for tag in tag_list:
            evidences_query = evidences_query.filter(Evidence.tags.any(name=tag))
    if sort == 'timestamp':
        evidences_query = evidences_query.order_by(Evidence.timestamp.desc())
    else:
        evidences_query = evidences_query.order_by(Evidence.file_path)
    evidences = evidences_query.all()
    all_tags = Tag.query.all()
    return render_template('base.html', form=form, tag_form=tag_form, evidences=evidences, tags=all_tags, page='evidence')

@app.route('/delete_evidence/<int:evidence_id>')
@login_required
@force_https_and_headers
def delete_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    if evidence.organization_id != current_user.organization_id:
        flash('アクセス権限がありません')
        return redirect(url_for('evidence'))
    if current_user.role == 'auditor':
        flash('監査人は証跡を削除できません')
        return redirect(url_for('evidence'))
    if not app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        # 本番環境: Cloudinaryから削除
        public_id = evidence.file_path.split('/')[-1].split('.')[0]  # Cloudinaryのpublic_idを抽出
        try:
            delete_file_from_cloudinary(public_id)
        except Exception as e:
            flash(f'Cloudinaryからのファイル削除に失敗しました: {str(e)}')
    else:
        # 開発環境: ローカルファイル削除
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], evidence.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            flash('ローカルファイルの削除に失敗しました')
    db.session.delete(evidence)
    db.session.add(AuditLog(user_id=current_user.id, action='delete_evidence', details=f'証跡 {evidence.file_path} を削除しました'))
    db.session.commit()
    flash('証跡が削除されました')
    return redirect(url_for('evidence'))

@app.route('/preview_evidence')
@login_required
@force_https_and_headers
def preview_evidence():
    file_path = request.args.get('file', '').replace('\\', '/')

    # ファイル名だけを抽出（ディレクトリ含まれていてもOKにする）
    filename = os.path.basename(file_path)

    # DB照合を「ファイル名部分」だけで行うように修正
    evidence = Evidence.query.filter(
        Evidence.file_path.like(f"%{filename}"),
        Evidence.organization_id == current_user.organization_id
    ).first()

    if not evidence:
        return '<p>アクセス権限がありませんまたはファイルが見つかりません</p>'

    # Cloudinary or Local 判定（httpならCloudinary）
    if file_path.startswith('http'):
        response = requests.get(file_path)
        if response.status_code != 200:
            return '<p>ファイルの取得に失敗しました</p>'
        file_content = response.content
    else:
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  # ← ファイル名だけでOK
        if not os.path.exists(local_path):
            return '<p>ファイルが見つかりません</p>'
        with open(local_path, 'rb') as f:
            file_content = f.read()

    if filename.endswith('.pdf'):
        return send_file(BytesIO(file_content), mimetype='application/pdf', download_name='preview.pdf', as_attachment=False)
    elif filename.endswith('.png'):
        encoded = base64.b64encode(file_content).decode('utf-8')
        return f'<img src="data:image/png;base64,{encoded}" style="max-width: 100%;">'
    else:
        return '<p>プレビュー非対応のファイル形式です</p>'




@app.route('/manage_tags', methods=['POST'])
@login_required
@force_https_and_headers
def manage_tags():
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('evidence'))
    form = TagForm()
    if form.validate_on_submit():
        tag = Tag(name=form.name.data)
        db.session.add(tag)
        db.session.add(AuditLog(user_id=current_user.id, action='create_tag', details=f'タグ {tag.name} を作成しました'))
        db.session.commit()
        flash('タグが追加されました')
    return redirect(url_for('evidence'))

@app.route('/delete_tag/<int:tag_id>')
@login_required
@force_https_and_headers
def delete_tag(tag_id):
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('evidence'))
    tag = Tag.query.get_or_404(tag_id)
    db.session.delete(tag)
    db.session.add(AuditLog(user_id=current_user.id, action='delete_tag', details=f'タグ {tag.name} を削除しました'))
    db.session.commit()
    flash('タグが削除されました')
    return redirect(url_for('evidence'))

@app.route('/fetch_external_evidence', methods=['POST'])
@login_required
@force_https_and_headers
def fetch_external_evidence():
    if current_user.role == 'auditor':
        flash('監査人は証跡を取得できません')
        return redirect(url_for('evidence'))

    evidence_type = request.form.get('evidence_type')

    if evidence_type == 'github':
        token = current_user.github_token  # ✅ Userモデルにgithub_tokenが必要
        if not token:
            flash('GitHub連携がされていません')
            return redirect(url_for('integrations'))

        headers = {'Authorization': f'token {token}'}
        response = requests.get('https://api.github.com/user/repos', headers=headers)
        response.encoding = 'utf-8'  # ✅ 文字化け対策を追加！

        if response.status_code == 200:
            repos = response.json()
            for repo in repos:
                evidence = Evidence(
                    file_path=repo['html_url'],
                    uploaded_by=current_user.email,
                    comment=f'GitHubリポジトリ: {repo["name"]}',
                    organization_id=current_user.organization_id
                )
                db.session.add(evidence)

            db.session.add(AuditLog(
                user_id=current_user.id,
                action='fetch_github_evidence',
                details='GitHubから証跡を取得しました'
            ))
            db.session.commit()
            flash('GitHub証跡が取得されました')
        else:
            flash('GitHub証跡の取得に失敗しました')
            db.session.add(Notification(
                user_id=current_user.id,
                message='GitHub証跡の取得に失敗しました'
            ))
            db.session.commit()

    elif evidence_type == 'slack':
        try:
            result = slack_client.files_list()
            for file in result['files']:
                evidence = Evidence(
                    file_path=file['url_private'],
                    uploaded_by=current_user.email,
                    comment=f'Slackファイル: {file["name"]}',
                    organization_id=current_user.organization_id
                )
                db.session.add(evidence)

            db.session.add(AuditLog(
                user_id=current_user.id,
                action='fetch_slack_evidence',
                details='Slackから証跡を取得しました'
            ))
            db.session.commit()
            flash('Slack証跡が取得されました')
        except SlackApiError:
            flash('Slack証跡の取得に失敗しました')
            db.session.add(Notification(
                user_id=current_user.id,
                message='Slack証跡の取得に失敗しました'
            ))
            db.session.commit()

    return redirect(url_for('evidence'))




@app.route('/auditor_view')
@login_required
@force_https_and_headers
def auditor_view():
    if current_user.role != 'auditor':
        flash('監査人権限が必要です')
        return redirect(url_for('dashboard'))
    tasks = Task.query.filter_by(organization_id=current_user.organization_id).all()
    policies = Policy.query.filter_by(organization_id=current_user.organization_id).all()
    evidences = Evidence.query.filter_by(organization_id=current_user.organization_id).all()
    return render_template('base.html', tasks=tasks, policies=policies, evidences=evidences, page='auditor_view')

@app.route('/create_organization', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def create_organization():
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('dashboard'))
    form = OrganizationForm()
    if form.validate_on_submit():
        org = Organization(name=form.name.data)
        db.session.add(org)
        db.session.add(AuditLog(user_id=current_user.id, action='create_organization', details=f'組織 {org.name} を作成しました'))
        db.session.commit()
        flash('組織が作成されました')
        return redirect(url_for('create_organization'))
    return render_template('base.html', form=form, page='create_organization')

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def manage_users():
    if current_user.email != app.config['ADMIN_EMAIL']:
        flash('運営者権限が必要です')
        return redirect(url_for('dashboard'))

    form = UserForm()
    form.organization_id.choices = [(org.id, org.name) for org in Organization.query.all()]
    if not form.organization_id.choices:
        default_org = Organization(name='デフォルト組織')
        db.session.add(default_org)
        db.session.commit()
        form.organization_id.choices = [(default_org.id, default_org.name)]

    if form.validate_on_submit():
        user = User(
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            role=form.role.data,
            organization_id=form.organization_id.data
        )
        db.session.add(user)
        db.session.commit()
        try:
            msg = MIMEText(f'アカウントが作成されました。メール: {form.email.data}, パスワード: {form.password.data}')
            msg['Subject'] = 'ISMSサービス アカウント作成'
            msg['From'] = os.getenv('SMTP_USER')
            msg['To'] = form.email.data
            with smtplib.SMTP(os.getenv('SMTP_SERVER'), os.getenv('SMTP_PORT')) as server:
                server.starttls()
                server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASSWORD'))
                server.send_message(msg)
            flash('ユーザーが作成され、通知メールが送信されました')
        except Exception:
            flash('ユーザーは作成されました')
        return redirect(url_for('manage_users'))

    # ✅ 最後に必ず return を書く
    users = User.query.all()
    return render_template('base.html', form=form, users=users, page='manage_users')



@app.route('/audit_log')
@login_required
@force_https_and_headers
def audit_log():
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('dashboard'))
    logs = AuditLog.query.all()
    return render_template('base.html', logs=logs, page='audit_log')

@app.route('/export_audit_log/<format>')
@login_required
@force_https_and_headers
def export_audit_log(format):
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('dashboard'))
    logs = AuditLog.query.all()
    if format == 'csv':
        output = 'ユーザーID,アクション,詳細,タイムスタンプ\n'
        for log in logs:
            output += f'"{log.user.email}","{log.action}","{log.details}","{log.timestamp}"\n'
        return send_file(
            BytesIO(output.encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='audit_log.csv'
        )
    elif format == 'pdf':
        html_content = render_template('report.html', logs=logs)
        pdf_file = 'audit_log.pdf'
        HTML(string=html_content).write_pdf(pdf_file)
        return send_file(pdf_file, as_attachment=True)
    flash('無効なフォーマットです')
    return redirect(url_for('audit_log'))

@app.route('/support', methods=['GET', 'POST'])
@login_required
@force_https_and_headers
def support():
    form = SupportForm()
    reply_form = ReplySupportForm()
    if form.validate_on_submit():
        file_path = None
        if form.file.data and allowed_file(form.file.data.filename):
            file = form.file.data
            filename = secure_filename(file.filename)
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
                # 開発環境: ローカルファイル保存
                file_path = save_file_local(file, filename)
            else:
                # 本番環境: Cloudinaryにアップロード
                file_path = upload_file_to_cloudinary(file)
            support_request = SupportRequest(
                user_id=current_user.id,
                subject=form.subject.data,
                message=form.message.data,
                file_path=file_path
            )
            db.session.add(support_request)
            db.session.add(AuditLog(user_id=current_user.id, action='submit_support', details=f'サポートリクエスト: {form.subject.data} を送信しました'))
            db.session.commit()
            try:
                slack_client.chat_postMessage(
                    channel='#support',
                    text=f'サポートリクエスト: {form.subject.data}\nメッセージ: {form.message.data}\nFrom: {current_user.email}'
                )
                flash('サポートリクエストが送信されました')
            except SlackApiError:
                flash('サポートリクエストの送信に失敗しました')
                db.session.add(Notification(user_id=current_user.id, message='サポートリクエストのSlack通知に失敗しました'))
                db.session.commit()
            return redirect(url_for('support'))
    support_requests = SupportRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('base.html', form=form, reply_form=reply_form, support_requests=support_requests, page='support')

@app.route('/reply_support', methods=['POST'])
@login_required
@force_https_and_headers
def reply_support():
    if current_user.role != 'admin':
        flash('管理者権限が必要です')
        return redirect(url_for('support'))
    form = ReplySupportForm()
    if form.validate_on_submit():
        support_request = SupportRequest.query.get_or_404(form.request_id.data)
        support_request.reply = form.reply.data
        support_request.status = form.status.data
        db.session.add(AuditLog(user_id=current_user.id, action='reply_support', details=f'サポートリクエスト {support_request.id} に返信しました'))
        db.session.commit()
        flash('サポートリクエストに返信しました')
    return redirect(url_for('support'))

@app.route('/download_support_file/<int:request_id>')
@login_required
@force_https_and_headers
def download_support_file(request_id):
    support_request = SupportRequest.query.get_or_404(request_id)
    if support_request.user_id != current_user.id and current_user.role != 'admin':
        flash('アクセス権限がありません')
        return redirect(url_for('support'))
    if not support_request.file_path:
        flash('ファイルが存在しません')
        return redirect(url_for('support'))
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        # 開発環境: ローカルファイル
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], support_request.file_path)
        if not os.path.exists(file_path):
            flash('ファイルが見つかりません')
            return redirect(url_for('support'))
        return send_file(file_path, as_attachment=True, download_name=support_request.file_path)
    else:
        # 本番環境: Cloudinaryから取得
        response = requests.get(support_request.file_path)
        if response.status_code != 200:
            flash('ファイルの取得に失敗しました')
            return redirect(url_for('support'))
        return send_file(
            BytesIO(response.content),
            as_attachment=True,
            download_name=support_request.file_path.split('/')[-1]
        )

@app.route('/faq')
@login_required
@force_https_and_headers
def faq():
    faqs = FAQ.query.all()
    return render_template('base.html', faqs=faqs, page='faq')  # faq.htmlからbase.htmlに変更（テンプレート統一）

@app.route('/generate_report')
@login_required
@force_https_and_headers
def generate_report():
    tasks = Task.query.filter_by(organization_id=current_user.organization_id).all()
    policies = Policy.query.filter_by(organization_id=current_user.organization_id).all()
    evidences = Evidence.query.filter_by(organization_id=current_user.organization_id).all()
    html_content = render_template('report.html', tasks=tasks, policies=policies, evidences=evidences)
    pdf_file = f'report_{current_user.id}.pdf'
    HTML(string=html_content).write_pdf(pdf_file)
    db.session.add(AuditLog(user_id=current_user.id, action='generate_report', details='レポートを生成しました'))
    db.session.commit()
    return send_file(pdf_file, as_attachment=True)

@app.route('/set_theme', methods=['POST'])
@login_required
@force_https_and_headers
def set_theme():
    theme = request.json.get('theme')
    session['theme'] = theme
    return jsonify({'message': 'テーマが設定されました'})

# APIエンドポイント
@app.route('/api/policies', methods=['GET', 'POST'])
@jwt_required()
@force_https_and_headers
def api_policies():
    if request.method == 'GET':
        policies = Policy.query.filter_by(organization_id=current_user.organization_id).all()
        return jsonify([{'id': p.id, 'title': p.title, 'content': p.content, 'version': p.version, 'created_at': p.created_at.isoformat(), 'tags': [t.name for t in p.tags]} for p in policies])
    if current_user.role == 'auditor':
        return jsonify({'error': '監査人はポリシーを編集できません'}), 403
    data = request.get_json()
    existing_policy = Policy.query.filter_by(title=data['title'], organization_id=current_user.organization_id).first()
    version = 1.0
    if existing_policy:
        version = existing_policy.version + 0.1
    tags = [Tag.query.filter_by(name=tag.strip()).first() or Tag(name=tag.strip()) for tag in data.get('tags', '').split(',') if tag.strip()]
    for tag in tags:
        if tag not in db.session:
            db.session.add(tag)
    policy = Policy(
        title=data['title'],
        content=data['content'],
        version=version,
        organization_id=current_user.organization_id,
        tags=tags
    )
    db.session.add(policy)
    db.session.add(AuditLog(user_id=current_user.id, action='api_create_policy', details=f'API経由でポリシー {policy.title} (v{policy.version}) を作成しました'))
    db.session.commit()
    return jsonify({'message': 'ポリシーが作成されました', 'id': policy.id}), 201

@app.route('/api/tasks', methods=['GET', 'POST'])
@jwt_required()
@force_https_and_headers
def api_tasks():
    if request.method == 'GET':
        tasks = Task.query.filter_by(organization_id=current_user.organization_id).all()
        return jsonify([{'id': t.id, 'control_id': t.control_id, 'description': t.description, 'status': t.status, 'assignee': t.assignee, 'deadline': t.deadline.isoformat() if t.deadline else None, 'notify': t.notify, 'comments': [{'content': c.content, 'timestamp': c.timestamp.isoformat()} for c in t.comments]} for t in tasks])
    if current_user.role == 'auditor':
        return jsonify({'error': '監査人はタスクを編集できません'}), 403
    if request.content_type == 'multipart/form-data':
        form = ImportTasksForm()
        if form.validate_on_submit():
            file = form.file.data
            if allowed_file(file.filename):
                try:
                    df = pd.read_csv(file)
                    for _, row in df.iterrows():
                        task = Task(
                            control_id=row['control_id'],
                            description=row['description'],
                            status=row['status'],
                            assignee=row.get('assignee'),
                            deadline=datetime.strptime(row['deadline'], '%Y-%m-%d') if pd.notnull(row.get('deadline')) else None,
                            notify=row.get('notify', False),
                            organization_id=current_user.organization_id
                        )
                        db.session.add(task)
                    db.session.add(AuditLog(user_id=current_user.id, action='api_import_tasks', details='API経由でCSVからタスクをインポートしました'))
                    db.session.commit()
                    return jsonify({'message': 'タスクがインポートされました'}), 201
                except Exception as e:
                    return jsonify({'error': f'CSVインポートに失敗しました: {str(e)}'}), 400
    data = request.get_json()
    task = Task(
        control_id=data['control_id'],
        description=data['description'],
        status=data['status'],
        assignee=data.get('assignee'),
        deadline=datetime.strptime(data['deadline'], '%Y-%m-%d') if data.get('deadline') else None,
        notify=data.get('notify', False),
        organization_id=current_user.organization_id
    )
    db.session.add(task)
    db.session.add(AuditLog(user_id=current_user.id, action='api_create_task', details=f'API経由でタスク {task.control_id} を作成しました'))
    db.session.commit()
    return jsonify({'message': 'タスクが作成されました', 'id': task.id}), 201

@app.route('/api/evidences', methods=['GET'])
@jwt_required()
@force_https_and_headers
def api_evidences():
    evidences = Evidence.query.filter_by(organization_id=current_user.organization_id).all()
    return jsonify([{'id': e.id, 'file_path': e.file_path, 'timestamp': e.timestamp.isoformat(), 'uploaded_by': e.uploaded_by, 'comment': e.comment, 'tags': [t.name for t in e.tags]} for e in evidences])



@app.route('/evidence/download/<int:evidence_id>')
@login_required
def download_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)

    # Cloudinary URLのときはリダイレクト
    if evidence.file_path.startswith('http'):
        return redirect(evidence.file_path)

    # ローカル保存時の処理
    directory = os.path.join(app.root_path, 'evidence_files')  # 保存ディレクトリ
    filename = os.path.basename(evidence.file_path)
    return send_from_directory(directory=directory, path=filename, as_attachment=True)









@app.route('/slack/login')
def slack_login():
    slack_client_id = os.getenv("SLACK_CLIENT_ID")
    redirect_uri = url_for('slack_callback', _external=True)
    auth_url = (
        f"https://slack.com/oauth/v2/authorize"
        f"?client_id={slack_client_id}"
        f"&scope=channels:read,chat:write,users:read"
        f"&redirect_uri={redirect_uri}"
    )
    return redirect(auth_url)

@app.route('/slack/callback')
def slack_callback():
    code = request.args.get('code')
    if not code:
        flash("Slack連携に失敗しました（codeがありません）", "danger")
        return redirect(url_for('integrations'))

    token_url = "https://slack.com/api/oauth.v2.access"
    data = {
        "client_id": os.getenv("SLACK_CLIENT_ID"),
        "client_secret": os.getenv("SLACK_CLIENT_SECRET"),
        "code": code,
        "redirect_uri": url_for('slack_callback', _external=True),
    }
    res = requests.post(token_url, data=data)
    token_data = res.json()

    if not token_data.get("ok"):
        flash("Slack連携に失敗しました: " + token_data.get("error", "不明なエラー"), "danger")
        return redirect(url_for('integrations'))

    access_token = token_data["access_token"]
    team_name = token_data["team"]["name"]

    # 任意: DB保存
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO slack_integrations (organization_id, access_token, team_name) VALUES (?, ?, ?)",
        (current_user.organization_id, access_token, team_name)
    )
    db.commit()

    flash(f"Slackチーム「{team_name}」と連携しました", "success")
    return redirect(url_for('integrations'))


@app.route('/github/login')
@login_required
def github_login():
    redirect_uri = url_for('github_callback', _external=True).replace("http://", "https://")
    github_auth_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={os.getenv('GITHUB_CLIENT_ID')}"
        f"&redirect_uri={redirect_uri}"
        "&scope=repo"
    )
    return redirect(github_auth_url)





@app.route('/github/callback')
@login_required
def github_callback():
    code = request.args.get("code")
    token_url = "https://github.com/login/oauth/access_token"
    headers = {'Accept': 'application/json'}
    data = {
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "code": code
    }
    res = requests.post(token_url, headers=headers, data=data)
    token_json = res.json()
    access_token = token_json.get("access_token")

    if not access_token:
        flash("GitHub連携に失敗しました")
        return redirect(url_for("integrations"))

    # ✅ db.sessionで保存
    user = User.query.get(current_user.id)
    user.github_token = access_token
    db.session.commit()

    flash("GitHub連携が完了しました")
    return redirect(url_for("integrations"))


@app.route('/integrations')
@login_required
def integrations():
    return render_template('integrations.html', page='integrations')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('新しいパスワードが一致しません', 'danger')
        return redirect(url_for('integrations'))

    # ORMで現在のユーザーを取得
    user = User.query.get(current_user.id)

    if not user or not check_password_hash(user.password, old_password):
        flash('現在のパスワードが正しくありません', 'danger')
        return redirect(url_for('integrations'))

    user.password = generate_password_hash(new_password)
    db.session.commit()

    flash('パスワードを変更しました', 'success')
    return redirect(url_for('integrations'))



# app.py の最後の方に追記するのがシンプル

def fetch_github_commits(token):
    repo = "YOUR_ORG/YOUR_REPO"
    url = f"https://api.github.com/repos/{repo}/commits"
    headers = {'Authorization': f'token {token}'}
    res = requests.get(url, headers=headers)

    if res.status_code != 200:
        print("❌ GitHub APIエラー:", res.text)
        return

    for commit in res.json():
        message = commit['commit']['message']
        author = commit['commit']['author']['name']
        timestamp = commit['commit']['author']['date']

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO evidence (source, content, timestamp, author) VALUES (?, ?, ?, ?)",
            ("GitHub", message, timestamp, author)
        )
        db.commit()




# スケジューラ
def send_task_reminders():
    with app.app_context():
        tasks = Task.query.filter(Task.deadline <= datetime.utcnow() + timedelta(days=1), Task.notify == True).all()
        for task in tasks:
            if task.assignee:
                try:
                    slack_client.chat_postMessage(
                        channel=f'@{task.assignee}',
                        text=f'タスク「{task.description}」の期限が近づいています: {task.deadline}'
                    )
                    db.session.add(Notification(user_id=task.organization.users[0].id, message=f'タスク「{task.description}」の期限が近づいています'))
                except SlackApiError:
                    db.session.add(Notification(user_id=task.organization.users[0].id, message=f'タスク「{task.description}」のリマインダー通知に失敗しました'))
        db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(send_task_reminders, 'interval', hours=24)
scheduler.start()

# データベース初期化
with app.app_context():
    db.create_all()
    if not Organization.query.first():
        default_org = Organization(name='デフォルト組織')
        db.session.add(default_org)
        db.session.commit()
    if not User.query.filter_by(email=app.config['ADMIN_EMAIL']).first():
        admin_user = User(
            email=app.config['ADMIN_EMAIL'],
            password=generate_password_hash('admin_password'),
            role='admin',
            organization_id=Organization.query.first().id
        )
        db.session.add(admin_user)
        db.session.commit()
    if not FAQ.query.first():
        faqs = [
            FAQ(question='証跡のアップロード方法は？', answer='ダッシュボードまたは証跡ページからファイルをドラッグ＆ドロップしてください。'),
            FAQ(question='タスクの期限通知を有効にするには？', answer='タスク作成時に「リマインダー通知を有効」をチェックしてください。'),
            FAQ(question='ポリシーのバージョンを確認するには？', answer='ポリシー一覧でバージョン番号を確認できます。')
        ]
        db.session.add_all(faqs)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
