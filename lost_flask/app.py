# app.py (認証機能追加版)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from config import Config # config.py から設定をインポート

# --- アプリケーションの初期設定 ---
app = Flask(__name__)
app.config.from_object(Config) # Configクラスから設定を読み込む

db = SQLAlchemy(app)
mail = Mail(app) # Flask-Mailの初期化
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) # トークン生成用のシリアライザ

# Flask-Loginの初期設定
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "ログインしてください。"

# --- データベースモデル定義 ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    # ▼▼▼ メール認証ステータスカラムを追加 ▼▼▼
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    teacher = db.Column(db.String(100), nullable=False)
    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")

    @property
    def star_rating(self):
        if not self.reviews:
            return "評価なし"
        avg = sum(r.rating for r in self.reviews) / len(self.reviews)
        return f"{avg:.2f}"

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    attendance = db.Column(db.String(10), nullable=False)
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ルート定義 ---

@app.route('/')
@login_required
def index():
    return render_template('top.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        email_pattern = r'^e\d{6}@cs\.u-ryukyu\.ac\.jp$'
        if not re.match(email_pattern, email):
            flash('指定された形式の学内メールアドレスを使用してください。 (例: e235701@cs.u-ryukyu.ac.jp)', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('このメールアドレスは既に使用されています。', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # ▼▼▼ 認証メール送信処理 ▼▼▼
        token = s.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url)
        
        msg = Message('メールアドレスの確認', recipients=[email], html=html)
        mail.send(msg)
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

# ▼▼▼ メール認証を行うための新しいルート ▼▼▼
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # トークンの有効期限は1時間
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except SignatureExpired:
        flash('認証リンクの有効期限が切れています。再度、新規登録を行ってください。', 'danger')
        return redirect(url_for('register'))
    except BadTimeSignature:
        flash('無効な認証リンクです。', 'danger')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('このアカウントは既に認証済みです。', 'success')
    else:
        user.is_verified = True
        db.session.commit()
        flash('メール認証が完了しました。ログインしてください。', 'success')
        
    return redirect(url_for('login'))
# ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('メールアドレスまたはパスワードが正しくありません。', 'danger')
            return redirect(url_for('login'))

        # ▼▼▼ 認証済みかどうかのチェックを追加 ▼▼▼
        if not user.is_verified:
            flash('アカウントがまだ認証されていません。送信されたメールを確認してください。', 'danger')
            return redirect(url_for('login'))
        # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        login_user(user)
        return redirect(url_for('index'))
        
    return render_template('login.html')

# (以降の /logout, /add, /search, /course/<id>, /add_review/<id> は変更なし)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add_course():
    name = request.form.get('name')
    teacher = request.form.get('teacher')

    if not name or not teacher:
        flash('講義名と先生の名前を入力してください。', 'error')
        return redirect(url_for('index'))

    existing_course = Course.query.filter_by(name=name).first()
    if existing_course:
        flash('その講義は既に登録されています。', 'error')
        return redirect(url_for('index'))

    new_course = Course(name=name, teacher=teacher)
    db.session.add(new_course)
    db.session.commit()
    
    flash('講義を登録しました。レビューを追加してください。', 'success')
    return redirect(url_for('course_detail', id=new_course.id))

@app.route('/search', methods=['POST'])
@login_required
def search_course():
    search_term = request.form.get('search')
    if not search_term:
        results = Course.query.all()
    else:
        results = Course.query.filter(
            db.or_(
                Course.name.like(f'%{search_term}%'),
                Course.teacher.like(f'%{search_term}%')
            )
        ).all()
    return render_template('search.html', results=results)

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.get_or_404(id)
    return render_template('detail.html', course=course)

@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    review_text = request.form.get('review')
    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')

    if not all([review_text, rating, attendance, test, report]):
        flash('すべての項目を入力してください。', 'error')
        return redirect(url_for('course_detail', id=id))
    
    new_review = Review(
        review=review_text, 
        rating=int(rating), 
        attendance=attendance,
        test=test,
        report=report,
        course_id=course.id,
        author=current_user
    )
    db.session.add(new_review)
    db.session.commit()
    
    flash('レビューを投稿しました。', 'success')
    return redirect(url_for('course_detail', id=id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)