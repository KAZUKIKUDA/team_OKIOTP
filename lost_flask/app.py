# app.py (Star Rating Update)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import uuid
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from config import Config

# --- Application Setup ---
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインしてください。"
login_manager.login_message_category = "danger"

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    teacher = db.Column(db.String(100), nullable=False)
    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")
    @property
    def star_rating(self):
        if not self.reviews: return "評価なし"
        # ▼▼▼ Handle float ratings ▼▼▼
        avg = sum(r.rating for r in self.reviews) / len(self.reviews)
        return f"{avg:.2f}"

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=True)
    # ▼▼▼ Changed rating to Float to allow 0.5 increments ▼▼▼
    rating = db.Column(db.Float, nullable=False)
    attendance = db.Column(db.String(10), nullable=False)
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes (Authentication) ---

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

        if User.query.filter_by(username=username).first():
            flash('そのユーザー名は既に使用されています。', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('このメールアドレスは既に使用されています。', 'danger')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        token = s.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url)
        msg = Message('講義レビュー | メールアドレスの確認', recipients=[email], html=html)
        mail.send(msg)
        
        flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('認証リンクが無効か、有効期限が切れています。', 'danger')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first_or_4_04()
    if user.is_verified:
        flash('このアカウントは既に認証済みです。', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        flash('メール認証が完了しました。ログインしてください。', 'success')
        
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('メールアドレスまたはパスワードが正しくありません。', 'danger')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('アカウントがまだ認証されていません。送信されたメールを確認してください。', 'warning')
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/guest_login', methods=['GET', 'POST'])
def guest_login():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash('お名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))

        if User.query.filter_by(username=username).first():
            flash('その名前は登録済みのユーザーが使用しています。別の名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))

        guest_email = f"guest_{uuid.uuid4().hex}@demo.com"
        hashed_password = generate_password_hash(f"guest_pw_{uuid.uuid4().hex}")
        
        new_guest_user = User(
            username=username, 
            email=guest_email, 
            password=hashed_password, 
            is_verified=True
        )
        db.session.add(new_guest_user)
        db.session.commit()
        
        login_user(new_guest_user)
        flash(f'{username}さんとしてゲストログインしました。', 'success')
        return redirect(url_for('index'))

    return render_template('guest_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Routes (Core App) ---

@app.route('/')
@login_required
def index():
    return render_template('top.html')
    
@app.route('/add', methods=['POST'])
@login_required
def add_course():
    name = request.form.get('name')
    teacher = request.form.get('teacher')
    if not name or not teacher:
        flash('講義名と先生の名前を入力してください。', 'danger')
        return redirect(url_for('index'))
    existing_course = Course.query.filter_by(name=name).first()
    if existing_course:
        flash('この講義は既に登録されています。', 'info')
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
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.get_or_404(id)
    return render_template('detail.html', course=course)

@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    # ▼▼▼ Get rating from form and convert to float ▼▼▼
    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')
    review_text = request.form.get('review')

    if not all([rating, attendance, test, report]):
        flash('評価、出欠、テスト、レポートの項目は必須です。', 'danger')
        return redirect(url_for('course_detail', id=id))

    new_review = Review(
        # ▼▼▼ Store rating as a float ▼▼▼
        rating=float(rating), 
        attendance=attendance,
        test=test, 
        report=report, 
        review=review_text,
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

