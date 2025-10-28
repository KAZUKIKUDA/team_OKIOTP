from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import uuid
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from config import Config
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError # <<< データベースエラー処理のためにインポート

# --- Application Setup ---
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

migrate = Migrate(app, db)

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
    
    # ▼▼▼ 修正 ▼▼▼
    # パスワードハッシュが150文字を超えるため、256文字に変更
    password = db.Column(db.String(256), nullable=False) 
    # ▲▲▲ 修正 ▲▲▲
    
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    teacher = db.Column(db.String(100), nullable=False)
    syllabus_url = db.Column(db.String(300), nullable=True)
    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")
    @property
    def star_rating(self):
        if not self.reviews: return "評価なし"
        avg = sum(r.rating for r in self.reviews) / len(self.reviews)
        return f"{avg:.2f}"

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Float, nullable=False) 
    attendance = db.Column(db.String(10), nullable=False)
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_format = db.Column(db.String(20), nullable=True)
    classroom = db.Column(db.String(100), nullable=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# --- Routes ---
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
            
        if User.query.filter_by(username=username).first():
            flash('そのユーザー名は既に使用されています。', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('このメールアドレスは既に使用されています。', 'danger')
            return redirect(url_for('register'))

        new_user = None # メール送信失敗時にロールバックするため
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit() 

            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('email/activate.html', confirm_url=confirm_url)
            msg = Message('講義レビュー | メールアドレスの確認', recipients=[email], html=html)
            
            app.logger.info("Attempting to send email...") # ログ追加
            mail.send(msg) # <<< タイムアウトする可能性
            app.logger.info("Email sent successfully.") # ログ追加
            
            flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
            return redirect(url_for('login'))

        except IntegrityError: 
            db.session.rollback() 
            if User.query.filter_by(username=username).first():
                flash('そのユーザー名は既に使用されています。 (エラー: IE-U)', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('このメールアドレスは既に使用されています。 (エラー: IE-E)', 'danger')
            else:
                flash('データベースエラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('register'))
            
        except Exception as e:
            # ▼▼▼ 修正 ▼▼▼
            # メール送信失敗などでエラーになった場合
            app.logger.error(f"Registration error: {e}") 
            
            # もしユーザー作成(commit)が成功した後にメール送信(send)で失敗した場合、
            # ユーザー作成を取り消す（ロールバック）
            if new_user:
                try:
                    db.session.rollback()
                    app.logger.info("User creation rolled back due to mail error.")
                except Exception as rb_e:
                    app.logger.error(f"Rollback failed: {rb_e}")
            
            flash(f'不明なエラー（{type(e).__name__}）が発生しました。管理者に連絡してください。', 'danger')
            return redirect(url_for('register'))
            # ▲▲▲ 修正 ▲▲▲

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('認証リンクが無効か、有効期限が切れています。', 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('ユーザーが見つかりません。', 'danger')
        return redirect(url_for('register'))

    if user.is_verified:
        flash('このアカウントは既に認証済みです。', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        flash('メール認証が完了しました。ログインしてください。', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
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
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))
        
    return render_template('login.html')

@app.route('/guest_login', methods=['GET', 'POST'])
def guest_login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash('お名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))
            
        if User.query.filter_by(username=username).first():
            flash('その名前は登録済みのユーザーが使用しています。別の名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))

        try:
            guest_email = f"guest_{uuid.uuid4().hex}@demo.com"
            hashed_password = generate_password_hash(f"guest_pw_{uuid.uuid4().hex}")
            new_guest_user = User(username=username, email=guest_email, password=hashed_password, is_verified=True)
            
            db.session.add(new_guest_user)
            db.session.commit() 

            login_user(new_guest_user)
            flash(f'{username}さんとしてゲストログインしました。', 'success')
            return redirect(url_for('index'))

        except IntegrityError: 
            db.session.rollback() 
            flash('その名前は直前に使用されました。別の名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Guest login error: {e}") # Renderのログに出力
            flash('不明なエラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('guest_login'))

    return render_template('guest_login.html')

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
    syllabus_url = request.form.get('syllabus_url')
    
    if not name or not teacher:
        flash('講義名と担当教員名は必須です。', 'danger')
        return redirect(url_for('index'))
        
    if not syllabus_url or not syllabus_url.startswith('https://tiglon.jim.u-ryukyu.ac.jp/portal/Public/Syllabus/'):
        flash('2025年度の正しいシラスURL (https://tiglon...で始まる) を入力してください。', 'danger')
        return redirect(url_for('index'))
        
    existing_course = Course.query.filter_by(name=name).first()
    if existing_course:
        flash('この講義名は既に登録されています。', 'info')
        return redirect(url_for('index'))
        
    try:
        new_course = Course(name=name, teacher=teacher, syllabus_url=syllabus_url)
        db.session.add(new_course)
        db.session.commit()
        flash('講義を登録しました。続けてレビューを追加できます。', 'success')
        return redirect(url_for('course_detail', id=new_course.id))
    except IntegrityError:
        db.session.rollback()
        flash('この講義名は既に登録されています。 (エラー: IE-C)', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add course error: {e}")
        flash('講義の登録中にエラーが発生しました。', 'danger')
        return redirect(url_for('index'))


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
    
    existing_review = Review.query.filter_by(course_id=id, user_id=current_user.id).first()
    if existing_review:
        flash('あなたはこの講義に既にレビューを投稿しています。', 'warning')
        return redirect(url_for('course_detail', id=id))

    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')
    course_format = request.form.get('course_format')
    classroom = request.form.get('classroom')
    review_text = request.form.get('review')
    
    if not all([rating, attendance, test, report, course_format]):
        flash('評価、出欠、テスト、レポート、授業形式の項目は必須です。', 'danger')
        return redirect(url_for('course_detail', id=id))
        
    try:
        rating_float = float(rating)
        if not (0 <= rating_float <= 5):
             flash('評価は0から5の間で入力してください。', 'danger')
             return redirect(url_for('course_detail', id=id))
    except ValueError:
        flash('評価の値が無効です。', 'danger')
        return redirect(url_for('course_detail', id=id))
        
    try:
        new_review = Review(
            rating=rating_float, attendance=attendance, test=test, report=report,
            course_format=course_format, classroom=classroom, review=review_text,
            course_id=course.id, author=current_user
        )
        db.session.add(new_review)
        db.session.commit()
        flash('レビューを投稿しました。', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add review error: {e}")
        flash('レビューの投稿中にエラーが発生しました。', 'danger')
        
    return redirect(url_for('course_detail', id=id))


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG', 'False').lower() == 'true')
