from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import uuid
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from config import Config
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
import os
import logging # ログ出力のため

# ▼▼▼ SendGrid のためのインポート ▼▼▼
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail
# ▲▲▲ SendGrid ▲▲▲

# --- Application Setup ---
app = Flask(__name__)
app.config.from_object(Config)

# ログ設定
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
migrate = Migrate(app, db)

# ▼▼▼ SendGrid APIクライアントのセットアップ ▼▼▼
try:
    # Renderの環境変数からAPIキーを読み込む
    SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
    if not SENDGRID_API_KEY:
        app.logger.warning("環境変数 'SENDGRID_API_KEY' が設定されていません。メール送信は失敗します。")
        sg = None
    else:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        app.logger.info("SendGrid API client configured successfully.")
except Exception as e:
    app.logger.error(f"Failed to configure SendGrid API client: {e}")
    sg = None
# ▲▲▲ SendGrid ▲▲▲

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# ▼▼▼ ログイン要求時のflashメッセージを無効化 (挙動修正) ▼▼▼
login_manager.login_message = None 
# ▲▲▲ 挙動修正 ▲▲▲
login_manager.login_message_category = "danger"

# --- Database Models (Passwordの長さを256に修正) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    # ▼▼▼ パスワードの長さを256に修正済み ▼▼▼
    password = db.Column(db.String(256), nullable=False) 
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
        try:
            # レビューが0件の場合のZeroDivisionErrorを避ける
            if len(self.reviews) == 0:
                return "評価なし"
            avg = sum(r.rating for r in self.reviews) / len(self.reviews)
            return f"{avg:.2f}"
        except ZeroDivisionError:
            return "評価なし"

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

# ▼▼▼ トップページ（/）の挙動を修正 ▼▼▼
@app.route('/')
def index():
    # ログイン済みなら講義登録ページ（top.html）へ
    if current_user.is_authenticated:
        return render_template('top.html')
    # 未ログインならflashメッセージなしでログインページへ
    else:
        return redirect(url_for('login'))
# ▲▲▲ 挙動修正 ▲▲▲

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # ▼▼▼ 確認用パスワードを取得 ▼▼▼
        password_confirm = request.form.get('password_confirm')
        
        # ▼▼▼ パスワード一致チェック ▼▼▼
        if password != password_confirm:
            flash('パスワードが一致しません。もう一度お試しください。', 'danger')
            return redirect(url_for('register'))
        # ▲▲▲ 一致チェック終了 ▲▲▲

        # ▼▼▼ パスワード制約のサーバー側バリデーション ▼▼▼
        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,}$'
        if not re.match(password_pattern, password):
            flash('パスワードは12文字以上で、大文字、小文字、数字をそれぞれ1文字以上含める必要があります。', 'danger')
            return redirect(url_for('register'))
        # ▲▲▲ バリデーション終了 ▲▲▲
        
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

        new_user = None 
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            
            # ▼▼▼ 正しいUserオブジェクトの作成 ▼▼▼
            # (is_verifiedは default=False が自動で設定される)
            new_user = User(username=username, email=email, password=hashed_password)
            # ▲▲▲ これが正しい形式 ▲▲▲
            
            db.session.add(new_user)
            db.session.commit() # データベースへの書き込み

            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            
            # ▼▼▼ SendGridでメール送信 ▼▼▼
            
            # 【重要】このEmailはSendGridで「送信者認証」したものに書き換えてください
            SENDER_EMAIL = 'e235735@ie.u-ryukyu.ac.jp' 
            SENDER_NAME = '講義レビューサイト（Okinawa OTP）' 

            html_content = render_template('email/activate.html', confirm_url=confirm_url)
            
            # ▼▼▼ SendGridMailオブジェクトの作成 (バグ修正版) ▼▼▼
            message = SendGridMail(
                from_email=(SENDER_EMAIL, SENDER_NAME),
                to_emails=email,
                subject='講義レビュー | メールアドレスの確認',
                html_content=html_content)
            # ▲▲▲ バグ修正版 ▲▲▲
            
            if not sg:
                app.logger.error("SendGrid API Client (sg) is not initialized. Check SENDGRID_API_KEY.")
                raise Exception("SendGrid API Client (sg) is not initialized.")
            
            app.logger.info(f"Attempting to send email via SendGrid to {email}...")
            response = sg.send(message)
            app.logger.info(f"SendGrid response status code: {response.status_code}")
            
            if response.status_code < 200 or response.status_code >= 300:
                app.logger.error(f"SendGrid API Error: {response.body}")
                raise Exception(f"SendGrid API error (Status {response.status_code})")

            # ▲▲▲ SendGrid ▲▲▲
            
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
            app.logger.error(f"Registration error (user {email}): {e}")
            # メール送信などでエラーが出た場合、作成したユーザーをロールバック
            if new_user and new_user in db.session:
                try:
                    db.session.rollback()
                    app.logger.info(f"User creation for {email} rolled back due to subsequent error.")
                except Exception as rb_e:
                    app.logger.error(f"Rollback failed: {rb_e}")
            
            # ユーザーにエラータイプをそのまま表示しないように修正
            flash(f'不明なエラー（{type(e).__name__}）が発生しました。管理者に連絡してください。', 'danger')
            return redirect(url_for('register'))

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
            hashed_password = generate_password_hash(f"guest_pw_{uuid.uuid4().hex}", method='pbkdf2:sha256')
            
            # ▼▼▼ 正しいUserオブジェクトの作成 ▼▼▼
            new_guest_user = User(username=username, email=guest_email, password=hashed_password, is_verified=True)
            # ▲▲▲ これが正しい形式 ▲▲▲
            
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
            app.logger.error(f"Guest login error: {e}") 
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
        flash('2025年度の正しいシラバスURL (https://tiglon...で始まる) を入力してください。', 'danger')
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
    
    # 検索語が空でなければ、前後の空白を除去
    if search_term:
        search_term = search_term.strip()

    if not search_term:
        # 検索語が空の場合は、何も表示しないか、全件表示するか選択
        # ここでは「全件表示」
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
    
    # ゲストユーザーはレビューを投稿できないようにする
    if current_user.email.endswith('@demo.com'):
        flash('レビューを投稿するには、学内メールアドレスで正規登録する必要があります。', 'danger')
        return redirect(url_for('course_detail', id=id))

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
        if not (0.5 <= rating_float <= 5.0): # 評価は0.5から5.0の間に
             flash('評価は0.5から5.0の間で選択してください。', 'danger')
             return redirect(url_for('course_detail', id=id))
    except (ValueError, TypeError):
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

# 開発環境でのみ`flask run`で実行するための設定
if __name__ == '__main__':
    # RenderはGunicornを使うので、この部分はRenderでは実行されない
    app.run(debug=True)


