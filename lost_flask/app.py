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
import time # ▼▼▼ スリープのために追加 ▼▼▼
import requests # ▼▼▼ スクレイピングのために追加 ▼▼▼
from bs4 import BeautifulSoup # ▼▼▼ スクレイピングのために追加 ▼▼▼

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
# ▼▼▼ 不自然なflashメッセージを無効化 ▼▼▼
login_manager.login_message = None 
# ▲▲▲ flashメッセージ無効化 ▲▲▲
login_manager.login_message_category = "danger"

# --- Database Models (Passwordの長さを256に修正) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    # ▼▼▼ パスワードの長さを256に変更 ▼▼▼
    password = db.Column(db.String(256), nullable=False) 
    # ▲▲▲ パスワードの長さ変更 ▲▲▲
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # ▼▼▼ 修正: unique=True を削除 ▼▼▼
    name = db.Column(db.String(100), nullable=False) # 講義名
    # ▲▲▲ 修正ここまで ▲▲▲
    teacher = db.Column(db.String(100), nullable=False) # 教員名
    syllabus_url = db.Column(db.String(300), nullable=True) # シラバスURL
    
    # ▼▼▼ スクレイピングで取得するカラムを追加 ▼▼▼
    subject_code = db.Column(db.String(50), nullable=True) # 科目番号
    classroom = db.Column(db.String(100), nullable=True) # 開講教室
    format = db.Column(db.String(50), nullable=True) # 対面/遠隔
    year = db.Column(db.String(20), nullable=True) # 開講年度
    term = db.Column(db.String(50), nullable=True) # 期間
    schedule = db.Column(db.String(100), nullable=True) # 曜日時限
    department = db.Column(db.String(100), nullable=True) # 開講学部等
    credits = db.Column(db.String(10), nullable=True) # 単位数
    # ▲▲▲ 追加ここまで ▲▲▲

    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")

    # ▼▼▼ 修正: 講義名と教員名の組み合わせでユニーク制約を追加 ▼▼▼
    __table_args__ = (
        db.UniqueConstraint('name', 'teacher', name='_name_teacher_uc'),
    )
    # ▲▲▲ 修正ここまで ▲▲▲

    @property
    def star_rating(self):
        if not self.reviews: return "評価なし"
        try:
            # ▼▼▼ レビュー0件の場合のエラーをハンドリング ▼▼▼
            if len(self.reviews) == 0:
                return "評価なし"
            avg = sum(r.rating for r in self.reviews) / len(self.reviews)
            return f"{avg:.2f}"
        except ZeroDivisionError:
            return "評価なし"
        # ▲▲▲ エラーハンドリング ▲▲▲

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Float, nullable=False) 
    attendance = db.Column(db.String(10), nullable=False)
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_format = db.Column(db.String(20), nullable=True) # 授業形式 (任意)
    classroom = db.Column(db.String(100), nullable=True) # 開講教室 (任意)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# ▼▼▼ スクレイピング関数をここに追加 ▼▼▼
def scrape_syllabus(url):
    """
    指定されたシラバスURLから情報を抽出する
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        syllabus_data = {
            "科目番号": None, "開講教室": None, "対面/遠隔": None, "開講年度": None,
            "期間": None, "曜日時限": None, "開講学部等": None, "講義名": None,
            "単位数": None, "教員名": None, "シラバスURL": url # URLも渡す
        }

        main_content = soup.find('table', id='ctl00_phContents_Detail_Table2')
        if not main_content:
            app.logger.error(f"Scrape Error: メインコンテナが見つかりません (URL: {url})")
            return None 

        all_tds = main_content.find_all('td')

        for i, td in enumerate(all_tds):
            text = td.get_text(strip=True)
            try:
                if text == '科目番号':
                    syllabus_data['科目番号'] = all_tds[i + 5].get_text(strip=True)
                elif text == '教室':
                    syllabus_data['開講教室'] = all_tds[i + 5].get_text(strip=True)
                elif text == '対面/遠隔':
                    syllabus_data['対面/遠隔'] = all_tds[i + 5].get_text(strip=True)
                elif text == '開講年度':
                    syllabus_data['開講年度'] = all_tds[i + 5].get_text(strip=True)
                elif text == '期間':
                    syllabus_data['期間'] = all_tds[i + 5].get_text(strip=True)
                elif text == '曜日時限':
                    syllabus_data['曜日時限'] = all_tds[i + 5].get_text(strip=True)
                elif text == '開講学部等':
                    syllabus_data['開講学部等'] = all_tds[i + 5].get_text(strip=True)
                elif text == '科目名[英文名]':
                    syllabus_data['講義名'] = all_tds[i + 3].get_text(strip=True)
                elif text == '単位数':
                    syllabus_data['単位数'] = all_tds[i + 3].get_text(strip=True)
                elif text == '担当教員[ローマ字表記]':
                    syllabus_data['教員名'] = all_tds[i + 1].get_text(strip=True)
            except IndexError:
                app.logger.warning(f"Scrape Warning: '{text}' のデータ取得中にIndexError (URL: {url})")
                pass
        
        # 必須項目チェック
        if not syllabus_data.get('講義名') or not syllabus_data.get('教員名'):
            app.logger.error(f"Scrape Error: 必須項目（講義名または教員名）が取得できませんでした (URL: {url})")
            return None

        return syllabus_data

    except requests.exceptions.RequestException as e:
        app.logger.error(f"HTTPリクエストエラー (URL: {url}): {e}")
        return None
    except Exception as e:
        app.logger.error(f"スクレイピング中の予期せぬエラー (URL: {url}): {e}")
        return None
# ▲▲▲ スクレイピング関数ここまで ▲▲▲


# --- Routes ---

# ▼▼▼ トップページ（/）の挙動を修正 ▼▼▼
@app.route('/')
@login_required # ログイン必須は維持
def index():
    # ログイン済みユーザーには、検索フォームと最近の講義を表示
    try:
        # DBからIDを降順（新しい順）で3件取得
        recent_courses = Course.query.order_by(db.desc(Course.id)).limit(3).all()
    except Exception as e:
        app.logger.error(f"Error fetching recent courses: {e}")
        recent_courses = []
        
    return render_template('top.html', recent_courses=recent_courses)
# ▲▲▲ 挙動修正 ▲▲▲

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ▼▼▼ 修正: ログイン済みのユーザーは登録ページにアクセスさせない ▼▼▼
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # ▲▲▲ 修正ここまで ▲▲▲
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # --- 入力チェック (ここは変更なし) ---
        if password != password_confirm:
            flash('パスワードが一致しません。もう一度お試しください。', 'danger')
            return redirect(url_for('register'))

        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,}$'
        if not re.match(password_pattern, password):
            flash('パスワードは12文字以上で、大文字、小文字、数字をそれぞれ1文字以上含める必要があります。', 'danger')
            return redirect(url_for('register'))
        
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

        # ▼▼▼ トランザクション修正 ▼▼▼
        try:
            # 1. データベースオブジェクトを準備（まだコミットしない）
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            
            # 2. メールの準備と送信
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            
            # 【重要】ここはあなたのSendGrid認証済みアドレスに書き換えてください
            SENDER_EMAIL = 'e235735@ie.u-ryukyu.ac.jp' 
            SENDER_NAME = '講義レビューサイト' # 送信者名

            html_content = render_template('email/activate.html', confirm_url=confirm_url)
            
            message = SendGridMail(
                from_email=(SENDER_EMAIL, SENDER_NAME),
                to_emails=email,
                subject='講義レビュー | メールアドレスの確認',
                html_content=html_content)
            
            if not sg:
                raise Exception("SendGrid API Client (sg) is not initialized. Check SENDGRID_API_KEY.")
            
            app.logger.info(f"Attempting to send email via SendGrid to {email}...")
            response = sg.send(message) # <<< メール送信を試行
            app.logger.info(f"SendGrid response status code: {response.status_code}")
            
            if response.status_code < 200 or response.status_code >= 300:
                app.logger.error(f"SendGrid API Error: {response.body}")
                raise Exception(f"SendGrid API error (Status {response.status_code})")

            # 3. メール送信が成功した場合のみ、データベースにコミット
            db.session.commit() # <<< 成功した場合のみDBを確定
            
            flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
            return redirect(url_for('login'))

        except IntegrityError: 
            # 3のコミットが（万が一の）重複エラーを起こした場合
            db.session.rollback() # 念のためロールバック
            if User.query.filter_by(username=username).first():
                flash('そのユーザー名は既に使用されています。 (エラー: IE-U)', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('このメールアドレスは既に使用されています。 (エラー: IE-E)', 'danger')
            else:
                flash('データベースエラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('register'))
            
        except Exception as e:
            # 2のメール送信が失敗した場合、またはその他のエラー
            db.session.rollback() # <<< 【重要】db.session.add(new_user) をここで取り消す
            
            app.logger.error(f"Registration error (user {email}): {e}")
            flash(f'不明なエラー（{type(e).__name__}）が発生しました。管理者に連絡してください。', 'danger')
            return redirect(url_for('register'))
        # ▲▲▲ トランザクション修正完了 ▲▲▲

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
            app.logger.error(f"Guest login error: {e}") 
            flash('不明なエラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('guest_login'))

    return render_template('guest_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ▼▼▼ 講義登録ルート (Step 1: スクレイピングと確認) ▼▼▼
@app.route('/add_course', methods=['POST'])
@login_required
def add_course_step1_scrape():
    # ▼▼▼ 修正: ゲストユーザーは登録不可 ▼▼▼
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。学内メールで登録してください。', 'warning')
        return redirect(url_for('search_course')) # 修正: search_course (GET) にリダイレクト
    # ▲▲▲ 修正ここまで ▲▲▲

    syllabus_url = request.form.get('syllabus_url')
    
    # ▼▼▼ 修正: URLバリデーションを年度指定なしに変更 ▼▼▼
    url_pattern = "tiglon.jim.u-ryukyu.ac.jp/portal/Public/Syllabus/"
    if not syllabus_url or url_pattern not in syllabus_url:
        flash('正しいシラバス詳細URL (DetailMain.aspx?lct_year=... を含む) を入力してください。', 'danger')
        return redirect(url_for('search_course')) # 検索ページに戻す
    # ▲▲▲ 修正ここまで ▲▲▲
    
    # --- サーバー負荷軽減のため3秒待機 ---
    app.logger.info("Waiting 3 seconds before scraping...")
    time.sleep(3)
    # ---------------------------------
        
    # スクレイピング実行
    app.logger.info(f"Attempting to scrape URL: {syllabus_url}")
    course_data = scrape_syllabus(syllabus_url)
    
    if course_data is None:
        flash('シラバス情報の取得に失敗しました。URLが正しいか、サイトの仕様が変更されていないか確認してください。', 'danger')
        return redirect(url_for('search_course')) # 検索ページに戻す
    
    # ▼▼▼ 修正: 講義名と教員名の「両方」で重複チェック ▼▼▼
    scraped_name = course_data.get('講義名')
    scraped_teacher = course_data.get('教員名')

    existing_course = Course.query.filter_by(
        name=scraped_name,
        teacher=scraped_teacher
    ).first()
    
    if existing_course:
        flash(f"講義「{scraped_name} (担当: {scraped_teacher})」は既に登録されています。", 'info')
        return redirect(url_for('course_detail', id=existing_course.id))
    # ▲▲▲ 修正ここまで ▲▲▲

    # 取得成功。確認ページへ
    return render_template('confirm_course.html', course_data=course_data)
# ▲▲▲ 講義登録ルート (Step 1) ▲▲▲

# ▼▼▼ 講義登録ルート (Step 2: DBへ登録) ▼▼▼
@app.route('/create_course', methods=['POST'])
@login_required
def add_course_step2_create():
    # ▼▼▼ 修正: ゲストユーザーは登録不可 ▼▼▼
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。', 'warning')
        return redirect(url_for('index'))
    # ▲▲▲ 修正ここまで ▲▲▲
    
    try:
        # POSTフォームからデータを取得
        name = request.form.get('name')
        teacher = request.form.get('teacher')
        syllabus_url = request.form.get('syllabus_url')
        
        if not name or not teacher or not syllabus_url:
            flash('登録データが不足しています。もう一度最初からやり直してください。', 'danger')
            return redirect(url_for('index')) # ホームに戻す

        # ▼▼▼ 修正: 講義名と教員名の「両方」で重複チェック (レースコンディション対策) ▼▼▼
        if Course.query.filter_by(name=name, teacher=teacher).first():
            flash(f'講義「{name} (担当: {teacher})」は既に登録されています。 (エラー: C-RACE)', 'info')
            return redirect(url_for('index')) # ホームに戻す
        # ▲▲▲ 修正ここまで ▲▲▲
            
        # Course オブジェクトの作成
        new_course = Course(
            name=name,
            teacher=teacher,
            syllabus_url=syllabus_url,
            subject_code=request.form.get('subject_code'),
            classroom=request.form.get('classroom'),
            format=request.form.get('format'),
            year=request.form.get('year'),
            term=request.form.get('term'),
            schedule=request.form.get('schedule'),
            department=request.form.get('department'),
            credits=request.form.get('credits')
        )
        
        db.session.add(new_course)
        db.session.commit()
        
        flash('講義を登録しました。続けてレビューを追加できます。', 'success')
        return redirect(url_for('course_detail', id=new_course.id))

    except IntegrityError:
        # ▼▼▼ 修正: 複合ユニーク制約違反の場合のエラー ▼▼▼
        db.session.rollback()
        flash('この講義名と教員の組み合わせは既に登録されています。 (エラー: IE-C)', 'danger')
        return redirect(url_for('index')) # ホームに戻す
        # ▲▲▲ 修正ここまで ▲▲▲
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add course (create) error: {e}")
        flash('講義の登録中にエラーが発生しました。', 'danger')
        return redirect(url_for('index')) # ホームに戻す
# ▲▲▲ 講義登録ルート (Step 2) ▲▲▲

# ▼▼▼ 修正: /search ルートで GET メソッドも許可する ▼▼▼
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_course():
    search_term = None
    results = []

    if request.method == 'POST':
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
    else: 
        # GETリクエストの場合
        # (ゲストがリダイレクトされた時や、URL直打ちで /search に来た場合)
        # 全件一覧を表示する
        results = Course.query.all()
        # search_term は None (デフォルト) のまま
        
    return render_template('search.html', results=results, search_term=search_term)
# ▲▲▲ 修正ここまで ▲▲▲

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.get_or_404(id)
    # 投稿・閲覧ができる 'detail.html' を表示
    return render_template('detail.html', course=course)

@app.route('/course_view/<int:id>')
@login_required
def course_view_detail(id):
    course = Course.query.get_or_404(id)
    # 閲覧専用の 'detail2.html' を表示
    return render_template('detail2.html', course=course)

@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    
    # ▼▼▼ 1ユーザー1レビューの制約 ▼▼▼
    existing_review = Review.query.filter_by(course_id=id, user_id=current_user.id).first()
    if existing_review:
        flash('あなたはこの講義に既にレビューを投稿しています。', 'warning')
        return redirect(url_for('course_detail', id=id))
    # ▲▲▲ 1ユーザー1レビュー ▲▲▲

    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')
    course_format = request.form.get('course_format') # 任意
    # classroom = request.form.get('classroom') # 削除
    review_text = request.form.get('review')
    
    # ▼▼▼ 修正: 必須項目チェックから course_format を削除 ▼▼▼
    if not all([rating, attendance, test, report]):
        flash('評価、出欠、テスト、レポートの項目は必須です。', 'danger')
        return redirect(url_for('course_detail', id=id))
    # ▲▲▲ 修正ここまで ▲▲▲
        
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
            course_format=course_format, 
            classroom=None, # ▼▼▼ 修正: classroom は入力させない（NoneをDBに保存）
            review=review_text,
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
    # 開発時に "instance" フォルダが存在することを確認
    if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')):
        os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'))
    
    # ▼▼▼ 変更点 ▼▼▼
    # ポート5000番がAirPlayなどで使われている場合があるため、5001番に変更
    app.run(debug=True, port=5001)
    # ▲▲▲ 変更ここまで ▲▲▲