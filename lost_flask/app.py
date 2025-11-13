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

# ▼▼▼ 検索ロジックのために追加 ▼▼▼
from collections import Counter
from sqlalchemy.orm import joinedload
# ▲▲▲ 追加ここまで ▲▲▲

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

# ▼▼▼ 修正: Courseモデルを簡略化 ▼▼▼
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) # 講義名
    teacher = db.Column(db.String(100), nullable=False) # 教員名
    syllabus_url = db.Column(db.String(300), nullable=True) # シラバスURL
    
    # ▼▼▼ 登録時に取得する6項目 ▼▼▼
    subject_code = db.Column(db.String(50), nullable=True) # 科目番号
    department = db.Column(db.String(100), nullable=True) # 開講学部等
    credits = db.Column(db.String(10), nullable=True) # 単位数
    format = db.Column(db.String(50), nullable=True) # 授業形式 (対面/遠隔)
    # ▲▲▲ 6項目ここまで ▲▲▲

    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")

    # ▼▼▼ 修正: ユニーク制約を 'name' と 'teacher' の2つに戻す ▼▼▼
    __table_args__ = (
        db.UniqueConstraint('name', 'teacher', name='_name_teacher_uc'),
    )
    # ▲▲▲ 修正ここまで ▲▲▲

    @property
    def star_rating(self):
        if not self.reviews: return "評価なし"
        try:
            if len(self.reviews) == 0:
                return "評価なし"
            avg = sum(r.rating for r in self.reviews) / len(self.reviews)
            return f"{avg:.2f}"
        except ZeroDivisionError:
            return "評価なし"
# ▲▲▲ Courseモデル修正ここまで ▲▲▲

# ▼▼▼ 修正: Reviewモデルに 'year' と 'classroom' を追加 ▼▼▼
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Float, nullable=False) 
    attendance = db.Column(db.String(10), nullable=False) # "あり", "なし", "時々" など
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_format = db.Column(db.String(20), nullable=True) # "オンライン", "ハイブリッド", "対面" など
    
    # ▼▼▼ レビュー投稿時に任意で入力する項目 ▼▼▼
    year = db.Column(db.String(20), nullable=True) # 開講年度 (任意)
    classroom = db.Column(db.String(100), nullable=True) # 開講教室 (任意)
    # ▲▲▲ 追加ここまで ▲▲▲
    
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
# ▲▲▲ Reviewモデル修正ここまで ▲▲▲


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# ▼▼▼ 修正: スクレイピング関数 (6項目のみ取得) ▼▼▼
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
        
        # ▼▼▼ 取得するデータを6 (+1) に限定 ▼▼▼
        syllabus_data = {
            "科目番号": None, "開講学部等": None, "講義名": None,
            "単位数": None, "教員名": None, "授業形式": None,
            "シラバスURL": url
        }
        # ▲▲▲ 修正ここまで ▲▲▲

        main_content = soup.find('table', id='ctl00_phContents_Detail_Table2')
        if not main_content:
            app.logger.error(f"Scrape Error: メインコンテナが見つかりません (URL: {url})")
            return None 

        all_tds = main_content.find_all('td')

        for i, td in enumerate(all_tds):
            text = td.get_text(strip=True)
            try:
                # ▼▼▼ 取得する6項目 ▼▼▼
                if text == '科目番号':
                    syllabus_data['科目番号'] = all_tds[i + 5].get_text(strip=True)
                elif text == '対面/遠隔':
                    syllabus_data['授業形式'] = all_tds[i + 5].get_text(strip=True)
                elif text == '開講学部等':
                    syllabus_data['開講学部等'] = all_tds[i + 5].get_text(strip=True)
                elif text == '科目名[英文名]':
                    syllabus_data['講義名'] = all_tds[i + 3].get_text(strip=True)
                elif text == '単位数':
                    syllabus_data['単位数'] = all_tds[i + 3].get_text(strip=True)
                elif text == '担当教員[ローマ字表記]':
                    syllabus_data['教員名'] = all_tds[i + 1].get_text(strip=True)
                # ▲▲▲ 修正ここまで ▲▲▲
                    
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
# ▲▲▲ スクレイピング関数修正ここまで ▲▲▲


# --- Routes ---

@app.route('/')
@login_required 
def index():
    try:
        # フォームの入力値を保持するための空の辞書を渡す
        form_data = {
            'lecture_name': '', 'teacher_name': '', 'course_format': '',
            'attendance': '', 'test': '', 'report': ''
        }
        recent_courses = Course.query.order_by(db.desc(Course.id)).limit(3).all()
    except Exception as e:
        app.logger.error(f"Error fetching recent courses: {e}")
        recent_courses = []
        
    return render_template('top.html', recent_courses=recent_courses, form_data=form_data)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
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

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            
            # ▼▼▼【！！修正点！！】▼▼▼
            # is_verified=False を明示的に指定し、DBのdefault値に依存しないようにする
            new_user = User(
                username=username, 
                email=email, 
                password=hashed_password, 
                is_verified=False # ←←← この行を追加
            )
            # ▲▲▲ 修正ここまで ▲▲▲
            
            db.session.add(new_user)
            
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            
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

            db.session.commit() # <<< 成功した場合のみDBを確定
            
            flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
            return redirect(url_for('login'))

        except IntegrityError: 
            db.session.rollback() # 念のためロールバック
            if User.query.filter_by(username=username).first():
                flash('そのユーザー名は既に使用されています。 (エラー: IE-U)', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('このメールアドレスは既に使用されています。 (エラー: IE-E)', 'danger')
            else:
                flash('データベースエラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('register'))
            
        except Exception as e:
            db.session.rollback() # <<< 【重要】db.session.add(new_user) をここで取り消す
            
            app.logger.error(f"Registration error (user {email}): {e}")
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
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。学内メールで登録してください。', 'warning')
        return redirect(url_for('search_course')) 
    
    syllabus_url = request.form.get('syllabus_url')
    
    url_pattern = "tiglon.jim.u-ryukyu.ac.jp/portal/Public/Syllabus/"
    if not syllabus_url or url_pattern not in syllabus_url:
        flash('正しいシラバス詳細URL (DetailMain.aspx?lct_year=... を含む) を入力してください。', 'danger')
        return redirect(url_for('search_course')) 
    
    app.logger.info("Waiting 3 seconds before scraping...")
    time.sleep(3)
        
    app.logger.info(f"Attempting to scrape URL: {syllabus_url}")
    course_data = scrape_syllabus(syllabus_url)
    
    if course_data is None:
        flash('シラバス情報の取得に失敗しました。URLが正しいか、サイトの仕様が変更されていないか確認してください。', 'danger')
        return redirect(url_for('search_course')) 
    
    # ▼▼▼ 修正: 講義名と教員名の「2つ」で重複チェック ▼▼▼
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

    return render_template('confirm_course.html', course_data=course_data)

# ▼▼▼ 講義登録ルート (Step 2: DBへ登録) ▼▼▼
@app.route('/create_course', methods=['POST'])
@login_required
def add_course_step2_create():
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。', 'warning')
        return redirect(url_for('index'))
    
    try:
        name = request.form.get('name')
        teacher = request.form.get('teacher')
        syllabus_url = request.form.get('syllabus_url')
        
        if not name or not teacher or not syllabus_url:
            flash('登録データが不足しています。もう一度最初からやり直してください。', 'danger')
            return redirect(url_for('index')) 

        # ▼▼▼ 修正: 講義名と教員名の「2つ」で重複チェック ▼▼▼
        if Course.query.filter_by(name=name, teacher=teacher).first():
            flash(f'講義「{name} (担当: {teacher})」は既に登録されています。 (エラー: C-RACE)', 'info')
            return redirect(url_for('index')) 
        # ▲▲▲ 修正ここまで ▲▲▲
            
        # ▼▼▼ 修正: Course オブジェクトの作成 (6項目のみ) ▼▼▼
        new_course = Course(
            name=name,
            teacher=teacher,
            syllabus_url=syllabus_url,
            subject_code=request.form.get('subject_code'),
            department=request.form.get('department'),
            credits=request.form.get('credits'),
            format=request.form.get('format')
        )
        # ▲▲▲ 修正ここまで ▲▲▲
        
        db.session.add(new_course)
        db.session.commit()
        
        flash('講義を登録しました。続けてレビューを追加できます。', 'success')
        return redirect(url_for('course_detail', id=new_course.id))

    except IntegrityError:
        db.session.rollback()
        flash('この講義名と教員の組み合わせは既に登録されています。 (エラー: IE-C)', 'danger')
        return redirect(url_for('index')) 
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add course (create) error: {e}")
        flash('講義の登録中にエラーが発生しました。', 'danger')
        return redirect(url_for('index'))

# ▼▼▼ 修正: /search ルート (GETメソッド許可 & 詳細検索ロジック) ▼▼▼
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_course():
    search_term = None # 旧ロジックの名残だが、互換性のため残す
    results = []
    
    # ▼▼▼【！！変更点！！】▼▼▼
    # フォームからの検索条件を保持するための辞書
    form_data = {
        'lecture_name': request.form.get('lecture_name', ''),
        'teacher_name': request.form.get('teacher_name', ''),
        'course_format': request.form.get('course_format', ''),
        'attendance': request.form.get('attendance', ''),
        'test': request.form.get('test', ''),     # 'test' を追加
        'report': request.form.get('report', '')  # 'report' を追加
        # 'full_text' を削除
    }

    if request.method == 'POST':
        # フォームからデータを取得
        lecture_name = form_data['lecture_name']
        teacher_name = form_data['teacher_name']
        course_format = form_data['course_format']
        attendance = form_data['attendance']
        test = form_data['test']     # 'test' を取得
        report = form_data['report'] # 'report' を取得

        # ベースクエリ (N+1問題を避けるため reviews をEager Loadingする)
        query = Course.query.options(joinedload(Course.reviews))
        
        # 絞り込み条件
        filters = []
        review_filters = []

        if lecture_name:
            # スペース区切りでAND検索（例: "講義A 演習" -> "講義A" AND "演習"）
            for term in lecture_name.split():
                filters.append(Course.name.like(f'%{term}%'))
        
        if teacher_name:
            for term in teacher_name.split():
                filters.append(Course.teacher.like(f'%{term}%'))
        
        # Review関連のフィルタ
        if course_format and course_format != "--------":
            review_filters.append(Review.course_format == course_format)
            
        # ▼▼▼【！！変更点！！】▼▼▼
        # 'full_text' のロジックを削除
        # ▲▲▲ 変更ここまで ▲▲▲

        # Courseのフィルタを適用
        if filters:
            query = query.filter(db.and_(*filters))
            
        # Reviewのフィルタを適用 (JOINが必要)
        if review_filters:
            query = query.join(Review, Course.id == Review.course_id).filter(db.and_(*review_filters))

        # この時点で重複する講義を除外
        query = query.distinct()
        
        # ここまでの条件で講義リストを取得
        try:
            initial_results = query.all()
        except Exception as e:
            app.logger.error(f"Search query error (before mode filter): {e}")
            initial_results = []
            flash('検索中にエラーが発生しました。', 'danger')

        # 'initial_results' を 'results' にコピーして、ここから絞り込みを開始
        results = initial_results

        # ▼▼▼【！！変更点！！】▼▼▼
        # (attendance, test, report) の最頻値フィルタリングを順番に適用
        
        # 1. 出席(attendance)での絞り込み
        if attendance and attendance != "--------":
            filtered_results = []
            for course in results: # 'results' (現在絞り込まれたリスト) をループ
                if not course.reviews: continue
                
                item_list = [r.attendance for r in course.reviews if r.attendance in ['あり', 'なし']]
                if not item_list: continue

                try:
                    counts = Counter(item_list)
                    mode_item = counts.most_common(1)[0][0]
                    if mode_item == attendance:
                        filtered_results.append(course)
                except IndexError:
                    continue
            results = filtered_results # 絞り込んだ結果を 'results' に上書き

        # 2. テスト(test)での絞り込み
        if test and test != "--------":
            filtered_results = []
            for course in results: # 'results' (出席で絞り込まれたリスト) をループ
                if not course.reviews: continue
                
                item_list = [r.test for r in course.reviews if r.test in ['あり', 'なし']]
                if not item_list: continue

                try:
                    counts = Counter(item_list)
                    mode_item = counts.most_common(1)[0][0]
                    if mode_item == test:
                        filtered_results.append(course)
                except IndexError:
                    continue
            results = filtered_results # 絞り込んだ結果を 'results' に上書き

        # 3. レポート(report)での絞り込み
        if report and report != "--------":
            filtered_results = []
            for course in results: # 'results' (出席・テストで絞り込まれたリスト) をループ
                if not course.reviews: continue
                
                item_list = [r.report for r in course.reviews if r.report in ['あり', 'なし']]
                if not item_list: continue

                try:
                    counts = Counter(item_list)
                    mode_item = counts.most_common(1)[0][0]
                    if mode_item == report:
                        filtered_results.append(course)
                except IndexError:
                    continue
            results = filtered_results # 最終的な結果を 'results' に上書き
            
        # ▲▲▲ 変更ここまで ▲▲▲
            
    else: 
        # GETリクエストの場合 (例: /search に直接アクセス)
        # すべての講義を表示（レビューも読み込む）
        try:
            results = Course.query.options(joinedload(Course.reviews)).order_by(db.desc(Course.id)).all()
        except Exception as e:
            app.logger.error(f"Search query error (GET request): {e}")
            results = []
            flash('講義一覧の取得中にエラーが発生しました。', 'danger')
            
    # search.html に検索結果とフォームの入力値を渡す
    return render_template('search.html', results=results, search_term=search_term, form_data=form_data)
# ▲▲▲ 修正ここまで ▲▲▲

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.get_or_404(id)
    return render_template('detail.html', course=course)

@app.route('/course_view/<int:id>')
@login_required
def course_view_detail(id):
    course = Course.query.get_or_404(id)
    return render_template('detail2.html', course=course)

# ▼▼▼ 修正: add_review (year, classroom を任意で取得) ▼▼▼
@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    
    if Review.query.filter_by(course_id=id, user_id=current_user.id).first():
        flash('あなたはこの講義に既にレビューを投稿しています。', 'warning')
        return redirect(url_for('course_detail', id=id))

    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')
    course_format = request.form.get('course_format') # 任意
    review_text = request.form.get('review')
    
    # ▼▼▼ 任意項目 (year, classroom) を取得 ▼▼▼
    year = request.form.get('year')
    classroom = request.form.get('classroom')
    # ▲▲▲ 修正ここまで ▲▲▲

    if not all([rating, attendance, test, report]):
        flash('評価、出欠、テスト、レポートの項目は必須です。', 'danger')
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
        # ▼▼▼ new_review に year と classroom を追加 ▼▼▼
        new_review = Review(
            rating=rating_float, attendance=attendance, test=test, report=report,
            course_format=course_format, 
            year=year, # 追加
            classroom=classroom, # 追加
            review=review_text,
            course_id=course.id, author=current_user
        )
        # ▲▲▲ 修正ここまで ▲▲▲
        
        db.session.add(new_review)
        db.session.commit()
        flash('レビューを投稿しました。', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add review error: {e}")
        flash('レビューの投稿中にエラーが発生しました。', 'danger')
        
    # ▼▼▼【！！変更点！！】▼▼▼
    # 投稿が成功したら、閲覧専用の 'detail2.html' (course_view_detail関数) に移動する
    return redirect(url_for('course_view_detail', id=id))
    # ▲▲▲ 変更ここまで ▲▲▲


# 開発環境でのみ`flask run`で実行するための設定
if __name__ == '__main__':
    # 開発時に "instance" フォルダが存在することを確認
    if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')):
        os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'))
    
    app.run(debug=True, port=5002)