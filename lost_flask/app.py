from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import uuid
import datetime
import random
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from config import Config
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError, OperationalError
import os
import logging 
import time 
import requests 
from bs4 import BeautifulSoup 
from sqlalchemy.sql.expression import func, or_

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail

from collections import Counter
from sqlalchemy.orm import joinedload
from urllib.parse import urlparse, parse_qs
from sqlalchemy import text 

# --- Application Setup ---
app = Flask(__name__)
# Configクラスから設定を読み込む (DB URIや接続オプションもここに含まれる)
app.config.from_object(Config)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    content_type = response.headers.get('Content-Type', '')
    if 'text/css' in content_type or \
       'image' in content_type or \
       'javascript' in content_type or \
       'font' in content_type:
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    if 'text/html' in content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
migrate = Migrate(app, db)

try:
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

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None 
login_manager.login_message_category = "danger"

# --- Database Models ---

class ReviewReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # ユーザー削除時にリアクションも削除 (ON DELETE CASCADE)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    reaction_type = db.Column(db.String(20), nullable=False) 
    __table_args__ = (
        db.UniqueConstraint('user_id', 'review_id', 'reaction_type', name='_user_review_reaction_uc'),
    )

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False) 
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)
    is_tutorial_seen = db.Column(db.Boolean, default=False)
    faculty = db.Column(db.String(50))      # 学部 (例: 工学部)
    department = db.Column(db.String(50))   # 学科 (例: 知能情報コース)
    grade = db.Column(db.String(10))        # 学年 (例: 2024年度入学)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) 
    # 教員名の文字数を1000に設定 (長い教員名リストに対応)
    teacher = db.Column(db.String(1000), nullable=False) 
    syllabus_url = db.Column(db.String(300), nullable=True) 
    subject_code = db.Column(db.String(50), nullable=True) 
    department = db.Column(db.String(100), nullable=True) 
    credits = db.Column(db.String(10), nullable=True) 
    format = db.Column(db.String(50), nullable=True) 
    syllabus_year = db.Column(db.String(20), nullable=True) 
    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")
    
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

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Float, nullable=False) 
    attendance = db.Column(db.String(10), nullable=False)
    test = db.Column(db.String(10), nullable=False)
    report = db.Column(db.String(10), nullable=False)
    course_format = db.Column(db.String(20), nullable=True)
    year = db.Column(db.String(20), nullable=True)
    classroom = db.Column(db.String(100), nullable=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reactions = db.relationship('ReviewReaction', backref='review', lazy='dynamic', cascade="all, delete-orphan")

    def get_reaction_counts(self):
        return {
            'empathy': self.reactions.filter_by(reaction_type='empathy').count(),
            'insightful': self.reactions.filter_by(reaction_type='insightful').count(),
            'hmm': self.reactions.filter_by(reaction_type='hmm').count()
        }

    def get_user_reactions(self, user_id):
        return [r.reaction_type for r in self.reactions.filter_by(user_id=user_id).all()]

@login_manager.user_loader
def load_user(user_id):
    # ▼▼▼ 修正: DB接続リトライ機能を追加 ▼▼▼
    # 無料枠の不安定な接続に対応するため、最大3回まで再試行する
    max_retries = 3
    for attempt in range(max_retries):
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            # 最後の試行で失敗した場合のみログを出してNoneを返す
            if attempt == max_retries - 1:
                app.logger.error(f"Error loading user {user_id} after {max_retries} attempts: {e}")
                return None
            # 失敗した場合は少し待ってから再試行 (0.1秒, 0.2秒...)
            time.sleep(0.1 * (2 ** attempt))
    return None
    # ▲▲▲ 修正ここまで ▲▲▲

def scrape_syllabus(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        syllabus_data = {
            "科目番号": None, "開講学部等": None, "講義名": None,
            "単位数": None, "教員名": None, "授業形式": None,
            "年度": None, "シラバスURL": url
        }
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            year = query_params.get('lct_year', [None])[0]
            if year and year.isdigit():
                syllabus_data['年度'] = f"{year}年度"
            else:
                syllabus_data['年度'] = "年度不明"
        except Exception:
            syllabus_data['年度'] = "年度不明"

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
            except IndexError:
                pass
        if not syllabus_data.get('講義名') or not syllabus_data.get('教員名'):
            return None
        return syllabus_data
    except requests.exceptions.RequestException as e:
        app.logger.error(f"HTTPリクエストエラー (URL: {url}): {e}")
        return None
    except Exception as e:
        app.logger.error(f"スクレイピング中の予期せぬエラー (URL: {url}): {e}")
        return None

# --- Routes ---

@app.route('/')
@login_required 
def index():
    try:
        if not current_user.is_tutorial_seen:
            return redirect(url_for('help_page'))
    except Exception as e:
        app.logger.error(f"Database error during tutorial check: {e}")
        pass

    try:
        form_data = {
            'lecture_name': '', 'teacher_name': '', 'course_format': '',
            'attendance': '', 'test': '', 'report': ''
        }
        
        # SQLレベルで評価平均を計算してトップ10を取得
        stmt = db.session.query(
            Review.course_id,
            func.avg(Review.rating).label('avg_rating')
        ).group_by(Review.course_id).subquery()

        # joinedload を復活させて N+1問題を回避 (トップページ)
        top_courses_query = db.session.query(Course)\
            .join(stmt, Course.id == stmt.c.course_id)\
            .options(joinedload(Course.reviews))\
            .order_by(stmt.c.avg_rating.desc())\
            .limit(10)
            
        top_courses = top_courses_query.all()
        
    except Exception as e:
        app.logger.error(f"Error fetching top courses: {e}")
        top_courses = []

    try:
        ua = str(request.user_agent).lower()
        is_mobile = 'iphone' in ua or ('android' in ua and 'mobile' in ua)
    except Exception:
        is_mobile = False

    if is_mobile:
        return render_template('top.html', top_courses=top_courses, form_data=form_data)
    else:
        return render_template('top_compact.html', top_courses=top_courses, form_data=form_data)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        faculty = request.form.get('faculty')
        department = request.form.get('department')
        grade = request.form.get('grade')
        
        if password != password_confirm:
            flash('パスワードが一致しません。', 'danger')
            return redirect(url_for('register'))

        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{12,}$'
        if not re.match(password_pattern, password):
            flash('パスワードは12文字以上で、大文字、小文字、数字をそれぞれ1文字以上含める必要があります。', 'danger')
            return redirect(url_for('register'))
        
        email_pattern = r'^e\d{6}@cs\.u-ryukyu\.ac\.jp$' 
        if not re.match(email_pattern, email):
            flash('現在、登録はCSコースのアドレス (eXXXXXX@cs.u-ryukyu.ac.jp) に限定されています。', 'danger')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                username=username, 
                email=email, 
                password=hashed_password, 
                is_verified=False,
                faculty=faculty,
                department=department,
                grade=grade
            )
            db.session.add(new_user)
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            SENDER_EMAIL = 'e235735@ie.u-ryukyu.ac.jp' 
            SENDER_NAME = '講義レビューサイト' 
            html_content = render_template('email/activate.html', confirm_url=confirm_url)
            message = SendGridMail(
                from_email=(SENDER_EMAIL, SENDER_NAME),
                to_emails=email,
                subject='講義レビュー | メールアドレスの確認',
                html_content=html_content)
            if not sg:
                raise Exception("SendGrid API Client (sg) is not initialized.")
            response = sg.send(message) 
            if response.status_code < 200 or response.status_code >= 300:
                raise Exception(f"SendGrid API error (Status {response.status_code})")
            db.session.commit() 
            flash('確認メールを送信しました。', 'success')
            return redirect(url_for('login'))
        except IntegrityError: 
            db.session.rollback() 
            existing_user_by_email = User.query.filter_by(email=email).first()
            if existing_user_by_email:
                if existing_user_by_email.is_verified:
                    flash('このメールアドレスは既に使用されています。', 'danger')
                    return redirect(url_for('login'))
                else:
                    flash('このメールアドレスは登録済みですが、未認証です。', 'warning')
                    return redirect(url_for('resend_activation'))
            flash('エラーが発生しました。', 'danger')
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {e}")
            flash(f'不明なエラーが発生しました。', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except SignatureExpired:
        flash('認証リンクの有効期限が切れています。', 'danger')
        return redirect(url_for('resend_activation')) 
    except BadTimeSignature:
        flash('認証リンクが無効です。', 'danger')
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
        flash('メール認証が完了しました。', 'success')
    return redirect(url_for('login'))

@app.route('/resend_activation', methods=['GET', 'POST'])
def resend_activation():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('そのメールアドレスのアカウントが未認証の場合、再送リンクを送信しました。', 'info')
            return redirect(url_for('login'))
        if user.is_verified:
            flash('このアカウントは既に有効化されています。', 'info')
            return redirect(url_for('login'))
        try:
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            SENDER_EMAIL = 'e235735@ie.u-ryukyu.ac.jp' 
            SENDER_NAME = '講義レビューサイト'
            html_content = render_template('email/activate.html', confirm_url=confirm_url)
            message = SendGridMail(from_email=(SENDER_EMAIL, SENDER_NAME), to_emails=email, subject='講義レビュー | メールアドレスの確認 (再送)', html_content=html_content)
            if not sg: raise Exception("SendGrid API Client not initialized.")
            response = sg.send(message)
            if response.status_code < 200 or response.status_code >= 300: raise Exception(f"SendGrid API error")
            flash('新しい認証リンクをメールアドレスに送信しました。', 'success')
        except Exception as e:
            app.logger.error(f"Resend activation error: {e}")
            flash(f'メールの送信中にエラーが発生しました。', 'danger')
        return redirect(url_for('login'))
    return render_template('resend_activation.html')

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
            flash('アカウントがまだ認証されていません。', 'warning')
            return redirect(url_for('resend_activation'))
        login_user(user)
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))
    return render_template('login.html')

@app.route('/guest_login', methods=['GET', 'POST'])
def guest_login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # 毎回新規作成せず、固定のゲストユーザーを使い回す
            GUEST_EMAIL = "guest@demo.com"
            user = User.query.filter_by(email=GUEST_EMAIL).first()

            if user:
                # 既に存在するゲストユーザーでログイン
                login_user(user)
                flash('ゲストとしてログインしました。', 'success')
                return redirect(url_for('index'))
            else:
                # 初回のみゲストユーザーを作成 (次回からは上記ifに入る)
                guest_username = "ゲスト"
                hashed_password = generate_password_hash("GuestPassword123!", method='pbkdf2:sha256')
                
                new_guest_user = User(
                    username=guest_username,
                    email=GUEST_EMAIL, 
                    password=hashed_password, 
                    is_verified=True,
                    faculty='工学部',
                    department='知能情報コース',
                    grade='3年'
                )
                
                db.session.add(new_guest_user)
                db.session.commit()
                
                login_user(new_guest_user)
                flash('ゲストユーザーを新規作成してログインしました。', 'success')
                return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Guest login error: {e}")
            flash('エラーが発生しました。もう一度お試しください。', 'danger')
            return redirect(url_for('guest_login'))
            
    return render_template('guest_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_course', methods=['POST'])
@login_required
def add_course_step1_scrape():
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。', 'warning')
        return redirect(url_for('index')) 
    syllabus_url = request.form.get('syllabus_url')
    url_pattern = "tiglon.jim.u-ryukyu.ac.jp/portal/Public/Syllabus/"
    if not syllabus_url or url_pattern not in syllabus_url:
        flash('正しいシラバス詳細URLを入力してください。', 'danger')
        return redirect(url_for('index')) 
    
    course_data = scrape_syllabus(syllabus_url)
    if course_data is None:
        flash('シラバス情報の取得に失敗しました。', 'danger')
        return redirect(url_for('index')) 
    scraped_name = course_data.get('講義名')
    scraped_teacher = course_data.get('教員名')
    existing_course = Course.query.filter_by(name=scraped_name, teacher=scraped_teacher).first()
    if existing_course:
        flash(f"講義「{scraped_name}」は既に登録されています。", 'info')
        return redirect(url_for('course_detail', id=existing_course.id))
    return render_template('confirm_course.html', course_data=course_data)

@app.route('/create_course', methods=['POST'])
@login_required
def add_course_step2_create():
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーは講義を登録できません。', 'warning')
        return redirect(url_for('index'))
    try:
        new_course = Course(
            name=request.form.get('name'),
            teacher=request.form.get('teacher'),
            syllabus_url=request.form.get('syllabus_url'),
            subject_code=request.form.get('subject_code'),
            department=request.form.get('department'),
            credits=request.form.get('credits'),
            format=request.form.get('format'),
            syllabus_year=request.form.get('syllabus_year')
        )
        db.session.add(new_course)
        db.session.commit()
        flash('講義を登録しました。', 'success')
        return redirect(url_for('course_detail', id=new_course.id))
    except IntegrityError:
        db.session.rollback()
        flash('既に登録されています。', 'danger')
        return redirect(url_for('index')) 
    except Exception as e:
        db.session.rollback()
        flash('エラーが発生しました。', 'danger')
        return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_course():
    # ページネーションとフィルタパラメータの取得
    page = request.args.get('page', 1, type=int)
    per_page_str = request.args.get('per_page') or request.form.get('per_page') or '10'
    try:
        per_page = int(per_page_str)
        if per_page <= 0: per_page = 10
    except:
        per_page = 10

    def get_param(key):
        return request.args.get(key) or request.form.get(key) or ''

    sort_key = get_param('sort') or 'id'
    sort_order = get_param('order') or 'desc'

    form_data = {
        'lecture_name': get_param('lecture_name'),
        'teacher_name': get_param('teacher_name'),
        'course_format': get_param('course_format'),
        'department': get_param('department'),
        'attendance': get_param('attendance'),
        'test': get_param('test'),
        'report': get_param('report'),
        'per_page': str(per_page),
        'sort': sort_key,
        'order': sort_order
    }
    
    try:
        # 基本クエリの構築
        query = Course.query

        # --- 基本情報のSQLフィルタリング ---
        if form_data['lecture_name']:
            for term in form_data['lecture_name'].split():
                query = query.filter(Course.name.like(f'%{term}%'))
        
        if form_data['teacher_name']:
            for term in form_data['teacher_name'].split():
                query = query.filter(Course.teacher.like(f'%{term}%'))

        if form_data['course_format'] and form_data['course_format'] != "--------":
            query = query.filter(Course.format == form_data['course_format'])

        if form_data['department'] and form_data['department'] != "--------":
            query = query.filter(Course.department.like(f'%{form_data["department"]}%'))

        # --- レビュー内容に基づくSQLフィルタリング ---
        review_criteria = []
        if form_data['attendance'] and form_data['attendance'] != "--------":
            review_criteria.append(Review.attendance == form_data['attendance'])
        if form_data['test'] and form_data['test'] != "--------":
            review_criteria.append(Review.test == form_data['test'])
        if form_data['report'] and form_data['report'] != "--------":
            review_criteria.append(Review.report == form_data['report'])
        
        if review_criteria:
            # 条件に一致するレビューを持つCourse.idをサブクエリで取得
            sub_query = db.session.query(Review.course_id).filter(*review_criteria).distinct()
            query = query.filter(Course.id.in_(sub_query))

        # --- SQLソート ---
        if sort_key == 'rating':
            # 評価平均でソート
            stmt = db.session.query(
                Review.course_id, func.avg(Review.rating).label('avg_rating')
            ).group_by(Review.course_id).subquery()
            
            query = query.outerjoin(stmt, Course.id == stmt.c.course_id)
            if sort_order == 'desc':
                query = query.order_by(stmt.c.avg_rating.desc().nullslast())
            else:
                query = query.order_by(stmt.c.avg_rating.asc().nullslast())
            
        elif sort_key == 'reviews':
            # レビュー数でソート
            stmt = db.session.query(
                Review.course_id, func.count(Review.id).label('review_count')
            ).group_by(Review.course_id).subquery()
            
            query = query.outerjoin(stmt, Course.id == stmt.c.course_id)
            if sort_order == 'desc':
                query = query.order_by(stmt.c.review_count.desc().nullslast())
            else:
                query = query.order_by(stmt.c.review_count.asc().nullslast())
                
        else:
            # ID順
            if sort_order == 'desc':
                query = query.order_by(Course.id.desc())
            else:
                query = query.order_by(Course.id.asc())

        # --- ページネーション実行 ---
        # 検索一覧でも各カードで★の数やレビュー件数を表示しているため、ここで取得しておく必要がある
        pagination = query.options(joinedload(Course.reviews)).paginate(
            page=page, per_page=per_page, error_out=False
        )
    
    except Exception as e:
        app.logger.error(f"Search Error: {e}")
        # エラー発生時は空の結果を返すか、エラーメッセージを表示
        flash('検索中にエラーが発生しました。条件を変更して再度お試しください。', 'danger')
        return render_template('search.html', 
                               pagination=None, 
                               search_term=None, 
                               form_data=form_data)
    
    return render_template('search.html', 
                           pagination=pagination, 
                           search_term=None, 
                           form_data=form_data)

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.options(joinedload(Course.reviews)).get_or_404(id)
    rating_counts = { '5': 0, '4': 0, '3': 0, '2': 0, '1': 0 }
    total_reviews = len(course.reviews)
    for review in course.reviews:
        r = review.rating
        if r == 5.0: rating_counts['5'] += 1
        elif r >= 4.0: rating_counts['4'] += 1
        elif r >= 3.0: rating_counts['3'] += 1
        elif r >= 2.0: rating_counts['2'] += 1
        else: rating_counts['1'] += 1
    rating_distribution = {}
    if total_reviews > 0:
        for star, count in rating_counts.items():
            rating_distribution[star] = {'count': count, 'percentage': (count / total_reviews) * 100}
    else:
        for star in rating_counts.keys():
            rating_distribution[star] = { 'count': 0, 'percentage': 0 }
    return render_template('detail.html', course=course, rating_distribution=rating_distribution)

@app.route('/course_view/<int:id>')
@login_required
def course_view_detail(id):
    course = Course.query.options(joinedload(Course.reviews)).get_or_404(id)
    rating_counts = { '5': 0, '4': 0, '3': 0, '2': 0, '1': 0 }
    total_reviews = len(course.reviews)
    for review in course.reviews:
        r = review.rating
        if r == 5.0: rating_counts['5'] += 1
        elif r >= 4.0: rating_counts['4'] += 1
        elif r >= 3.0: rating_counts['3'] += 1
        elif r >= 2.0: rating_counts['2'] += 1
        else: rating_counts['1'] += 1
    rating_distribution = {}
    if total_reviews > 0:
        for star, count in rating_counts.items():
            rating_distribution[star] = {'count': count, 'percentage': (count / total_reviews) * 100}
    else:
        for star in rating_counts.keys():
            rating_distribution[star] = { 'count': 0, 'percentage': 0 }
    return render_template('detail2.html', course=course, rating_distribution=rating_distribution)

@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    
    # ゲストユーザーのダミー投稿処理
    if current_user.email.endswith('@demo.com'):
        # 本来ならここでDB保存処理だが、ゲストなのでスキップ
        # ユーザーには成功メッセージを表示（体感速度向上）
        flash('レビューを投稿しました。（デモ動作：ゲストのため実際には保存されません）', 'success')
        return redirect(url_for('course_view_detail', id=id))

    if Review.query.filter_by(course_id=id, user_id=current_user.id).first():
        flash('既にレビューを投稿しています。', 'warning')
        return redirect(url_for('course_detail', id=id))
    try:
        new_review = Review(
            rating=float(request.form.get('rating')),
            attendance=request.form.get('attendance'),
            test=request.form.get('test'),
            report=request.form.get('report'),
            course_format=request.form.get('course_format'),
            year=request.form.get('year'),
            classroom=request.form.get('classroom'),
            review=request.form.get('review'),
            course_id=course.id, 
            user_id=current_user.id
        )
        db.session.add(new_review)
        db.session.commit()
        flash('レビューを投稿しました。', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add review error: {e}")
        flash('エラーが発生しました。', 'danger')
    return redirect(url_for('course_view_detail', id=id))

@app.route('/api/react', methods=['POST'])
@login_required
def api_react():
    data = request.get_json()
    review_id = data.get('review_id')
    reaction_type = data.get('reaction_type')
    if not review_id or not reaction_type: return jsonify({'error': 'Missing data'}), 400
    review = Review.query.get(review_id)
    if not review: return jsonify({'error': 'Review not found'}), 404
    existing_reaction = ReviewReaction.query.filter_by(user_id=current_user.id, review_id=review_id).first()
    current_user_reaction = None
    try:
        if existing_reaction:
            if existing_reaction.reaction_type == reaction_type:
                db.session.delete(existing_reaction)
                current_user_reaction = None
            else:
                existing_reaction.reaction_type = reaction_type
                current_user_reaction = reaction_type
        else:
            new_reaction = ReviewReaction(user_id=current_user.id, review_id=review_id, reaction_type=reaction_type)
            db.session.add(new_reaction)
            current_user_reaction = reaction_type
        db.session.commit()
        return jsonify({'success': True, 'counts': review.get_reaction_counts(), 'user_reaction': current_user_reaction})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Reaction error: {e}")
        return jsonify({'error': 'Database error'}), 500
    
@app.route('/help')
@login_required
def help_page():
    return render_template('help.html')

@app.route('/complete_tutorial')
@login_required
def complete_tutorial():
    if not current_user.is_tutorial_seen:
        current_user.is_tutorial_seen = True
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/swipe')
@login_required
def swipe_page():
    return render_template('swipe.html')

@app.route('/api/fetch_cards')
@login_required
def fetch_cards():
    # 1. 自分が既にレビューした講義IDを取得（サブクエリで高速化）
    reviewed_subquery = db.session.query(Review.course_id)\
        .filter(Review.user_id == current_user.id)

    # クエリのベースを作成（まだレビューしていない講義を除外）
    query = Course.query.filter(~Course.id.in_(reviewed_subquery))

    # 2. 学部フィルタリング（ユーザーに学部が設定されている場合のみ適用）
    if current_user.faculty:
        query = query.filter(
            or_(
                Course.department.like(f'%{current_user.faculty}%'),
                Course.department.like('%共通教育等科目%')
            )
        )
    
    # 3. 高速化のため、まずIDリストを取得してPython側でランダムサンプリング
    # IDのみを取得する軽量クエリ
    candidate_ids = [r[0] for r in query.with_entities(Course.id).all()]
    
    if not candidate_ids:
        return jsonify([])

    # IDリストからランダムに10個選ぶ
    sample_size = min(len(candidate_ids), 10)
    selected_ids = random.sample(candidate_ids, sample_size)
    
    # 選ばれたIDの講義データを取得
    cards = Course.query.filter(Course.id.in_(selected_ids)).all()

    data = [{
        'id': c.id,
        'name': c.name,
        'teacher': c.teacher,
        'format': c.format,
        'department': c.department
    } for c in cards]
    
    random.shuffle(data)
    
    return jsonify(data)

@app.route('/edit_review/<int:review_id>', methods=['GET', 'POST'])
@login_required
def edit_review(review_id):
    review = Review.query.get_or_404(review_id)
    if review.user_id != current_user.id:
        flash('他のユーザーのレビューは編集できません。', 'danger')
        return redirect(url_for('course_detail', id=review.course_id))
    
    if request.method == 'POST':
        try:
            review.rating = float(request.form.get('rating'))
            review.attendance = request.form.get('attendance')
            review.test = request.form.get('test')
            review.report = request.form.get('report')
            review.course_format = request.form.get('course_format')
            review.year = request.form.get('year')
            review.classroom = request.form.get('classroom')
            review.review = request.form.get('review')
            
            db.session.commit()
            flash('レビューを更新しました。', 'success')
            return redirect(url_for('course_view_detail', id=review.course_id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Update review error: {e}")
            flash('更新中にエラーが発生しました。', 'danger')

    return render_template('edit_review.html', review=review, course=review.course)

@app.route('/delete_review/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    if review.user_id != current_user.id:
        flash('他のユーザーのレビューは削除できません。', 'danger')
        return redirect(url_for('course_detail', id=review.course_id))
    
    try:
        course_id = review.course_id
        db.session.delete(review)
        db.session.commit()
        flash('レビューを削除しました。', 'success')
        return redirect(url_for('course_view_detail', id=course_id))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete review error: {e}")
        flash('削除中にエラーが発生しました。', 'danger')
        return redirect(url_for('course_view_detail', id=review.course_id))

@app.route('/mypage', methods=['GET', 'POST'])
@login_required
def mypage():
    if request.method == 'POST':
        try:
            if current_user.email.endswith('@demo.com'):
                flash('ゲストユーザーのプロフィールは変更できません。', 'warning')
                return redirect(url_for('mypage'))

            current_user.username = request.form.get('username')
            current_user.faculty = request.form.get('faculty')
            current_user.department = request.form.get('department')
            current_user.grade = request.form.get('grade')
            
            db.session.commit()
            flash('プロフィールを更新しました。', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('そのユーザー名は既に使用されています。', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Profile update error: {e}")
            flash('更新中にエラーが発生しました。', 'danger')
        return redirect(url_for('mypage'))
        
    return render_template('mypage.html', user=current_user)

if __name__ == '__main__':
    # 開発環境用の設定
    if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')):
        os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'))
    
    # 手動起動(python app.py)の場合のDB作成
    # ※ 本番環境(Gunicorn)ではここは実行されない
    with app.app_context(): db.create_all()
    
    # 環境変数PORTに対応（Render等）
    port = int(os.environ.get('PORT', 5005))
    
    # 環境変数 FLASK_ENV が 'development' の場合のみデバッグモードを有効にする
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # 0.0.0.0 でバインドして外部アクセスを許可
    app.run(debug=debug_mode, host='0.0.0.0', port=port)