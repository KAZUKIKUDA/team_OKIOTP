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
import logging
import time
import requests
from bs4 import BeautifulSoup

# SendGrid
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail

# 集計用
from collections import Counter
from sqlalchemy.orm import joinedload

# URLパース
from urllib.parse import urlparse, parse_qs

# --- Application Setup ---
app = Flask(__name__)
app.config.from_object(Config)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
migrate = Migrate(app, db)

try:
    SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
    if not SENDGRID_API_KEY:
        app.logger.warning("環境変数 'SENDGRID_API_KEY' が設定されていません。")
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

# ▼▼▼【重要】キャッシュ無効化の設定を追加 ▼▼▼
# これにより、他人のログイン状態が表示される事故を防ぎます
@app.after_request
def add_header(response):
    """
    ブラウザやCDNに、ページをキャッシュしないように指示するヘッダーを追加。
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response
# ▲▲▲ 追加ここまで ▲▲▲

# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False) 
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher = db.Column(db.String(100), nullable=False)
    syllabus_url = db.Column(db.String(300), nullable=True)
    
    subject_code = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    credits = db.Column(db.String(10), nullable=True)
    format = db.Column(db.String(50), nullable=True)
    syllabus_year = db.Column(db.String(20), nullable=True)

    reviews = db.relationship('Review', backref='course', lazy=True, cascade="all, delete-orphan")

    __table_args__ = (
        db.UniqueConstraint('name', 'teacher', name='_name_teacher_uc'),
    )

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


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# --- Helper Functions ---

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

    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None


# --- Routes ---

@app.route('/')
@login_required 
def index():
    try:
        form_data = {
            'lecture_name': '', 'teacher_name': '', 'course_format': '',
            'attendance': '', 'test': '', 'report': ''
        }
        
        # 星の数ランキングTOP10 (Pythonで計算)
        all_courses = Course.query.options(joinedload(Course.reviews)).all()
        
        courses_with_ratings = []
        for course in all_courses:
            rating_str = course.star_rating
            if rating_str != "評価なし":
                try:
                    courses_with_ratings.append((course, float(rating_str)))
                except ValueError:
                    continue
        
        sorted_courses = sorted(courses_with_ratings, key=lambda x: x[1], reverse=True)
        top_courses = [course for course, rating in sorted_courses[:10]]

    except Exception as e:
        app.logger.error(f"Error fetching top courses: {e}")
        top_courses = []
    
    return render_template('top.html', top_courses=top_courses, form_data=form_data)

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

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                username=username, email=email, password=hashed_password, is_verified=False
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
            
            if sg:
                response = sg.send(message)
            
            db.session.commit()
            
            flash('確認メールを送信しました。メール内のリンクをクリックして登録を完了してください。', 'success')
            return redirect(url_for('login'))

        except IntegrityError: 
            db.session.rollback() 
            existing_user_by_email = User.query.filter_by(email=email).first()
            existing_user_by_name = User.query.filter_by(username=username).first()

            if existing_user_by_name:
                flash('そのユーザー名は既に使用されています。', 'danger')
            elif existing_user_by_email:
                if existing_user_by_email.is_verified:
                    flash('このメールアドレスは既に使用されています。', 'danger')
                    return redirect(url_for('login'))
                else:
                    flash('このメールアドレスは登録済みですが、未認証です。認証メールを再送しますか？', 'warning')
                    return redirect(url_for('resend_activation'))
            else:
                flash('データベースエラーが発生しました。', 'danger')
            return redirect(url_for('register'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {e}")
            flash('不明なエラーが発生しました。', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except SignatureExpired:
        flash('認証リンクの有効期限が切れています。再度リクエストしてください。', 'danger')
        return redirect(url_for('resend_activation'))
    except BadTimeSignature:
        flash('認証リンクが無効です。', 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('ユーザーが見つかりません。', 'danger')
        return redirect(url_for('register'))

    if not user.is_verified:
        user.is_verified = True
        db.session.commit()
        flash('メール認証が完了しました。ログインしてください。', 'success')
    else:
        flash('このアカウントは既に認証済みです。', 'info')
        
    return redirect(url_for('login'))

@app.route('/resend_activation', methods=['GET', 'POST'])
def resend_activation():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('再送リンクを送信しました（未登録の場合も表示）。', 'info')
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
            
            message = SendGridMail(
                from_email=(SENDER_EMAIL, SENDER_NAME),
                to_emails=email,
                subject='講義レビュー | メールアドレスの確認 (再送)',
                html_content=html_content
            )
            
            if sg:
                sg.send(message)

            flash('新しい認証リンクを送信しました。', 'success')
        except Exception:
            flash('メール送信中にエラーが発生しました。', 'danger')

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
            flash('アカウントが未認証です。認証メールを再送しますか？', 'warning')
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
        username = request.form.get('username')
        if not username:
            flash('お名前を入力してください。', 'danger')
            return redirect(url_for('guest_login'))
            
        if User.query.filter_by(username=username).first():
            flash('その名前は使用されています。別の名前を入力してください。', 'danger')
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
        except Exception:
            db.session.rollback()
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
    
    time.sleep(3)
    course_data = scrape_syllabus(syllabus_url)
    
    if course_data is None:
        flash('シラバス情報の取得に失敗しました。', 'danger')
        return redirect(url_for('index')) 
    
    scraped_name = course_data.get('講義名')
    scraped_teacher = course_data.get('教員名')

    existing_course = Course.query.filter_by(
        name=scraped_name, teacher=scraped_teacher
    ).first()
    
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
        name = request.form.get('name')
        teacher = request.form.get('teacher')
        syllabus_url = request.form.get('syllabus_url')
        
        if not name or not teacher or not syllabus_url:
            flash('登録データが不足しています。', 'danger')
            return redirect(url_for('index')) 

        if Course.query.filter_by(name=name, teacher=teacher).first():
            flash(f'講義「{name}」は既に登録されています。', 'info')
            return redirect(url_for('index')) 
            
        new_course = Course(
            name=name, teacher=teacher, syllabus_url=syllabus_url,
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
        flash('既に登録されている可能性があります。', 'danger')
        return redirect(url_for('index')) 
    except Exception:
        db.session.rollback()
        flash('登録中にエラーが発生しました。', 'danger')
        return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_course():
    search_term = None 
    results = []
    
    form_data = {
        'lecture_name': request.form.get('lecture_name', ''),
        'teacher_name': request.form.get('teacher_name', ''),
        'course_format': request.form.get('course_format', ''),
        'department': request.form.get('department', ''),
        'attendance': request.form.get('attendance', ''),
        'test': request.form.get('test', ''),
        'report': request.form.get('report', '')
    }

    if request.method == 'POST':
        lecture_name = form_data['lecture_name']
        teacher_name = form_data['teacher_name']
        course_format_filter = form_data['course_format']
        attendance = form_data['attendance']
        test = form_data['test']
        report = form_data['report']
        department = form_data['department']

        # N+1問題を避けるため reviews をEager Loading
        query = Course.query.options(joinedload(Course.reviews))
        
        filters = []
        # Reviewのフィルタ (course_formatはReviewにもあるが、Courseにもあるため注意。ここではCourseのformatを使用)
        review_filters = [] 

        if lecture_name:
            for term in lecture_name.split():
                filters.append(Course.name.like(f'%{term}%'))
        
        if teacher_name:
            for term in teacher_name.split():
                filters.append(Course.teacher.like(f'%{term}%'))
        
        if course_format_filter and course_format_filter != "--------":
            filters.append(Course.format == course_format_filter)
            
        if department and department != "--------":
            filters.append(Course.department.like(f'%{department}%'))

        if filters:
            query = query.filter(db.and_(*filters))
            
        # Reviewのフィルタがある場合は結合 (今回はCourseのformatを使ったので不要だが、将来のために残す)
        if review_filters:
            query = query.join(Review, Course.id == Review.course_id).filter(db.and_(*review_filters))

        query = query.distinct()
        
        try:
            initial_results = query.all()
        except Exception as e:
            app.logger.error(f"Search query error: {e}")
            initial_results = []
            flash('検索中にエラーが発生しました。', 'danger')

        results = initial_results

        # Pythonでのフィルタリング (最頻値)
        # 1. 出席
        if attendance and attendance != "--------":
            filtered_results = []
            for course in results:
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
            results = filtered_results

        # 2. テスト
        if test and test != "--------":
            filtered_results = []
            for course in results:
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
            results = filtered_results

        # 3. レポート
        if report and report != "--------":
            filtered_results = []
            for course in results:
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
            results = filtered_results
            
    else: 
        try:
            # 全件取得してソートするのは重いため、最新20件などを取得するに留める
            results = Course.query.options(joinedload(Course.reviews)).order_by(db.desc(Course.id)).limit(20).all()
        except Exception:
            results = []
            
    return render_template('search.html', results=results, search_term=search_term, form_data=form_data)

@app.route('/course/<int:id>')
@login_required
def course_detail(id):
    course = Course.query.options(joinedload(Course.reviews)).get_or_404(id)

    rating_counts = { '5': 0, '4': 0, '3': 0, '2': 0, '1': 0 }
    total_reviews = 0

    if course.reviews:
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
            rating_distribution[star] = {
                'count': count,
                'percentage': (count / total_reviews) * 100
            }
    else:
        for star in rating_counts.keys():
            rating_distribution[star] = { 'count': 0, 'percentage': 0 }
    
    return render_template('detail.html', course=course, rating_distribution=rating_distribution)

@app.route('/course_view/<int:id>')
@login_required
def course_view_detail(id):
    course = Course.query.options(joinedload(Course.reviews)).get_or_404(id)

    rating_counts = { '5': 0, '4': 0, '3': 0, '2': 0, '1': 0 }
    total_reviews = 0

    if course.reviews:
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
            rating_distribution[star] = {
                'count': count,
                'percentage': (count / total_reviews) * 100
            }
    else:
        for star in rating_counts.keys():
            rating_distribution[star] = { 'count': 0, 'percentage': 0 }
    
    return render_template('detail2.html', course=course, rating_distribution=rating_distribution)

@app.route('/add_review/<int:id>', methods=['POST'])
@login_required
def add_review(id):
    course = Course.query.get_or_404(id)
    
    if current_user.email.endswith('@demo.com'):
        flash('ゲストユーザーはレビューを投稿できません。', 'warning')
        return redirect(url_for('course_detail', id=id))

    if Review.query.filter_by(course_id=id, user_id=current_user.id).first():
        flash('既にレビューを投稿しています。', 'warning')
        return redirect(url_for('course_detail', id=id))

    rating = request.form.get('rating')
    attendance = request.form.get('attendance')
    test = request.form.get('test')
    report = request.form.get('report')
    course_format = request.form.get('course_format')
    review_text = request.form.get('review')
    year = request.form.get('year')
    classroom = request.form.get('classroom')

    if not all([rating, attendance, test, report]):
        flash('必須項目を入力してください。', 'danger')
        return redirect(url_for('course_detail', id=id))
        
    try:
        rating_float = float(rating)
        new_review = Review(
            rating=rating_float, attendance=attendance, test=test, report=report,
            course_format=course_format, year=year, classroom=classroom,
            review=review_text, course_id=course.id, user_id=current_user.id
        )
        
        db.session.add(new_review)
        db.session.commit()
        flash('レビューを投稿しました。', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add review error: {e}")
        flash('エラーが発生しました。', 'danger')
        
    return redirect(url_for('course_view_detail', id=id))

if __name__ == '__main__':
    if not os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')):
        os.makedirs(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'))
    
    with app.app_context():
        db.create_all()

    app.run(debug=True, port=5002)