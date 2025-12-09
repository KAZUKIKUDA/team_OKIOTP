import os

# このファイルの絶対パスを基準に、プロジェクトのルートディレクトリを設定
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Flaskアプリケーションの設定を管理するクラス"""

    # --- 基本設定 ---
    # Renderの環境変数 'SECRET_KEY' を読み込む
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev')
    
    if SECRET_KEY == 'default-secret-key-for-dev' and os.environ.get('FLASK_ENV') != 'development':
        print("="*50)
        print("警告: 環境変数 'SECRET_KEY' が設定されていません。")
        print("       開発用のデフォルトキーを使用します。")
        print("       本番環境では必ず 'SECRET_KEY' を設定してください。")
        print("="*50)

    # --- データベース設定 (Render/Supabase対応) ---
    # 環境変数からDB URLを取得
    database_url = os.environ.get('DATABASE_URL')

    # SQLAlchemy 1.4以降 (2.0含む) では 'postgres://' はエラーになるため
    # 'postgresql://' に置換する処理を追加
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    # Renderの 'DATABASE_URL' があればそれを使い、なければローカルのSQLiteを使う
    SQLALCHEMY_DATABASE_URI = database_url or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'lectures.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- メール設定 ---
    # SendGrid API (app.pyで直接os.environ.get) を使うため、Flask-Mailの設定はすべて不要