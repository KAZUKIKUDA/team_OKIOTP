import os

# このファイルの絶対パスを基準に、プロジェクトのルートディレクトリを設定
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Flaskアプリケーションの設定を管理するクラス"""

    # --- 基本設定 ---
    # SECRET_KEYは環境変数から読み込む。
    # 設定されていない場合は、開発用の安全でないデフォルトキーを使用する。
    # (本番環境では必ず環境変数の設定が必要です)
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev')
    
    if SECRET_KEY == 'default-secret-key-for-dev':
        print("="*50)
        print("警告: 環境変数 'SECRET_KEY' が設定されていません。")
        print("       開発用のデフォルトキーを使用します。")
        print("       本番環境では必ず 'SECRET_KEY' を設定してください。")
        print("="*50)


    # --- データベース設定 (Render対応) ---
    # Renderが提供する 'DATABASE_URL' (PostgreSQL) を優先的に使用する。
    # 環境変数 'DATABASE_URL' がない場合 (ローカル開発時) は、
    # 'instance' フォルダ内の 'lectures.db' (SQLite) を使用する。
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'lectures.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    # --- メール設定 (Flask-Mail) ---
    # 環境変数から読み込む (ローカル開発用にデフォルト値を設定)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']

    # ユーザー名とパスワードも環境変数から読み込む
    # (これらはローカルでも本番でも環境変数に設定することを推奨)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
        
    # メール送信元として表示される名前とアドレス
    MAIL_DEFAULT_SENDER = ('講義レビューサイト', MAIL_USERNAME)
