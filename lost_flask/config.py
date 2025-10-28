import os

# このファイルの絶対パスを基準に、プロジェクトのルートディレクトリを設定
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Flaskアプリケーションの設定を管理するクラス"""

    # --- 基本設定 ---
    # Renderの環境変数 'SECRET_KEY' を読み込む
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev')
    
    if SECRET_KEY == 'default-secret-key-for-dev':
        print("="*50)
        print("警告: 環境変数 'SECRET_KEY' が設定されていません。")
        print("       開発用のデフォルトキーを使用します。")
        print("       本番環境では必ず 'SECRET_KEY' を設定してください。")
        print("="*50)

    # --- データベース設定 (Render対応) ---
    # Renderの 'DATABASE_URL' があればそれを使い、なければローカルのSQLiteを使う
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'lectures.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- メール設定 ---
    # SendGrid APIを使うため、Flask-MailのSMTP設定はすべて不要

