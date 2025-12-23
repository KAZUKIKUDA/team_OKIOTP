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
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        
        # ▼▼▼ 修正: SSLモードを明示的に指定する (Supabase接続用) ▼▼▼
        # URLの末尾にクエリパラメータとして追加する形が確実です
        if 'sslmode' not in database_url:
            # 既存のクエリパラメータがあるかチェック
            if '?' in database_url:
                database_url += '&sslmode=require'
            else:
                database_url += '?sslmode=require'
        # ▲▲▲ 修正ここまで ▲▲▲

    # Renderの 'DATABASE_URL' があればそれを使い、なければローカルのSQLiteを使う
    SQLALCHEMY_DATABASE_URI = database_url or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'lectures.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ▼▼▼ 修正: DB接続の安定化設定 (調整版) ▼▼▼
    # RenderやSupabaseでのSSL接続エラーやタイムアウトを防ぐための設定です
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,   # 接続前に生存確認を行う（重要：切断されていたら再接続する）
        'pool_recycle': 120,     # 280秒から120秒へ短縮（より頻繁にリサイクルして切断を防ぐ）
        'pool_size': 5,          # プール数を少し減らして接続数制限に配慮 (10 -> 5)
        'max_overflow': 10,      # あふれた場合の最大接続数 (20 -> 10)
        'pool_timeout': 60,      # 接続待ちタイムアウトを延長 (30 -> 60)
        'connect_args': {
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 5
        }
    }
    # ▲▲▲ 修正ここまで ▲▲▲

    # --- メール設定 ---
    # SendGrid API (app.pyで直接os.environ.get) を使うため、Flask-Mailの設定はすべて不要