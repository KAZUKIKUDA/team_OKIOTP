# config.py

import os

class Config:
    """Flaskアプリケーションの設定を管理するクラス"""

    # --- 基本設定 ---
    # SECRET_KEYは必須。設定されていない場合はエラーを発生させます。
    try:
        SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev')
    except KeyError:
        raise RuntimeError("環境変数 'SECRET_KEY' が設定されていません。")

    # --- データベース設定 ---
    SQLALCHEMY_DATABASE_URI = "sqlite:///lectures.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- メール設定 ---
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    # ユーザー名とパスワードも必須。環境変数から読み込みます。
    # ※ 事前に環境変数の設定が必要です
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
        
    # メール送信元として表示される名前とアドレス
    MAIL_DEFAULT_SENDER = ('講義レビューサイト', MAIL_USERNAME)