from app import app, db
from sqlalchemy import text

def add_column_to_render():
    """
    Render上のPostgreSQLデータベースにカラムを追加するスクリプト
    """
    print("🚀 データベースの更新を開始します...")
    
    with app.app_context():
        try:
            # "user" テーブルに "is_tutorial_seen" カラムを追加するSQL
            # PostgreSQLでは "user" は予約語のため、ダブルクォートで囲む必要があります
            sql = text('ALTER TABLE "user" ADD COLUMN is_tutorial_seen BOOLEAN DEFAULT FALSE')
            
            db.session.execute(sql)
            db.session.commit()
            
            print("✅ 成功: カラム 'is_tutorial_seen' を追加しました！")
            
        except Exception as e:
            # カラムが既に存在する場合などはエラーになりますが、データは安全です
            print(f"⚠️ エラー（または既に適用済み）: {e}")
            db.session.rollback()

if __name__ == '__main__':
    add_column_to_render()