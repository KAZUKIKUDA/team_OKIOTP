"""Add review access unlock fields

Revision ID: c9f1a2b3c4d5
Revises: b42ba0eaef7e
Create Date: 2026-01-06

"""

from alembic import op
import sqlalchemy as sa
import datetime
from sqlalchemy.sql import text


# revision identifiers, used by Alembic.
revision = 'c9f1a2b3c4d5'
down_revision = 'b42ba0eaef7e'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pass_expires_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('permanent_access', sa.Boolean(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column('quick_review_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('detailed_review_count', sa.Integer(), nullable=False, server_default='0'))

    with op.batch_alter_table('review', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_quick', sa.Boolean(), nullable=False, server_default=sa.text('0')))

    bind = op.get_bind()

    # Backfill is_quick based on the existing placeholder used by swipe.html
    bind.execute(text("UPDATE review SET is_quick = 1 WHERE review = :q"), {'q': '【高速レビュー】'})

    # Aggregate counts by user
    rows = bind.execute(text(
        """
        SELECT
            user_id,
            SUM(CASE WHEN is_quick THEN 1 ELSE 0 END) AS quick_cnt,
            SUM(CASE WHEN is_quick THEN 0 ELSE 1 END) AS detailed_cnt
        FROM review
        GROUP BY user_id
        """
    )).fetchall()

    now = datetime.datetime.utcnow()

    for user_id, quick_cnt, detailed_cnt in rows:
        quick_cnt = int(quick_cnt or 0)
        detailed_cnt = int(detailed_cnt or 0)

        permanent_access = detailed_cnt >= 15

        pass_expires_at = None
        if not permanent_access:
            day_pass_days = detailed_cnt // 3
            if day_pass_days > 0:
                pass_expires_at = now + datetime.timedelta(days=day_pass_days)

        bind.execute(
            text(
                """
                UPDATE "user"
                SET quick_review_count = :q,
                    detailed_review_count = :d,
                    permanent_access = :p,
                    pass_expires_at = :e
                WHERE id = :uid
                """
            ),
            {
                'q': quick_cnt,
                'd': detailed_cnt,
                'p': permanent_access,
                'e': pass_expires_at,
                'uid': user_id,
            },
        )


def downgrade():
    with op.batch_alter_table('review', schema=None) as batch_op:
        batch_op.drop_column('is_quick')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('detailed_review_count')
        batch_op.drop_column('quick_review_count')
        batch_op.drop_column('permanent_access')
        batch_op.drop_column('pass_expires_at')
