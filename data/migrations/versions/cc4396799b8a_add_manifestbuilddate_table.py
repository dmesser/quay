"""Add ManifestBuildDate table

Revision ID: cc4396799b8a
Revises: 414c5e2fc487
Create Date: 2026-03-07 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "cc4396799b8a"
down_revision = "414c5e2fc487"

import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


def upgrade(op, tables, tester):
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)

    if "manifestbuilddate" not in inspector.get_table_names():
        op.create_table(
            "manifestbuilddate",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("manifest_id", sa.Integer(), nullable=False),
            sa.Column("repository_id", sa.Integer(), nullable=False),
            sa.Column("build_date", sa.BigInteger(), nullable=True),
            sa.ForeignKeyConstraint(
                ["manifest_id"],
                ["manifest.id"],
                name=op.f("fk_manifestbuilddate_manifest_id_manifest"),
            ),
            sa.ForeignKeyConstraint(
                ["repository_id"],
                ["repository.id"],
                name=op.f("fk_manifestbuilddate_repository_id_repository"),
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_manifestbuilddate")),
        )

        op.create_index(
            "manifestbuilddate_manifest_id",
            "manifestbuilddate",
            ["manifest_id"],
            unique=True,
        )

        op.create_index(
            "manifestbuilddate_repository_id",
            "manifestbuilddate",
            ["repository_id"],
            unique=False,
        )

    tester.populate_table(
        "manifestbuilddate",
        [
            ("manifest_id", tester.TestDataType.Foreign("manifest")),
            ("repository_id", tester.TestDataType.Foreign("repository")),
            ("build_date", tester.TestDataType.BigInteger),
        ],
    )


def downgrade(op, tables, tester):
    op.drop_table("manifestbuilddate")
