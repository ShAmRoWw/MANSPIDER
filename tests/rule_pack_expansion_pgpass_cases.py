"""Context-bound PostgreSQL password-file fixtures; all credentials are synthetic.

Rows are (path, content, rule_id). Negative rows concern only the named rule.
"""

CONTENT_CASES = [
    (".pgpass", "db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    ("home/alice/.pgpass.bak.2", "*:*:*:*:FixturePassword!", "postgresql-password-entry"),
    (
        "C:\\Users\\alice\\AppData\\Roaming\\postgresql\\pgpass.conf",
        "db.internal:5432:replication:replicator:SyntheticFixtureOnly!",
        "postgresql-password-entry",
    ),
    ("backups/PGPASS.CONF.OLD", "db.internal:5432:app:alice:p", "postgresql-password-entry"),
    (".pgpass.20260905", "db.internal:postgresql:app:alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass~", "db.internal:5432:app:alice:fixture\\:password\\\\with-slash", "postgresql-password-entry"),
    (".pgpass", "2001\\:db8\\:\\:1:5432:app\\:test:domain\\\\alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:учебныйПароль🔑", "postgresql-password-entry"),
    (
        "pgpass.conf",
        "# Host-specific fixture\r\ndb.internal:5432:app:alice:FixtureOne!\r\n*:5432:reports:bob:FixtureTwo!\r\n",
        "postgresql-password-entry",
    ),
    (
        ".pgpass",
        "\n# hostname:port:database:username:password\nlocalhost:5432:app:alice:PasswordWith Space\n",
        "postgresql-password-entry",
    ),
]

NEGATIVE_CASES = [
    ("notes.txt", "db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    ("pgpass.conf.example", "db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    ("pgpass.config", "db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    (".pgpass", "# db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    (".pgpass", " \t# db.internal:5432:app:alice:SyntheticFixtureOnly!", "postgresql-password-entry"),
    (".pgpass", "", "postgresql-password-entry"),
    (".pgpass", "\r\n", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:", "postgresql-password-entry"),
    (".pgpass", ":5432:app:alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal::app:alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432::alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app::FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:unescaped:colon", "postgresql-password-entry"),
    (".pgpass", "db.internal,5432,app,alice,FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:invalid\\escape", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:trailing\\", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:\napp:alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "x" * 257 + ":5432:app:alice:FixturePassword!", "postgresql-password-entry"),
    (".pgpass", "db.internal:5432:app:alice:" + "x" * 1025, "postgresql-password-entry"),
]

SOURCES = [
    "https://www.postgresql.org/docs/current/libpq-pgpass.html",
]
