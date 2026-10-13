CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  sender_id TEXT NOT NULL REFERENCES users(id),
  recipient_id TEXT NOT NULL REFERENCES users(id),
  subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 120),
  body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 3000),
  created TEXT NOT NULL,
  read_at TEXT,
  deleted_by_sender INTEGER NOT NULL DEFAULT 0,
  deleted_by_recipient INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX messages_recipient_unread ON messages(recipient_id, read_at, created);
CREATE INDEX messages_sender_created ON messages(sender_id, created);
