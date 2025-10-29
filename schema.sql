-- This SQL command creates our 'users' table.
-- IF NOT EXISTS prevents an error if the table is already there.
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);