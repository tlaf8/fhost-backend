DROP TABLE IF EXISTS login;

CREATE TABLE login
(
    username TEXT PRIMARY KEY,
    email    TEXT NOT NULL,
    password TEXT NOT NULL,
    salt     TEXT NOT NULL
);
