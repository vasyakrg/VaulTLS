CREATE TABLE groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_on  INTEGER NOT NULL
);

CREATE TABLE group_users (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE group_certificates (
    group_id       INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
    certificate_id INTEGER NOT NULL REFERENCES user_certificates(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, certificate_id)
);
