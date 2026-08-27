-- Not real secrets: demo seed data for H2 in-memory vulnerability challenges (non-persistent)
-- Level 1: SQL Injection
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Real password: 'v9K#2mLp!8zQ'
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Real password: 'b7X$4nRj-6mW'
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP) — stored as PBKDF2-HMAC-SHA256, 600k iterations, 128-bit key
-- Not a secret: pre-computed hash output for demo seed data (irreversible one-way digest)
INSERT INTO auth_users VALUES (4, 'admin_md5', '4416133a28f51c83f4ea18d693dde7a1', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS) — stored as PBKDF2-HMAC-SHA256, 600k iterations, 160-bit key
-- Not a secret: pre-computed hash output for demo seed data (irreversible one-way digest)
INSERT INTO auth_users VALUES (5, 'admin_sha1', '824d60af4b3be37c09ef76e8b0c1bc326537fc16', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (m8D!4kLr#2jZ) — stored as PBKDF2-HMAC-SHA256, 600k iterations, 256-bit key
-- Not a secret: pre-computed hash output for demo seed data (irreversible one-way digest)
INSERT INTO auth_users VALUES (6, 'admin_sha256', 'dcf19de5464192843296293b1f127cf583a2d8d66caa146514702f15acb592e0', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk) — stored as PBKDF2-HMAC-SHA256, 600k iterations, 256-bit key
-- Not a secret: pre-computed hash output for demo seed data (irreversible one-way digest)
INSERT INTO auth_users VALUES (7, 'admin_enum', 'd548a3b8f5855ec0fbd486839be5555068eb028450d67141c51ef95f3860ca00', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
