-- Level 1: SQL Injection
-- NOTSECRET: demo credential for training exercise (password value in INSERT below is intentional test data)
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- NOTSECRET: demo credential for training exercise (password value in INSERT below is intentional test data)
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- NOTSECRET: demo credential for training exercise (password value in INSERT below is intentional test data)
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP) — PBKDF2-HMAC-SHA256 with 600000 iterations
INSERT INTO auth_users VALUES (4, 'admin_md5', 'ec65a12c206babe7e161a97f70c7d32d582dcc29c19388f7e59752e2a4e08b05', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS) — PBKDF2-HMAC-SHA256 with 600000 iterations
INSERT INTO auth_users VALUES (5, 'admin_sha1', 'cbba729b08a70cad98787a84574b2043499cd9cd81b9d0a074d2a35e4c47be09', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (m8D!4kLr#2jZ) — PBKDF2-HMAC-SHA256 with 600000 iterations
INSERT INTO auth_users VALUES (6, 'admin_sha256', '9c3ac94e132774798b7a638cbe5d5e5d7e74f8fa4963a213d93067b9777becfc', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk) — PBKDF2-HMAC-SHA256 with 600000 iterations
INSERT INTO auth_users VALUES (7, 'admin_enum', '069892fbfe82d9fa477544ef288c540243fc1d70ccee5e0f5d7b1f5403362071', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
