-- nosec: Deliberately vulnerable challenge seed data for authentication training levels (not production credentials)
-- Level 1: SQL Injection
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP) — PBKDF2WithHmacSHA256 (600000 iterations, per-user salt: username+algorithm)
INSERT INTO auth_users VALUES (4, 'admin_md5', 'b3e106dd03b597c31f885c29ab5b1da31f8e6e356e9902a2e34d6e49d909a009', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS) — PBKDF2WithHmacSHA256 (600000 iterations, per-user salt: username+algorithm)
INSERT INTO auth_users VALUES (5, 'admin_sha1', '95475dac41992c82fc8a9f8ce8a4531f624df4deedb3143f17f312cecf4622ba', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (m8D!4kLr#2jZ) — PBKDF2WithHmacSHA256 (600000 iterations, per-user salt: username+algorithm)
INSERT INTO auth_users VALUES (6, 'admin_sha256', '58847c9987c5c10cfa4e486468615f70a671952243f69352ebdaf163debbaafe', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk) — PBKDF2WithHmacSHA256 (600000 iterations, per-user salt: username+algorithm)
INSERT INTO auth_users VALUES (7, 'admin_enum', '257fcf71c11055ad318e4b96fc04d4ab0fc88909ee52797c6b8973adf13d6fde', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
