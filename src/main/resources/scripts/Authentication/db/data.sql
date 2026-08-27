-- Level 1: SQL Injection
-- Intentional demo credentials for OWASP VulnerableApp training levels (not real secrets)
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Real password: 'v9K#2mLp!8zQ'
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Real password: 'b7X$4nRj-6mW'
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP) — now stored as PBKDF2WithHmacSHA256 (600000 iterations)
-- Hash below is a one-way demo hash, not a secret
INSERT INTO auth_users VALUES (4, 'admin_md5', '51d7db1ae27674714fb2aeec8f2aa96e7f6ed36ed08af3169b5c29e9a796461d', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS) — now stored as PBKDF2WithHmacSHA256 (600000 iterations)
-- Hash below is a one-way demo hash, not a secret
INSERT INTO auth_users VALUES (5, 'admin_sha1', 'd69919b9449f904fe43b2e725a9b2a531f1d0888ff75f316ccf203d6d9c039e3', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (m8D!4kLr#2jZ) — now stored as PBKDF2WithHmacSHA256 (600000 iterations)
-- Hash below is a one-way demo hash, not a secret
INSERT INTO auth_users VALUES (6, 'admin_sha256', '1c54853086b998dddf67e12295e86d47f3325d6990c022f46ed47d0a43cbe607', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk) — now stored as PBKDF2WithHmacSHA256 (600000 iterations)
-- Hash below is a one-way demo hash, not a secret
INSERT INTO auth_users VALUES (7, 'admin_enum', '948ac766901df927f9b0fe2d55b814010316593a7ba772b1ebb4525dc91f3d29', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
