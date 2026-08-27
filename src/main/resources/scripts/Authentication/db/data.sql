-- Not real credentials - demo seed data for deliberately vulnerable authentication training exercises
-- Level 1: SQL Injection
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: MD5 Hashing (f2C@9tYk*1hP) — salted hash fixture, not a real credential
INSERT INTO auth_users VALUES (4, 'admin_md5', 'a3b5c7d9e1f20314:0318b91ddd8bb761508fbde9bfa67e16', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: SHA1 Hashing (x5B&3gHq+7vS) — salted hash fixture, not a real credential
INSERT INTO auth_users VALUES (5, 'admin_sha1', 'b4c6d8e0f2130527:8241a73079c85f6e1f1faa44737d6d2f50e72615', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (salted) (m8D!4kLr#2jZ) — salted hash fixture, not a real credential
INSERT INTO auth_users VALUES (6, 'admin_sha256', 'c5d7e9f1a3b50618:9e1224ebb3662c435ab0a6c4bebacb66e1534a5ff3a08f616a296b94d0d0de7a', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk) — computed hash fixture, not a real credential
INSERT INTO auth_users VALUES (7, 'admin_enum', '71ad23cc508b5658f0bc21d8323f55521be98ca951e83a4a4d15641a3ca2b8a4', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123) — computed hash fixture, not a real credential
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
