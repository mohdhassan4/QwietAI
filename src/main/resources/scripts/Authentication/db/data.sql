-- Level 1: SQL Injection
-- Not a real credential - demo seed data for authentication vulnerability training
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Not a real credential - demo seed data for authentication vulnerability training
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Not a real credential - demo seed data for authentication vulnerability training
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: PBKDF2-HMAC-SHA256 600k iterations (f2C@9tYk*1hP)
-- Not a secret: derived hash output used as test fixture for vulnerability training
INSERT INTO auth_users VALUES (4, 'admin_md5', 'dbc3410160fe81d9fdf72235c38a05547de460e76c530807832427f8c9fd4030', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: PBKDF2-HMAC-SHA256 600k iterations (x5B&3gHq+7vS)
-- Not a secret: derived hash output used as test fixture for vulnerability training
INSERT INTO auth_users VALUES (5, 'admin_sha1', 'b161f49b65c325273882622ac255d91f8c7c934b11855dc7ff0b42e930b76787', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: PBKDF2-HMAC-SHA256 600k iterations no salt (m8D!4kLr#2jZ)
-- Not a secret: derived hash output used as test fixture for vulnerability training
INSERT INTO auth_users VALUES (6, 'admin_sha256', 'c58da290e5bca59017d9059849da8db0ad9b78a82f850c052ced8dec2fd9e244', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: PBKDF2-HMAC-SHA256 600k iterations salted (q1W%6nTp^8vM with Salt s9A#2zLk)
-- Not a secret: derived hash output used as test fixture for vulnerability training
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
