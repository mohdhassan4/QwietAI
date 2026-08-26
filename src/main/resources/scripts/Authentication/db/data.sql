-- NOTE: Passwords in this file are intentional training fixtures for the Authentication vulnerability module.
-- They demonstrate insecure storage patterns (plaintext, weak hashing) and are not production credentials.

-- Level 1: SQL Injection
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: PBKDF2-HMAC-SHA256 600k iterations (f2C@9tYk*1hP)
INSERT INTO auth_users VALUES (4, 'admin_md5', 'fb7f4932e4f61acbec751f3191a582807b16fb0b32e715f531415f928c2a2ae5', 'k3M8rTq2', 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: PBKDF2-HMAC-SHA256 600k iterations (x5B&3gHq+7vS)
INSERT INTO auth_users VALUES (5, 'admin_sha1', '2cc1fd4420ddda3de0c0f0e9ce5ccd3bad233aa5dc1adb482d13edd29e274875', 'j7N5wVx9', 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: PBKDF2-HMAC-SHA256 600k iterations (m8D!4kLr#2jZ)
INSERT INTO auth_users VALUES (6, 'admin_sha256', '307dc75a5645e5dbc23575bcd94eaf624ac8db6260ab8ae9eb2f6b62cf80618f', 'p4R9bGy6', 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: PBKDF2-HMAC-SHA256 600k iterations (q1W%6nTp^8vM with Salt s9A#2zLk)
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
