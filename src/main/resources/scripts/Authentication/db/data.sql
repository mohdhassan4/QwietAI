-- Level 1: SQL Injection
-- Not a real secret — intentional demo credential for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Not a real secret — intentional demo credential for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (2, 'admin_logs', 'v9K#2mLp!8zQ', NULL, 'PLAIN', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Not a real secret — intentional demo credential for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (3, 'admin_plain', 'b7X$4nRj-6mW', NULL, 'PLAIN', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: BCrypt (upgraded from MD5) (f2C@9tYk*1hP)
-- Not a real secret — intentional demo password hash for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (4, 'admin_md5', '$2b$10$uRQ1Rq.Xed7OeipAYTUxleTblZLBkM5BVvPye.0fvIQ5msVpmy4Hu', NULL, 'MD5', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: BCrypt (upgraded from SHA1) (x5B&3gHq+7vS)
-- Not a real secret — intentional demo password hash for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (5, 'admin_sha1', '$2b$10$ci4yNxKMFWLiC09Z14ghdORKwaIGMuRA6B.XDIQhBiLTjRBYVq7w6', NULL, 'SHA1', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: SHA-256 (No Salt) (m8D!4kLr#2jZ)
-- Not a real secret — intentional demo password hash for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (6, 'admin_sha256', '8b8eca84f7e2b04f531749f999c3bf9e3f045bab78f4c8a451fa70929b3c3946', NULL, 'SHA256', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk)
-- Not a real secret — intentional demo password hash for vulnerability training (ephemeral H2 in-memory DB)
INSERT INTO auth_users VALUES (7, 'admin_enum', '71ad23cc508b5658f0bc21d8323f55521be98ca951e83a4a4d15641a3ca2b8a4', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: Weak Password + Bcrypt (password123)
-- Bcrypt hash for 'password123'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$10$gV2vZ5fxhZlwOP.GIqOI1.z7q5jws8VDmgIcKqY/uzvhzSUDio2sW', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: Low-iteration BCrypt (cost factor 4)
-- Bcrypt hash (cost 4) for the common password 'sunshine'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$04$rK/CT/Bz7GjjGLnB3WWjTOpMpNcGJzmoh.bdc7gQJ4DBQnKj9xnHC', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
