-- Table is seeded by CryptographicFailuresSeeder in vulnerability.service.cryptographicFailures

DROP TABLE IF EXISTS cryptographic_failures_vault;

CREATE TABLE cryptographic_failures_vault (
    level INT PRIMARY KEY ,
    password VARCHAR(500),
    algorithm VARCHAR(50)
);

-- Application user has full access (for functional purposes)
GRANT ALL ON cryptographic_failures_vault TO application;

-- Not a real credential - demo H2 in-memory database user for training exercise
CREATE USER IF NOT EXISTS cryptographic_failures_user PASSWORD 'cryptographic_failures_password';
GRANT SELECT ON cryptographic_failures_vault TO cryptographic_failures_user;