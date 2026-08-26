package org.sasanlabs.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Generates bcrypt password hashes at startup from externalized configuration and updates the
 * auth_users table rows that were inserted with placeholder values by the SQL seed script.
 *
 * <p>Passwords MUST be supplied via environment variables or Spring properties — they are never
 * stored in source control.
 *
 * @author security-remediation
 */
@Component
public class AuthDataInitializer implements ModuleSeeder {

    private static final Logger LOGGER = LogManager.getLogger(AuthDataInitializer.class);
    private static final String PLACEHOLDER = "PENDING_HASH_GENERATION";

    private final JdbcTemplate jdbcTemplate;

    @Value("${auth.seed.password.level8:changeme}")
    private String level8Password;

    @Value("${auth.seed.password.level9:changeme}")
    private String level9Password;

    @Value("${auth.seed.password.level10:changeme}")
    private String level10Password;

    public AuthDataInitializer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void seed() {
        BCryptPasswordEncoder standardEncoder = new BCryptPasswordEncoder(10);
        BCryptPasswordEncoder lowCostEncoder = new BCryptPasswordEncoder(4);

        String level8Hash = standardEncoder.encode(level8Password);
        String level9Hash = standardEncoder.encode(level9Password);
        String level10Hash = lowCostEncoder.encode(level10Password);

        jdbcTemplate.update(
                "UPDATE auth_users SET password = ? WHERE id = ? AND password = ?",
                level8Hash,
                8,
                PLACEHOLDER);
        jdbcTemplate.update(
                "UPDATE auth_users SET password = ? WHERE id = ? AND password = ?",
                level9Hash,
                9,
                PLACEHOLDER);
        jdbcTemplate.update(
                "UPDATE auth_users SET password = ? WHERE id = ? AND password = ?",
                level10Hash,
                10,
                PLACEHOLDER);

        LOGGER.info("Auth bcrypt hashes generated from configuration and applied to seed data");
    }

    @Override
    public boolean isSeeded() {
        Integer count =
                jdbcTemplate.queryForObject(
                        "SELECT COUNT(*) FROM auth_users WHERE password = ?",
                        Integer.class,
                        PLACEHOLDER);
        return count == null || count == 0;
    }

    @Override
    public String getModuleTable() {
        return "auth_users";
    }

    @Override
    public String getModuleName() {
        return "Authentication";
    }
}
