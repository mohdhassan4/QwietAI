package org.sasanlabs.configuration;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Inserts authentication rows that require bcrypt hashes at runtime, avoiding hardcoded hash
 * literals in SQL scripts. Runs after the admin DataSource initializer has created the schema.
 */
@Component
@DependsOn("adminDataSourceInitializer")
public class AuthBcryptDataInitializer {

    private final JdbcTemplate jdbcTemplate;

    public AuthBcryptDataInitializer(
            @Qualifier("adminDataSource") DataSource adminDataSource) {
        this.jdbcTemplate = new JdbcTemplate(adminDataSource);
    }

    @PostConstruct
    public void insertBcryptUsers() {
        // Level 9: Secure (Bcrypt + Generic Error) - cost factor 10
        BCryptPasswordEncoder encoder10 = new BCryptPasswordEncoder(10);
        String secureHash = encoder10.encode("9fG#2hJk*LmN!8qR");
        jdbcTemplate.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                9,
                "admin_secure",
                secureHash,
                "BCRYPT",
                9,
                "admin_secure@example.com",
                "ADMIN");

        // Level 10: Low-iteration BCrypt - cost factor 4
        BCryptPasswordEncoder encoder4 = new BCryptPasswordEncoder(4);
        String lowCostHash = encoder4.encode("sunshine");
        jdbcTemplate.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                10,
                "admin_lowcost",
                lowCostHash,
                "BCRYPT_LOW_ITERATION",
                10,
                "admin_lowcost@example.com",
                "ADMIN");
    }
}
