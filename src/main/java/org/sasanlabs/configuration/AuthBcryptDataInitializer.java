package org.sasanlabs.configuration;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
    private final String securePassword;
    private final String lowCostPassword;

    public AuthBcryptDataInitializer(
            @Qualifier("adminDataSource") DataSource adminDataSource,
            @Value("${vuln.auth.level9.password:9fG#2hJk*LmN!8qR}") String securePassword,
            @Value("${vuln.auth.level10.password:sunshine}") String lowCostPassword) {
        this.jdbcTemplate = new JdbcTemplate(adminDataSource);
        this.securePassword = securePassword;
        this.lowCostPassword = lowCostPassword;
    }

    @PostConstruct
    public void insertBcryptUsers() {
        BCryptPasswordEncoder encoder10 = new BCryptPasswordEncoder(10);
        String secureHash = encoder10.encode(securePassword);
        jdbcTemplate.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                9,
                "admin_secure",
                secureHash,
                "BCRYPT",
                9,
                "admin_secure@example.com",
                "ADMIN");

        BCryptPasswordEncoder encoder4 = new BCryptPasswordEncoder(4);
        String lowCostHash = encoder4.encode(lowCostPassword);
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
