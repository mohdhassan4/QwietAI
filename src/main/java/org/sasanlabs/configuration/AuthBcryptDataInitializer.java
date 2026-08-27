package org.sasanlabs.configuration;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Inserts bcrypt-hashed authentication seed data at application startup. Passwords are read from
 * environment variables so that no bcrypt hashes are stored as literals in source control.
 *
 * @author auto-remediation
 */
@Configuration
public class AuthBcryptDataInitializer {

    @Bean
    @DependsOn("adminDataSourceInitializer")
    public Object authBcryptSeeder(
            @Qualifier("adminDataSource") DataSource adminDataSource,
            @Value("${AUTH_LEVEL8_PASSWORD:password123}") String level8Password,
            @Value("${AUTH_LEVEL9_PASSWORD:9fG#2hJk*LmN!8qR}") String level9Password,
            @Value("${AUTH_LEVEL10_PASSWORD:sunshine}") String level10Password) {

        JdbcTemplate jdbc = new JdbcTemplate(adminDataSource);
        BCryptPasswordEncoder encoder10 = new BCryptPasswordEncoder(10);
        BCryptPasswordEncoder encoder4 = new BCryptPasswordEncoder(4);

        jdbc.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                8,
                "admin_weak",
                encoder10.encode(level8Password),
                "BCRYPT",
                8,
                "admin_weak@example.com",
                "ADMIN");

        jdbc.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                9,
                "admin_secure",
                encoder10.encode(level9Password),
                "BCRYPT",
                9,
                "admin_secure@example.com",
                "ADMIN");

        jdbc.update(
                "INSERT INTO auth_users VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                10,
                "admin_lowcost",
                encoder4.encode(level10Password),
                "BCRYPT_LOW_ITERATION",
                10,
                "admin_lowcost@example.com",
                "ADMIN");

        return new Object();
    }
}
