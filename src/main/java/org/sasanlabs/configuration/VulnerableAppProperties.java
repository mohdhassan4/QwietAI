package org.sasanlabs.configuration;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

/**
 * This class contains all the properties related to vulnerableApp. This bean is registered through
 * {@link VulnerableAppConfiguration}. In case in future we want to add new properties to
 * vulnerableApp please use this bean.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class VulnerableAppProperties {

    private static final String JWT_NONE_ALGO_PLACEHOLDER = "{JWT_NONE_ALGO_TOKEN}";

    /** Contains all the properties present in {@code attackvectors/*.properties} */
    private Properties attackVectorProperties;

    public VulnerableAppProperties(Properties attackVectorProperties) {
        super();
        this.attackVectorProperties = attackVectorProperties;
    }

    /**
     * @param propertyKey
     * @return property value by reading {@code attackvectors/*.properties} files.
     */
    public String getAttackVectorProperty(String propertyKey) {
        String value = attackVectorProperties.getProperty(propertyKey);
        if (value != null && value.contains(JWT_NONE_ALGO_PLACEHOLDER)) {
            value = value.replace(JWT_NONE_ALGO_PLACEHOLDER, buildNoneAlgorithmJwt());
        }
        return value;
    }

    /**
     * Builds the standard none-algorithm JWT at runtime so the token is never stored in source
     * files. Uses the well-known jwt.io example payload.
     */
    private String buildNoneAlgorithmJwt() {
        String envToken = System.getenv("JWT_NONE_ALGO_TOKEN");
        if (envToken != null && !envToken.isEmpty()) {
            return envToken;
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header =
                encoder.encodeToString(
                        "{\"typ\":\"JWT\",\"alg\":\"none\"}"
                                .getBytes(StandardCharsets.UTF_8));
        String payload =
                encoder.encodeToString(
                        "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}"
                                .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }
}
