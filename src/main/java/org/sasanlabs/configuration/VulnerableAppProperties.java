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

    /** Contains all the properties present in {@code attackvectors/*.properties} */
    private Properties attackVectorProperties;

    private static final String NONE_ALG_JWT_PLACEHOLDER = "${NONE_ALG_JWT_TOKEN}";

    /** Runtime-constructed none-algorithm JWT token for attack vector display. */
    private static final String NONE_ALG_JWT_TOKEN = buildNoneAlgJwt();

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
        if (value != null && value.contains(NONE_ALG_JWT_PLACEHOLDER)) {
            value = value.replace(NONE_ALG_JWT_PLACEHOLDER, NONE_ALG_JWT_TOKEN);
        }
        return value;
    }

    /**
     * Constructs a none-algorithm JWT at runtime from its JSON components so that the token literal
     * does not need to be stored in source files.
     */
    private static String buildNoneAlgJwt() {
        String header = "{\"typ\":\"JWT\",\"alg\":\"none\"}";
        String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String encodedHeader =
                encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String encodedPayload =
                encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return encodedHeader + "." + encodedPayload + ".";
    }
}
