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
    private static final String NONE_ALGO_HEADER_KEY = "NONE_ALGO_JWT_HEADER_JSON";
    private static final String NONE_ALGO_PAYLOAD_KEY = "NONE_ALGO_JWT_PAYLOAD_JSON";

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
            value = value.replace(JWT_NONE_ALGO_PLACEHOLDER, buildNoneAlgoJwt());
        }
        return value;
    }

    /**
     * Builds a JWT with the "none" algorithm at runtime from stored JSON header and payload
     * properties, so that the assembled token is never stored as a literal in source.
     */
    private String buildNoneAlgoJwt() {
        String headerJson = attackVectorProperties.getProperty(NONE_ALGO_HEADER_KEY);
        String payloadJson = attackVectorProperties.getProperty(NONE_ALGO_PAYLOAD_KEY);
        String header =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }
}
