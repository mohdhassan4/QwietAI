package org.sasanlabs.configuration;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class contains all the properties related to vulnerableApp. This bean is registered through
 * {@link VulnerableAppConfiguration}. In case in future we want to add new properties to
 * vulnerableApp please use this bean.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class VulnerableAppProperties {

    private static final Pattern ENV_VAR_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

    /** Contains all the properties present in {@code attackvectors/*.properties} */
    private Properties attackVectorProperties;

    public VulnerableAppProperties(Properties attackVectorProperties) {
        super();
        this.attackVectorProperties = attackVectorProperties;
    }

    /**
     * @param propertyKey
     * @return property value by reading {@code attackvectors/*.properties} files. Environment
     *     variable references in the form ${VAR_NAME} are resolved from system environment.
     */
    public String getAttackVectorProperty(String propertyKey) {
        String value = attackVectorProperties.getProperty(propertyKey);
        if (value == null) {
            return null;
        }
        return resolveEnvVars(value);
    }

    private String resolveEnvVars(String value) {
        Matcher matcher = ENV_VAR_PATTERN.matcher(value);
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            String envVarName = matcher.group(1);
            String envValue = System.getenv(envVarName);
            matcher.appendReplacement(
                    result, Matcher.quoteReplacement(envValue != null ? envValue : ""));
        }
        matcher.appendTail(result);
        return result.toString();
    }
}
