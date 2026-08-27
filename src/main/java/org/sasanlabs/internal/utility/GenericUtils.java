package org.sasanlabs.internal.utility;

/**
 * Generic Internal Utility class.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class GenericUtils {

    public static final String LOCALHOST = "127.0.0.1";

    private GenericUtils() {}

    /**
     * Sanitizes a value for safe inclusion in log messages by removing CR and LF characters that
     * could enable log forging/injection (CWE-117).
     */
    public static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\\r\\n]", "");
    }

    /**
     * @deprecated
     * @param payload
     * @return
     */
    @Deprecated
    public static String wrapPayloadInGenericVulnerableAppTemplate(String payload) {
        String generalPayload =
                "<html><title>Security Testing</title><body><h1>Vulnerable Application </h1> %s </body></html>";
        return String.format(generalPayload, payload);
    }
}
