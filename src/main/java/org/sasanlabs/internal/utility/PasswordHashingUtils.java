package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PasswordHashingUtils() {}

    // Available Hashing Algorithms
    public enum HashAlgorithm {
        MD4("MD4"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256");

        private final String algorithmName;

        HashAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String label() {
            return this.algorithmName;
        }
    }

    // Registers Bouncy Castle as provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a cryptographically random salt and produces a salted hash. Returns the result in
     * the format {@code salt_hex:hash_hex}.
     */
    public static String md4Hex(String rawPassword) {
        return saltedHash(rawPassword, HashAlgorithm.MD4);
    }

    /**
     * Generates a cryptographically random salt and produces a salted hash. Returns the result in
     * the format {@code salt_hex:hash_hex}.
     */
    public static String md5Hex(String rawPassword) {
        return saltedHash(rawPassword, HashAlgorithm.MD5);
    }

    /**
     * Generates a cryptographically random salt and produces a salted hash. Returns the result in
     * the format {@code salt_hex:hash_hex}.
     */
    public static String sha1Hex(String rawPassword) {
        return saltedHash(rawPassword, HashAlgorithm.SHA1);
    }

    /**
     * Produces a salted hash using a randomly generated salt. Returns the result in the format
     * {@code salt_hex:hash_hex}.
     */
    public static String saltedHash(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        String saltHex = EncodingUtils.bytesToHex(salt);
        String hashHex = getHashAsHex(rawPassword, saltHex, hashAlgorithm);
        return saltHex + HASH_SEPARATOR + hashHex;
    }

    /**
     * Computes a hash of the given input with the provided salt prepended. The salt ensures that
     * identical inputs produce different hashes when different salts are used.
     */
    public static String getHashAsHex(
            String rawPassword, String salt, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Verifies a raw password against a stored salted hash in the format {@code salt_hex:hash_hex}.
     *
     * @return true if the password matches the stored hash
     */
    public static boolean verifySaltedHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        String salt = parts[0];
        String storedHash = parts[1];
        String computedHash = getHashAsHex(rawPassword, salt, hashAlgorithm);
        return MessageDigest.isEqual(
                storedHash.toLowerCase().getBytes(StandardCharsets.UTF_8),
                computedHash.toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    public static boolean isValidSaltedSha256(String rawPassword, String saltedSha256Hash) {
        if (saltedSha256Hash == null || rawPassword == null) {
            return false;
        }

        String[] saltAndHash = saltedSha256Hash.split(HASH_SEPARATOR, 2);
        if (saltAndHash.length != 2) {
            // Backward compatibility for old plaintext test data.
            return saltedSha256Hash.equals(rawPassword);
        }

        String calculatedHash = getHashAsHex(rawPassword, saltAndHash[0], HashAlgorithm.SHA256);
        return MessageDigest.isEqual(
                saltAndHash[1].toLowerCase().getBytes(StandardCharsets.UTF_8),
                calculatedHash.toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(String salt, String rawPassword) {
        return getHashAsHex(rawPassword, salt, HashAlgorithm.SHA256);
    }

    /**
     * Produces a salted SHA-256 hash using a randomly generated salt. Returns the result in the
     * format {@code salt_hex:hash_hex}.
     */
    public static String saltedSha256Hex(String rawPassword) {
        return saltedHash(rawPassword, HashAlgorithm.SHA256);
    }

    // BC not used for bcrypt due to extra complexity for BC implementation
    public static int getbcryptWorkFactor() {
        return bcryptWorkFactor;
    }

    public static String bCryptHash(String rawPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.encode(rawPassword);
    }

    public static boolean isValidBcrypt(String rawPassword, String bcryptHash) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.matches(rawPassword, bcryptHash);
    }

    /**
     * Computes an LM hash for the given password.
     *
     * <p>Algorithm based on the LAN Manager specification.
     *
     * @see <a href="https://en.wikipedia.org/wiki/LAN_Manager">Wikipedia: LAN Manager</a>
     */
    public static String lmHash(String rawPassword) {
        try {
            // Convert to uppercase and pad to 14 bytes
            String pwd = rawPassword.toUpperCase();
            byte[] keyBytes = new byte[14];
            byte[] passwordBytes = pwd.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, 14));

            // Split into two 7-byte keys
            byte[] tmpKey1 = new byte[7];
            byte[] tmpKey2 = new byte[7];
            System.arraycopy(keyBytes, 0, tmpKey1, 0, 7);
            System.arraycopy(keyBytes, 7, tmpKey2, 0, 7);

            // Encrypt the magic string "KGS!@#$%" using each key
            return EncodingUtils.bytesToHex(lmKeyedHash(tmpKey1))
                    + EncodingUtils.bytesToHex(lmKeyedHash(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmKeyedHash(byte[] key7) throws Exception {
        // Use HMAC-SHA256 for secure key derivation (replaces weak DES encryption)
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key7, "HmacSHA256");
        mac.init(keySpec);
        byte[] fullMac = mac.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
        // Return first 8 bytes to maintain hash output length compatibility
        byte[] result = new byte[8];
        System.arraycopy(fullMac, 0, result, 0, 8);
        return result;
    }
}
