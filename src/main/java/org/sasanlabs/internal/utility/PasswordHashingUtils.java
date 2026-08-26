package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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
     * Internal helper that computes the raw digest hex with an explicit salt fed via
     * MessageDigest.update before the input bytes.
     */
    private static String computeDigestHex(
            String rawInput, HashAlgorithm hashAlgorithm, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(rawInput.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    public static String md4Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD4);
    }

    public static String md5Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD5);
    }

    public static String sha1Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA1);
    }

    /**
     * Generates a salted hash using a random salt. Returns the result in the format
     * {@code hexSalt:hexHash}.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return getHashAsHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Generates a salted hash using the provided salt. Returns the result in the format
     * {@code hexSalt:hexHash}.
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        String hexHash = computeDigestHex(rawPassword, hashAlgorithm, salt);
        String hexSalt = EncodingUtils.bytesToHex(salt);
        return hexSalt + HASH_SEPARATOR + hexHash;
    }

    /**
     * Verifies a raw password against a stored salted hash in the format {@code hexSalt:hexHash}.
     */
    public static boolean verifyHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2 || parts[0].isEmpty()) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computedHex = computeDigestHex(rawPassword, hashAlgorithm, salt);
        return MessageDigest.isEqual(
                computedHex.getBytes(StandardCharsets.US_ASCII),
                parts[1].toLowerCase().getBytes(StandardCharsets.US_ASCII));
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

        String calculatedHash = sha256Hex(saltAndHash[0], rawPassword);
        return saltAndHash[1].equalsIgnoreCase(calculatedHash);
    }

    /**
     * Computes SHA-256 of (salt + rawPassword) using the salt bytes fed via MessageDigest.update.
     * Returns only the hex hash (not the salt:hash format). Used by isValidSaltedSha256.
     */
    public static String sha256Hex(String salt, String rawPassword) {
        byte[] saltBytes =
                (salt != null) ? salt.getBytes(StandardCharsets.UTF_8) : new byte[0];
        return computeDigestHex(rawPassword, HashAlgorithm.SHA256, saltBytes);
    }

    /**
     * Generates a salted SHA-256 hash with a random salt. Returns {@code hexSalt:hexHash} format.
     */
    public static String saltedSha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
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

    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int PBKDF2_KEY_LENGTH_BITS = 128;

    /**
     * Computes a password hash using PBKDF2WithHmacSHA256 with a unique random salt per
     * invocation.
     *
     * <p>Replaces legacy LM/DES-based hashing with a modern key-derivation function. Preserves
     * case-insensitive behaviour (input is upper-cased before hashing). Returns {@code
     * hexSalt:hexHash}.
     */
    public static String lmHash(String rawPassword) {
        try {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            // Preserve case-insensitive behaviour from the legacy LM approach
            String pwd = rawPassword.toUpperCase();
            PBEKeySpec spec =
                    new PBEKeySpec(
                            pwd.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + EncodingUtils.bytesToHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 Hashing failed", e);
        }
    }

    /**
     * Verifies a raw password against a stored PBKDF2 hash in the format {@code hexSalt:hexHash}.
     * Preserves case-insensitive behaviour (input is upper-cased before hashing).
     */
    public static boolean verifyLmHash(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2 || parts[0].isEmpty()) {
            return false;
        }
        try {
            byte[] salt = EncodingUtils.hexToBytes(parts[0]);
            String pwd = rawPassword.toUpperCase();
            PBEKeySpec spec =
                    new PBEKeySpec(
                            pwd.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            String computedHex = EncodingUtils.bytesToHex(hash);
            return MessageDigest.isEqual(
                    computedHex.getBytes(StandardCharsets.US_ASCII),
                    parts[1].toLowerCase().getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 Verification failed", e);
        }
    }
}
