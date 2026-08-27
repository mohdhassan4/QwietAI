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
    private static final int SALT_LENGTH = 16;
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
     * Computes a salted hash. A random salt is generated and prepended to the input before
     * digesting. Returns the format {@code hex(salt):hex(hash)}.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] saltBytes = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(saltBytes);
        String salt = EncodingUtils.bytesToHex(saltBytes);
        String hash = computeSaltedHash(salt, rawPassword, hashAlgorithm);
        return salt + HASH_SEPARATOR + hash;
    }

    /**
     * Verifies a password against a stored salted hash in the format {@code hex(salt):hex(hash)}.
     */
    public static boolean verifyHashAsHex(
            String rawPassword, String storedSaltAndHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedSaltAndHash == null) {
            return false;
        }
        String[] parts = storedSaltAndHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        String computed = computeSaltedHash(parts[0], rawPassword, hashAlgorithm);
        return MessageDigest.isEqual(
                computed.toLowerCase().getBytes(StandardCharsets.UTF_8),
                parts[1].toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    private static String computeSaltedHash(
            String salt, String rawPassword, HashAlgorithm hashAlgorithm) {
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

    public static String sha256Hex(String salt, String rawPassword) {
        return computeSaltedHash(salt, rawPassword, HashAlgorithm.SHA256);
    }

    public static String sha256SaltedHex(String rawPassword) {
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

    /**
     * Computes a password hash using HMAC-SHA256.
     *
     * <p>Replaces the legacy LM hash (which used weak DES/ECB) with a secure HMAC-SHA256 based
     * approach. The hash is case-insensitive (password is uppercased) and deterministic.
     */
    public static String lmHash(String rawPassword) {
        try {
            // Convert to uppercase to maintain case-insensitive behavior
            String pwd = rawPassword.toUpperCase();
            byte[] passwordBytes = pwd.getBytes(StandardCharsets.UTF_8);

            // Use HMAC-SHA256 with a fixed key for deterministic hashing
            byte[] hmacKey = "KGS!@#$%".getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] hash = mac.doFinal(passwordBytes);

            // Return first 16 bytes (32 hex chars) to match previous output length
            byte[] truncated = new byte[16];
            System.arraycopy(hash, 0, truncated, 0, 16);
            return EncodingUtils.bytesToHex(truncated);
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }
}
