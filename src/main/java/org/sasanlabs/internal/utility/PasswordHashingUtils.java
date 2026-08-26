package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int SALT_LENGTH = 16;
    private static final int bcryptWorkFactor = 12;

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
     * Generates a salted hash using a cryptographically random salt.
     *
     * @return the hash in {@code saltHex:hashHex} format
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        String hashHex = getHashAsHex(rawPassword, hashAlgorithm, salt);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hashHex;
    }

    /**
     * Computes a hash of the password with the given salt applied via {@link
     * MessageDigest#update(byte[])}.
     *
     * @return the raw hex hash (without salt prefix)
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            if (salt != null && salt.length > 0) {
                messageDigest.update(salt);
            }
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Verifies a password against a stored salted hash in {@code saltHex:hashHex} format.
     *
     * @param rawPassword the candidate password
     * @param storedSaltedHash the stored value produced by {@link #getHashAsHex(String,
     *     HashAlgorithm)}
     * @param algorithm the hash algorithm used
     * @return true if the password matches
     */
    public static boolean verifySaltedHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm algorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computed = getHashAsHex(rawPassword, algorithm, salt);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8));
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
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256, saltBytes);
    }

    /**
     * Computes a salted SHA-256 hash. Despite the legacy name, this method now generates a random
     * salt for security. Use {@link #verifySaltedHash} to verify.
     */
    public static String unsaltedSha256Hex(String rawPassword) {
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

    private static final int LM_SALT_LENGTH = 16;

    /**
     * Computes a salted hash for the given password using a unique random salt.
     *
     * <p>Returns the salt and hash in the format {@code hex(salt):hex(SHA-256(salt+password))}.
     * Each invocation generates a new random salt so the same password produces different output.
     */
    public static String lmHash(String rawPassword) {
        try {
            byte[] salt = new byte[LM_SALT_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(salt);
            String saltHex = EncodingUtils.bytesToHex(salt);

            MessageDigest md = MessageDigest.getInstance(HashAlgorithm.SHA256.label(), "BC");
            md.update(salt);
            md.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            byte[] hash = md.digest();

            return saltHex + HASH_SEPARATOR + EncodingUtils.bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }

    /**
     * Validates a raw password against a stored salted hash produced by {@link #lmHash(String)}.
     *
     * @param rawPassword the candidate password
     * @param storedHash the stored value in {@code salt:hash} format
     * @return true if the password matches
     */
    public static boolean isValidLmHash(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        try {
            byte[] salt = EncodingUtils.hexToBytes(parts[0]);
            MessageDigest md = MessageDigest.getInstance(HashAlgorithm.SHA256.label(), "BC");
            md.update(salt);
            md.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            byte[] computed = md.digest();
            return MessageDigest.isEqual(
                    computed, EncodingUtils.hexToBytes(parts[1]));
        } catch (Exception e) {
            return false;
        }
    }
}
