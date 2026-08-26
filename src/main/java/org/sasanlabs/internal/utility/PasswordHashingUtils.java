package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int SALT_LENGTH = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
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
     * Computes a salted hash. Generates a random salt, prepends it to the input, and returns the
     * result as "saltHex:digestHex".
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        String digestHex = computeRawDigestHex(salt, rawPassword, hashAlgorithm);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + digestHex;
    }

    /**
     * Verifies a raw password against a stored salted hash in "saltHex:digestHex" format.
     *
     * @return true if the password matches
     */
    public static boolean verifyHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        if (storedSaltedHash == null || rawPassword == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computed = computeRawDigestHex(salt, rawPassword, hashAlgorithm);
        return computed.equalsIgnoreCase(parts[1]);
    }

    /**
     * Computes a raw digest (no internal salt generation). Salt bytes are prepended to the password
     * bytes before hashing.
     */
    private static String computeRawDigestHex(
            byte[] salt, String rawPassword, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
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

    /**
     * Computes SHA-256 of (salt + rawPassword) using the caller-provided salt. Returns only the
     * digest hex (caller manages salt storage separately).
     */
    public static String sha256Hex(String salt, String rawPassword) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(HashAlgorithm.SHA256.label(), "BC");
            byte[] digest =
                    messageDigest.digest(
                            (salt + rawPassword).getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("SHA-256 Hash Algorithm Not Found", e);
        }
    }

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

    private static final int PBKDF2_ITERATIONS = 600000;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int PBKDF2_SALT_LENGTH = 16;

    /**
     * Computes a PBKDF2-HMAC-SHA256 hash for the given password.
     *
     * <p>Generates a unique random salt per invocation and returns the result as
     * "saltHex:hashHex". This replaces the legacy LM hash which relied on the broken DES
     * algorithm.
     */
    public static String pbkdf2Hash(String rawPassword) {
        try {
            byte[] salt = new byte[PBKDF2_SALT_LENGTH];
            SECURE_RANDOM.nextBytes(salt);
            PBEKeySpec spec =
                    new PBEKeySpec(
                            rawPassword.toCharArray(),
                            salt,
                            PBKDF2_ITERATIONS,
                            PBKDF2_KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + EncodingUtils.bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 Hashing failed", e);
        }
    }

    /**
     * Verifies a raw password against a stored PBKDF2 salted hash in "saltHex:hashHex" format.
     *
     * @return true if the password matches
     */
    public static boolean verifyPbkdf2(String rawPassword, String storedSaltedHash) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        try {
            byte[] salt = EncodingUtils.hexToBytes(parts[0]);
            PBEKeySpec spec =
                    new PBEKeySpec(
                            rawPassword.toCharArray(),
                            salt,
                            PBKDF2_ITERATIONS,
                            PBKDF2_KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return EncodingUtils.bytesToHex(hash).equalsIgnoreCase(parts[1]);
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 verification failed", e);
        }
    }
}
