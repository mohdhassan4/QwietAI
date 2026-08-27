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
    private static final int bcryptWorkFactor = 12;
    private static final int SALT_BYTES = 16;
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
     * Computes a salted hash. A random salt is generated and prepended to the digest. The returned
     * format is {@code saltHex:hashHex}.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(salt)
                    + HASH_SEPARATOR
                    + EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Verifies a raw password against a stored salted hash in the format {@code saltHex:hashHex}.
     */
    public static boolean verifiesHash(
            String rawPassword, String storedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        try {
            byte[] salt = EncodingUtils.hexToBytes(parts[0]);
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return parts[1].equalsIgnoreCase(EncodingUtils.bytesToHex(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
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
     * Computes SHA-256 of the concatenation of the given text salt and raw password. Used by
     * {@link #isValidSaltedSha256} for legacy text-salt format validation.
     */
    public static String sha256Hex(String salt, String rawPassword) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(HashAlgorithm.SHA256.label(), "BC");
            messageDigest.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
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

    private static final byte[] LM_HASH_SALT =
            "VulnerableApp-LM-Hash-Salt".getBytes(StandardCharsets.UTF_8);
    private static final int PBKDF2_ITERATIONS = 310000;
    private static final int LM_HASH_KEY_LENGTH_BITS = 128;

    /**
     * Computes a secure password hash as a replacement for the legacy LM hash.
     *
     * <p>Uses PBKDF2WithHmacSHA256 with a fixed application salt for deterministic output.
     * Maintains case-insensitivity to preserve the original API contract.
     *
     * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">OWASP Password Storage</a>
     */
    public static String lmHash(String rawPassword) {
        try {
            // Maintain case-insensitivity from original LM hash contract
            String pwd = rawPassword.toUpperCase();
            char[] passwordChars = pwd.toCharArray();

            PBEKeySpec spec =
                    new PBEKeySpec(
                            passwordChars, LM_HASH_SALT, PBKDF2_ITERATIONS, LM_HASH_KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();

            return EncodingUtils.bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }
}
