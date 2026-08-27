package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int SALT_LENGTH_BYTES = 16;
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
     * Hashes the given password with a random salt. Returns the result in the format {@code
     * saltHex:hashHex}.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        new SecureRandom().nextBytes(salt);
        return getHashAsHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Hashes the given password with the provided salt bytes. Returns the result in the format
     * {@code saltHex:hashHex}.
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest =
                    messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(salt)
                    + HASH_SEPARATOR
                    + EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Verifies that the given raw password matches the stored salted hash in {@code
     * saltHex:hashHex} format.
     */
    public static boolean verifyHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computed = getHashAsHex(rawPassword, hashAlgorithm, salt);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                storedSaltedHash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Hashes the given password using the same salt found in the stored salted hash. Useful for
     * displaying what a guess hashes to with the same salt as the target.
     */
    public static String hashWithSameSalt(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        byte[] salt =
                (parts.length == 2)
                        ? EncodingUtils.hexToBytes(parts[0])
                        : new byte[SALT_LENGTH_BYTES];
        return getHashAsHex(rawPassword, hashAlgorithm, salt);
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
        return MessageDigest.isEqual(
                saltAndHash[1].getBytes(StandardCharsets.UTF_8),
                calculatedHash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes SHA-256 of the password with the given string salt. Returns only the hash hex
     * (callers manage the salt:hash storage format themselves).
     */
    public static String sha256Hex(String salt, String rawPassword) {
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(HashAlgorithm.SHA256.label(), "BC");
            messageDigest.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest =
                    messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /** Hashes the given password with a random salt using SHA-256. Returns saltHex:hashHex. */
    public static String saltedSha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    /**
     * @deprecated Use {@link #saltedSha256Hex(String)} instead. This method now produces salted
     *     output in saltHex:hashHex format.
     */
    @Deprecated
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
            return EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmAesEncrypt(byte[] key7) throws Exception {
        // Derive a 256-bit AES key from the 7-byte input using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] aesKey = sha256.digest(key7);

        // Deterministic IV: safe because key varies per password and plaintext is constant
        byte[] iv = new byte[12];
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), gcmSpec);
        return aes.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
