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

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Internal hash computation that always includes salt bytes in the digest input.
     *
     * @param salt the salt bytes to prepend to the digest input
     * @param rawPassword the password to hash
     * @param hashAlgorithm the algorithm to use
     * @return the hex-encoded hash (without salt prefix)
     */
    private static String computeHashInternal(
            byte[] salt, String rawPassword, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest =
                    messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Generates a salted hash. Returns the format "saltHex:hashHex" so the salt is stored
     * alongside the hash for later verification.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = generateSalt();
        String hashHex = computeHashInternal(salt, rawPassword, hashAlgorithm);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hashHex;
    }

    /**
     * Verifies a password against a stored salted hash in "saltHex:hashHex" format.
     *
     * @param rawPassword the password to verify
     * @param saltedHash the stored hash in "saltHex:hashHex" format
     * @param hashAlgorithm the algorithm used to create the hash
     * @return true if the password matches
     */
    public static boolean isValidHash(
            String rawPassword, String saltedHash, HashAlgorithm hashAlgorithm) {
        if (saltedHash == null || rawPassword == null) {
            return false;
        }
        String[] parts = saltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computedHash = computeHashInternal(salt, rawPassword, hashAlgorithm);
        return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8));
    }

    public static String md4Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD4);
    }

    public static boolean isValidMd4(String rawPassword, String storedHash) {
        return isValidHash(rawPassword, storedHash, HashAlgorithm.MD4);
    }

    public static String md5Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD5);
    }

    public static boolean isValidMd5(String rawPassword, String storedHash) {
        return isValidHash(rawPassword, storedHash, HashAlgorithm.MD5);
    }

    public static String sha1Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA1);
    }

    public static boolean isValidSha1(String rawPassword, String storedHash) {
        return isValidHash(rawPassword, storedHash, HashAlgorithm.SHA1);
    }

    public static String sha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    public static boolean isValidSha256(String rawPassword, String storedHash) {
        return isValidHash(rawPassword, storedHash, HashAlgorithm.SHA256);
    }

    /**
     * Validates a password against a stored value in "stringSalt:hashHex" format where the salt is
     * a literal string (not hex-encoded bytes). Used by LDAP and IDOR modules.
     */
    public static boolean isValidSaltedSha256(String rawPassword, String saltedSha256Hash) {
        if (saltedSha256Hash == null || rawPassword == null) {
            return false;
        }

        String[] saltAndHash = saltedSha256Hash.split(HASH_SEPARATOR, 2);
        if (saltAndHash.length != 2) {
            // Backward compatibility for old plaintext test data.
            return saltedSha256Hash.equals(rawPassword);
        }

        String calculatedHash = sha256WithStringSalt(saltAndHash[0], rawPassword);
        return MessageDigest.isEqual(
                calculatedHash.toLowerCase().getBytes(StandardCharsets.UTF_8),
                saltAndHash[1].toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes SHA-256 hash with an explicit string salt. The salt string bytes are fed to the
     * digest before the password bytes. Returns just the hash hex (not "salt:hash" format).
     */
    public static String sha256Hex(String salt, String rawPassword) {
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        return computeHashInternal(saltBytes, rawPassword, HashAlgorithm.SHA256);
    }

    /**
     * Alias for {@link #sha256Hex(String, String)} used internally.
     */
    private static String sha256WithStringSalt(String salt, String rawPassword) {
        return sha256Hex(salt, rawPassword);
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
            return EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmDesEncrypt(byte[] key7) throws Exception {
        // Derive a 256-bit AES key from the input bytes using SHA-256
        MessageDigest keyDigest = MessageDigest.getInstance("SHA-256", "BC");
        byte[] aesKeyBytes = keyDigest.digest(key7);

        // Derive a 12-byte GCM nonce deterministically using a domain-separated hash
        MessageDigest nonceDigest = MessageDigest.getInstance("SHA-256", "BC");
        nonceDigest.update(key7);
        nonceDigest.update((byte) 0x01);
        byte[] nonceHash = nonceDigest.digest();
        byte[] nonce = new byte[12];
        System.arraycopy(nonceHash, 0, nonce, 0, 12);

        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(
                Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
        return cipher.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
