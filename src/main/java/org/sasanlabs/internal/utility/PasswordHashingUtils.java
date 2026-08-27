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

    /** Generates a cryptographically secure random salt. */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
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
     * Hashes the input with a randomly generated salt. Returns "saltHex:hashHex".
     *
     * @param rawPassword the input to hash
     * @param hashAlgorithm the hash algorithm to use
     * @return salted hash in the format "saltHex:hashHex"
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = generateSalt();
        return getHashAsHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Hashes the input with the provided salt. Returns "saltHex:hashHex".
     *
     * @param rawPassword the input to hash
     * @param hashAlgorithm the hash algorithm to use
     * @param salt the salt bytes to prepend before hashing
     * @return salted hash in the format "saltHex:hashHex"
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        return EncodingUtils.bytesToHex(salt)
                + HASH_SEPARATOR
                + computeDigestHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Verifies a raw password against a stored salted hash (format "saltHex:hashHex").
     *
     * @param rawPassword the password to verify
     * @param storedSaltedHash the stored hash in "saltHex:hashHex" format
     * @param hashAlgorithm the hash algorithm that was used
     * @return true if the password matches
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
        String recomputed = computeDigestHex(rawPassword, hashAlgorithm, salt);
        return MessageDigest.isEqual(
                recomputed.getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Core digest computation with salt. Returns only the hash hex (no salt prefix).
     *
     * <p>Uses MessageDigest.update(salt) followed by digest(input) to properly incorporate the
     * salt into the hash computation.
     */
    private static String computeDigestHex(
            String rawInput, HashAlgorithm hashAlgorithm, byte[] salt) {
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(rawInput.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
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
     * Computes SHA-256 hash with the given string salt. Returns only the hash hex (caller manages
     * salt storage separately). The salt bytes are fed into the digest via update() before the
     * password.
     */
    public static String sha256Hex(String salt, String rawPassword) {
        return computeDigestHex(rawPassword, HashAlgorithm.SHA256,
                salt.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes a salted SHA-256 hash with a random salt. Returns "saltHex:hashHex".
     *
     * @param rawPassword the password to hash
     * @return salted hash in the format "saltHex:hashHex"
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
            return EncodingUtils.bytesToHex(lmEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmEncrypt(byte[] key7) throws Exception {
        // Derive a 16-byte AES-128 key from the 7-byte input (zero-padded)
        byte[] aesKey = new byte[16];
        System.arraycopy(key7, 0, aesKey, 0, key7.length);

        // Use the LM magic string zero-padded to AES block size (16 bytes)
        byte[] plaintext = new byte[16];
        byte[] magic = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, plaintext, 0, magic.length);

        // Deterministic 12-byte nonce derived from key material for hash computation
        byte[] nonce = new byte[12];
        System.arraycopy(key7, 0, nonce, 0, key7.length);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aes.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, nonce));
        return aes.doFinal(plaintext);
    }
}
