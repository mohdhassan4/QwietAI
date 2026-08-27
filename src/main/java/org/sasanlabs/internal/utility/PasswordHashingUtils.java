package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
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

    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        String hashHex =
                computeHashHex(
                        salt, rawPassword.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hashHex;
    }

    /**
     * Verifies a password against a stored salted hash in the format {@code hexSalt:hexHash}.
     *
     * @return true if the password matches the stored hash
     */
    public static boolean verifyHash(
            String rawPassword, String storedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedHash == null) return false;
        String[] parts = storedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) return false;
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computedHash =
                computeHashHex(
                        salt, rawPassword.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
        return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                parts[1].toLowerCase().getBytes(StandardCharsets.UTF_8));
    }

    private static String computeHashHex(
            byte[] salt, byte[] input, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(input);
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
        return computeHashHex(
                salt.getBytes(StandardCharsets.UTF_8),
                rawPassword.getBytes(StandardCharsets.UTF_8),
                HashAlgorithm.SHA256);
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

    /**
     * Computes an LM-style hash for the given password using AES-128.
     *
     * <p>Derived from the LAN Manager approach but uses AES-128 instead of DES to avoid weak
     * cipher vulnerabilities.
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

            // Encrypt a magic plaintext using each key with AES-128
            return EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmAesEncrypt(byte[] key7) throws Exception {
        // Derive a 16-byte AES-128 key from the 7-byte input (zero-padded)
        byte[] key16 = new byte[16];
        System.arraycopy(key7, 0, key16, 0, 7);

        // Pad the magic string "KGS!@#$%" to 16 bytes (AES block size)
        byte[] magic = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = new byte[16];
        System.arraycopy(magic, 0, plaintext, 0, magic.length);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        return aes.doFinal(plaintext);
    }
}
