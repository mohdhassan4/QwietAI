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
     * Computes a salted hash with an auto-generated random salt. Returns "saltHex:hashHex".
     *
     * @return salted hash in the format "saltHex:hashHex"
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = generateSalt();
        String hashHex = computeHashHex(rawPassword, hashAlgorithm, salt);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hashHex;
    }

    /**
     * Computes a hash using the provided salt bytes fed into the digest before the password.
     *
     * @return hash hex string (without salt prefix)
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        return computeHashHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Verifies a password against a stored "saltHex:hashHex" value.
     *
     * @return true if the password matches the stored salted hash
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
        String computed = computeHashHex(rawPassword, hashAlgorithm, salt);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8));
    }

    private static String computeHashHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
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

    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
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
                rawPassword,
                HashAlgorithm.SHA256,
                salt.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes a salted SHA-256 hash with auto-generated random salt. Returns "saltHex:hashHex".
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
            return EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmAesEncrypt(byte[] key7) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        javax.crypto.SecretKeyFactory skf =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec pbeSpec =
                new javax.crypto.spec.PBEKeySpec(
                        new String(key7, StandardCharsets.ISO_8859_1).toCharArray(),
                        salt, 600000, 256);
        byte[] aesKey = skf.generateSecret(pbeSpec).getEncoded();

        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aes.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, nonce));
        byte[] ciphertext = aes.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));

        byte[] result = new byte[salt.length + nonce.length + ciphertext.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(nonce, 0, result, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, result, salt.length + nonce.length, ciphertext.length);
        return result;
    }
}
