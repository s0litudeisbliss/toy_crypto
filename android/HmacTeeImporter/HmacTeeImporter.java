import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public final class HmacTeeImporter {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    // AndroidKeyStore uses algorithm-specific names for HMAC keys:
    // "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacSHA1", "HmacSHA224".
    // The raw key material is the same bytes either way; the algorithm tag
    // bound at import time fixes which digest KeyMint will accept.
    private static final String KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;

    /**
     * Generate a 256-bit HMAC-SHA256 key in software, import it into
     * AndroidKeyStore, and verify the resulting key is hardware-backed.
     *
     * Threat note: the raw bytes briefly live in app-process memory (and in
     * the keystore2 daemon during transit) before the TEE seals them. If that
     * window is unacceptable, use KeyStore#importWrappedKey instead.
     */
    public static boolean generateAndImport(String alias) throws Exception {
        // 1. Generate raw HMAC key material in software.
        //    NIST SP 800-107 / RFC 2104: key length should be >= digest output
        //    (32 bytes for SHA-256). Going beyond the block size (64 bytes for
        //    SHA-256) gains nothing — HMAC pre-hashes oversized keys.
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        SecretKey softwareKey = new SecretKeySpec(rawKey, KEY_ALGORITHM);

        try {
            // 2. Authorisation tags bound to the key inside the TEE.
            //    HMAC keys take only PURPOSE_SIGN | PURPOSE_VERIFY. No block
            //    modes, no paddings — those are AES-only authorisations and
            //    KeyMint will reject the import if you set them.
            KeyProtection spec = new KeyProtection.Builder(
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // Optional hardening — enable per your threat model:
                    // .setIsStrongBoxBacked(true)
                    // .setUnlockedDeviceRequired(true)
                    // .setUserAuthenticationRequired(true)
                    // .setUserAuthenticationParameters(0,
                    //         KeyProperties.AUTH_BIOMETRIC_STRONG)
                    // .setInvalidatedByBiometricEnrollment(true)
                    .build();

            // 3. Import into AndroidKeyStore under the given alias.
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);
            ks.setEntry(alias, new KeyStore.SecretKeyEntry(softwareKey), spec);

            // 4. Verify hardware backing. setEntry has no flag to *require*
            //    hardware backing — inspect after import and reject the
            //    device if it fell back to software.
            return isHardwareBacked(ks, alias);

        } finally {
            // 5. Best-effort wipe of the plaintext copy.
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    private static boolean isHardwareBacked(KeyStore ks, String alias) throws Exception {
        SecretKey key = (SecretKey) ks.getKey(alias, null);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(
                key.getAlgorithm(), KEYSTORE_PROVIDER);
        KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

        if (android.os.Build.VERSION.SDK_INT >= 31) {
            int level = info.getSecurityLevel();
            return level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                || level == KeyProperties.SECURITY_LEVEL_STRONGBOX;
        } else {
            //noinspection deprecation
            return info.isInsideSecureHardware();
        }
    }

    /** Remove if the device fell back to software. */
    public static void deleteAlias(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
        ks.load(null);
        if (ks.containsAlias(alias)) ks.deleteEntry(alias);
    }
}
