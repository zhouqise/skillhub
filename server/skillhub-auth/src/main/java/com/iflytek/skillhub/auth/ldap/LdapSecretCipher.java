package com.iflytek.skillhub.auth.ldap;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Versioned authenticated encryption; the deployment key must survive application restarts. */
@Component
public class LdapSecretCipher {
    private final String encodedKey;
    public LdapSecretCipher(@Value("${skillhub.auth.ldap-settings-encryption-key:}") String encodedKey) {
        this.encodedKey = encodedKey;
    }
    public boolean configured() {
        try { return Base64.getDecoder().decode(encodedKey).length == 32; }
        catch (IllegalArgumentException invalid) { return false; }
    }
    public String encrypt(String value) {
        if (value.isEmpty()) return "";
        try {
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, nonce);
            return "v1:" + Base64.getEncoder().encodeToString(nonce) + ":"
                    + Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception failure) { throw unavailable(); }
    }
    public String decrypt(String value) {
        if (value.isEmpty()) return "";
        try {
            String[] parts = value.split(":", -1);
            if (parts.length != 3 || !parts[0].equals("v1")) throw unavailable();
            byte[] nonce = Base64.getDecoder().decode(parts[1]);
            if (nonce.length != 12) throw unavailable();
            return new String(cipher(Cipher.DECRYPT_MODE, nonce).doFinal(
                    Base64.getDecoder().decode(parts[2])), StandardCharsets.UTF_8);
        } catch (Exception failure) { throw unavailable(); }
    }
    private Cipher cipher(int mode, byte[] nonce) throws Exception {
        if (!configured()) throw unavailable();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(Base64.getDecoder().decode(encodedKey), "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD("skillhub:auth.ldap:v1".getBytes(StandardCharsets.UTF_8));
        return cipher;
    }
    private IllegalStateException unavailable() { return new IllegalStateException("LDAP configuration encryption unavailable"); }
}
