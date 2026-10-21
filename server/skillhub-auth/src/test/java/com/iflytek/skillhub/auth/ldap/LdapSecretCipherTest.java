package com.iflytek.skillhub.auth.ldap;
import static org.assertj.core.api.Assertions.*;
import org.junit.jupiter.api.Test;
class LdapSecretCipherTest {
    private final LdapSecretCipher cipher = new LdapSecretCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    @Test void randomNoncesAndRestartDecryption() {
        String first = cipher.encrypt("reader-secret");
        assertThat(first).doesNotContain("reader-secret").isNotEqualTo(cipher.encrypt("reader-secret"));
        assertThat(new LdapSecretCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").decrypt(first)).isEqualTo("reader-secret");
    }
    @Test void rejectsMissingKeyWrongKeyAndTampering() {
        assertThatThrownBy(() -> new LdapSecretCipher("").encrypt("secret")).isInstanceOf(IllegalStateException.class);
        String encrypted = cipher.encrypt("secret");
        assertThatThrownBy(() -> new LdapSecretCipher("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").decrypt(encrypted)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> cipher.decrypt(encrypted.substring(0, encrypted.length() - 4) + "AAAA")).isInstanceOf(IllegalStateException.class);
    }
}
