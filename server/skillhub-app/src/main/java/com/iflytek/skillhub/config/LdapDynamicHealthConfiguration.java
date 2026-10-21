package com.iflytek.skillhub.config;
import com.iflytek.skillhub.auth.ldap.LdapSettingsService;
import com.iflytek.skillhub.service.LdapSettingsAppService;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
@Configuration(proxyBeanMethods = false)
public class LdapDynamicHealthConfiguration {
    @Bean(name = "ldapHealthIndicator")
    HealthIndicator ldapHealthIndicator(LdapSettingsService settings) {
        return () -> {
            try {
                if (!settings.enabled()) return Health.up().withDetail("enabled", false).build();
                return LdapSettingsAppService.probe(settings.current()) ? Health.up().build() : Health.down().build();
            } catch (Exception failure) { return Health.down().build(); }
        };
    }
}
