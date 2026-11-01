package com.zentrauth.auth.sdk.autoconfigure;

import com.zentrauth.auth.sdk.filter.ZentrauthTenantSecurityFilter;
import com.zentrauth.auth.sdk.security.ZentrauthCachingJwkProvider;
import com.zentrauth.auth.sdk.security.ZentrauthJwkProvider;
import jakarta.servlet.Filter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AutoConfiguration
@ConditionalOnClass({HttpSecurity.class, SecurityFilterChain.class})
@EnableConfigurationProperties(ZentrauthAuthProperties.class)
@ConditionalOnProperty(prefix = "zentrauth.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ZentrauthAuthAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(ZentrauthJwkProvider.class)
    ZentrauthCachingJwkProvider zentrauthJwkProvider(ZentrauthAuthProperties properties) {
        return new ZentrauthCachingJwkProvider(
                properties.getJwksUri(),
                properties.getJwksCacheDuration(),
                properties.getJwksConnectTimeout(),
                properties.getJwksReadTimeout()
        );
    }

    @Bean
    @ConditionalOnMissingBean(ZentrauthTenantSecurityFilter.class)
    ZentrauthTenantSecurityFilter zentrauthTenantSecurityFilter(
            ZentrauthAuthProperties zentrauthAuthProperties,
            ZentrauthJwkProvider zentrauthJwkProvider
    ) {
        return new ZentrauthTenantSecurityFilter(zentrauthAuthProperties, zentrauthJwkProvider);
    }

    @Bean
    FilterRegistrationBean<Filter> disableServletRegistration(ZentrauthTenantSecurityFilter zentrauthTenantSecurityFilter) {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>(zentrauthTenantSecurityFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain zentrauthSecurityFilterChain(
            HttpSecurity http,
            ZentrauthTenantSecurityFilter zentrauthTenantSecurityFilter,
            ZentrauthAuthProperties zentrauthAuthProperties
    ) throws Exception {
        String[] excludedPaths = zentrauthAuthProperties.getExcludedPaths().toArray(String[]::new);
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> {
                    if (excludedPaths.length > 0) {
                        authorize.requestMatchers(excludedPaths).permitAll();
                    }
                    authorize.anyRequest().authenticated();
                })
                .addFilterBefore(zentrauthTenantSecurityFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form.disable());
        return http.build();
    }
}
