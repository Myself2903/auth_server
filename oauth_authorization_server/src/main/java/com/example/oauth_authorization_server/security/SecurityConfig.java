package com.example.oauth_authorization_server.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static org.springframework.security.config.Customizer.withDefaults;




@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(withDefaults());

        http.exceptionHandling(exception -> exception
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        .oauth2ResourceServer(resourceServer -> resourceServer
            .jwt(withDefaults()));
        return http.formLogin(withDefaults()).build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
        .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService users() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.builder()
            .username("admin")
            .password("password")
            .passwordEncoder(encoder::encode)
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    // @Bean 
	// public RegisteredClientRepository registeredClientRepository() {
	// 	RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
	// 			.clientId("articles-client")
	// 			.clientSecret("{noop}secret")
	// 			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	// 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	// 			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	// 			.redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")
	// 			.postLogoutRedirectUri("http://127.0.0.1:8080/")
	// 			.scope(OidcScopes.OPENID)
	// 			.scope(OidcScopes.PROFILE)
	// 			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
	// 			.build();

	// 	return new InMemoryRegisteredClientRepository(oidcClient);
	// }

}
