package org.example;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;

@Configuration
@EnableWebSecurity
public class SecurityConfig {



    @Bean
    public PasswordEncoder passwordEncoder() {
        // your “always matches” encoder
        return new PasswordEncoder() {
            @Override public String encode(CharSequence raw) { return raw.toString(); }
            @Override public boolean matches(CharSequence raw, String enc) { return true; }
        };
    }

    @Bean
    public DaoAuthenticationProvider daoAuthProvider(
            UserDetailsService uds,
            PasswordEncoder pe
    ) {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1) Disable CSRF so both your API clients and the H2 web console can submit forms
                .csrf(csrf -> csrf.disable())

                // 2) Allow H2 console to be loaded in a frame
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin())
                )

                // 3) URL authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Registration and user‐existence check
                        .requestMatchers(HttpMethod.GET,  "/api/users/exists/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/register").permitAll()
                        // message polling and posting require auth
                        .requestMatchers(HttpMethod.GET,    "/api/messages/**").authenticated()
                        .requestMatchers(HttpMethod.POST,   "/api/messages").authenticated()
                        // Key exchange endpoints (clients need to PUT and GET public keys)
                        .requestMatchers(HttpMethod.PUT, "/api/users/*/public-key").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/users/*/public-key").permitAll()

                        // H2 console
                        .requestMatchers("/h2-console/**").permitAll()

                        // Everything else requires authentication
                        .anyRequest().authenticated()
                )

                // 4) Use HTTP Basic for your API …
                .httpBasic(Customizer.withDefaults())

                // 5) … but keep the default session management so the H2 console’s login will work
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                );

        return http.build();
    }

}