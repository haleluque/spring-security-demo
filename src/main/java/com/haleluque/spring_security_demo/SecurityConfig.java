package com.haleluque.spring_security_demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration //configuration to the app context
@EnableWebSecurity //specifies the security config
@EnableMethodSecurity
public class SecurityConfig {


    /**
     * Automatically extracts the db configurations into a datasource bean
     */
    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests.anyRequest()).authenticated(); //ask for auth for every http request
        });
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); //requests are stateless
        //http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults()); //enables basic auth
        return (SecurityFilterChain) http.build();
    }


    /**
     * Non-persistent implementation of UserDetailsManager
     * in memory map, won't persist
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                //.password("{noop}user1") //prefix to saved as plain text, not encoded
                .password(passwordEncoder().encode("user1"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetailsManager
                = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;
        //return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
