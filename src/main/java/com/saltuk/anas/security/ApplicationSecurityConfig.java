package com.saltuk.anas.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//TODO: fix deprecated class

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails boris = User.builder()
                .username("boris")
                .password(passwordEncoder.encode("password"))
                .roles("STUDENT") //ROLE_STUDENT
                .build();

        UserDetails varvara = User.builder()
                .username("varvara")
                .password(passwordEncoder.encode("password123"))
                .roles("ADMIN") //ROLE_STUDENT
                .build();
        return new InMemoryUserDetailsManager(boris, varvara);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*",  "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
        //it says "we wanna have authorize requests they have be authenticated via httpBasic
    }
}
