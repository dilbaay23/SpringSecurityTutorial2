package com.moon.springsecuritytutorial2.security;

/**
 * Created by Moon on 12/9/2020
 */

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

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig  extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // we choose this method to secure things
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*", "/js/*")    //we add this paths into white list
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {      // this is for how you retrieve your users from the database
       UserDetails moonUser=  User.builder()
                .username("moonkoc")
                .password(passwordEncoder.encode("password"))
                .roles(ApplicationUserRole.STUDENT.name())  //ROLE_STUDENT
               .build();

        UserDetails luaUser=  User.builder()
                .username("lua")
                .password(passwordEncoder.encode("password123"))
                .roles(ApplicationUserRole.ADMIN.name())  //ROLE_ADMIN
                .build();

        UserDetails bahaUser=  User.builder()
                .username("baha")
                .password(passwordEncoder.encode("password111"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name())  //ROLE_ADMINTRAINEE
                .build();

       return new InMemoryUserDetailsManager(moonUser,luaUser,bahaUser);    //this is a class (InMemoryUserDetailsManager) which implements UserDetailsService
    }
}
