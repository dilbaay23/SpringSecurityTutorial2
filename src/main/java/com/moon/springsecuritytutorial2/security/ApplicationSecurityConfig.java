package com.moon.springsecuritytutorial2.security;

/**
 * Created by Moon on 12/9/2020
 */

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import static com.moon.springsecuritytutorial2.security.ApplicationUserPermission.*;
import static com.moon.springsecuritytutorial2.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  // if we use annotations with method for permission, we should add this annotation and set prePostEnable=true
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
                .antMatchers("/","index","/css/*", "/js/*") .permitAll()    //we add this paths into white list
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())  // we used annotation in controller class with the methods
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())  // this order is very important that it can change all permissions:/
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
  //              .roles(ApplicationUserRole.STUDENT.name())  //ROLE_STUDENT
               .authorities(STUDENT.getGrantedAuthorities())
               .build();

        UserDetails luaUser=  User.builder()
                .username("lua")
                .password(passwordEncoder.encode("password123"))
 //               .roles(ApplicationUserRole.ADMIN.name())  //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails bahaUser=  User.builder()
                .username("baha")
                .password(passwordEncoder.encode("password111"))
  //              .roles(ApplicationUserRole.ADMINTRAINEE.name())  //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

       return new InMemoryUserDetailsManager(moonUser,luaUser,bahaUser);    //this is a class (InMemoryUserDetailsManager) which implements UserDetailsService
    }
}
