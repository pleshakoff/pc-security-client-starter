package com.parcom.security_client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.security.PermitAll;
import java.util.Arrays;
import java.util.List;


@Configuration
@ConditionalOnMissingBean(ParcomWebSecurityConfigurerAdapter.class)
public class ParcomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private MessageSource messageSource;
    protected List<String> permitAllList = Arrays.asList(
            "/webjars/springfox-swagger-ui/**",
            "/swagger-ui.html/**",
            "/swagger-resources/**",
            "/v2/api-docs",
            "/actuator/**");

    @Bean
    AuthenticationTokenProcessingFilter authenticationTokenProcessingFilter() {
        return new AuthenticationTokenProcessingFilter(messageSource);
    }

    @Bean
    UnauthorizedEntryPoint unauthorizedEntryPoint() {
        return new UnauthorizedEntryPoint(messageSource);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String[] permitListArray = (String[]) permitAllList.toArray();
        http.
                authorizeRequests((requests) -> {
                    requests.antMatchers(permitListArray).permitAll();
                    requests.anyRequest().authenticated();
                });
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
        http.exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint());
        http.addFilterBefore(authenticationTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }



}