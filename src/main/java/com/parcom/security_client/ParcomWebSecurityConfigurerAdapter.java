package com.parcom.security_client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.security.PermitAll;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Configuration
@ConditionalOnMissingBean(ParcomWebSecurityConfigurerAdapter.class)
@EnableConfigurationProperties(SecurityProps.class)
public class ParcomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    protected MessageSource messageSource;

    @Autowired
    SecurityProps securityProps;

    private List<String> permitAllList;

    public ParcomWebSecurityConfigurerAdapter() {
        this.permitAllList =   new ArrayList<>();
        permitAllList.add("/webjars/springfox-swagger-ui/**");
        permitAllList.add("/swagger-ui.html/**");
        permitAllList.add("/swagger-resources/**");
        permitAllList.add("/v2/api-docs");
        permitAllList.add("/actuator/**");
    }


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
        permitAllList.addAll(securityProps.getPermitted());
        String[] permitListArray = permitAllList.toArray(new String[0]);
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