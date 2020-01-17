package com.parcom.security_client;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.actuate.metrics.export.prometheus.PrometheusScrapeEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@Import(SecurityClientConfiguration.class)
@ConditionalOnMissingBean(ParcomWebSecurityConfigurerAdapter.class)
public class ParcomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    
    private final  UnauthorizedEntryPoint unauthorizedEntryPoint;

    private final AuthenticationTokenProcessingFilter authenticationTokenProcessingFilter;

    public ParcomWebSecurityConfigurerAdapter(UnauthorizedEntryPoint unauthorizedEntryPoint, AuthenticationTokenProcessingFilter authenticationTokenProcessingFilter) {
        this.unauthorizedEntryPoint = unauthorizedEntryPoint;
        this.authenticationTokenProcessingFilter = authenticationTokenProcessingFilter;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests((requests) -> {
                    requests.requestMatchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class, PrometheusScrapeEndpoint.class)).permitAll();
                    requests.antMatchers(
                            "/webjars/springfox-swagger-ui/**",
                            "/swagger-ui.html/**",
                            "/swagger-resources/**",
                            "/v2/api-docs").
                            permitAll();
                    requests.anyRequest().authenticated();
                });
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
        http.exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint);
        http.addFilterBefore(authenticationTokenProcessingFilter, UsernamePasswordAuthenticationFilter.class);
    }


}