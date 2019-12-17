package com.parcom.security_client;


import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.util.Strings;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Filter;
import java.util.logging.LogRecord;

import static com.parcom.security_client.ExceptionResource.getExceptionResource;

@RequiredArgsConstructor
public class AuthenticationTokenProcessingFilter extends GenericFilterBean implements Filter {

    private final MessageSource messageSource;


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest httpRequest = this.getAsHttpRequest(request);
        String authToken = this.extractAuthTokenFromRequest(httpRequest);
        if (authToken != null) {
            try {
                UserDetails userDetails = TokenValidate.validateToken(authToken);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                chain.doFilter(request, response);
            } catch (Exception e) {
                handleException((HttpServletRequest) request, (HttpServletResponse) response, e);
            }
        } else
            chain.doFilter(request, response);
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response, Exception e) throws IOException {
        String message = messageSource.getMessage(e.getMessage(), null, e.getMessage(), LocaleContextHolder.getLocale());
        ExceptionResource exceptionResource = getExceptionResource(request,e, message);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().write(exceptionResource.toJson().getBytes(StandardCharsets.UTF_8));
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    }


    private HttpServletRequest getAsHttpRequest(ServletRequest request) {
        if (!(request instanceof HttpServletRequest)) {
            throw new RuntimeException("Expecting an HTTP request");
        }
        return (HttpServletRequest) request;
    }

    private String extractAuthTokenFromRequest(HttpServletRequest httpRequest) {
        /* Get token from header */
        String authToken = httpRequest.getHeader(UserUtils.X_AUTH_TOKEN);

        /* If token not found get it from request parameter */
        if (Strings.isEmpty(authToken)) {
            authToken = httpRequest.getParameter(UserUtils.TOKEN);
        }
        return (Strings.isNotEmpty(authToken)) ? authToken : null;
    }


    @Override
    public boolean isLoggable(LogRecord record) {
        return false;
    }
}