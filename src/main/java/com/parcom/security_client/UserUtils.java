package com.parcom.security_client;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.function.Function;


public class UserUtils {

    public static String ROLE_ADMIN= "ROLE_ADMIN";
    public static String ROLE_MEMBER= "ROLE_MEMBER";
    public static String ROLE_PARENT= "ROLE_PARENT";
    public static final String X_AUTH_TOKEN = "X-Auth-Token";
    public static final String TOKEN = "token";


    private static UserDetailsPC getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AccessDeniedException("Access denied");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String && principal.equals("anonymousUser")) {
            throw new AccessDeniedException("Access denied");
        }
        else
        {
            return (UserDetailsPC)authentication.getPrincipal();
        }
    }


    public static Long getIdUser() {

        return getPrincipal().getId();
    }

    public static String getRole() {

        return getPrincipal().getRole();
    }

    public static String getToken() {

        return getPrincipal().getToken();
    }


    public static Long getIdGroup() {

        return getPrincipal().getIdGroup();

    }


   }
