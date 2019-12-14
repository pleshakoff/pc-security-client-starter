package com.parcom.security_client;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.function.Function;


public class UserUtils {

    public static String ROLE_ADMIN= "ROLE_ADMIN";
    public static String ROLE_MEMBER= "ROLE_MEMBER";
    public static String ROLE_PARENT= "ROLE_PARENT";
    public static final String X_AUTH_TOKEN = "X-Auth-Token";
    public static final String TOKEN = "token";


    private static Optional<UserDetailsPC> getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String && principal.equals("anonymousUser")) {
            return Optional.empty();
        }
        else
        {
            return  Optional.of((UserDetailsPC)authentication.getPrincipal());
        }
    }


    public static Long getIdUser() {

        return getPrincipal().map(UserDetailsPC::getId).orElse(null);
    }

    public static String getRole() {

        return getPrincipal().map(UserDetailsPC::getRole).orElse(null);
    }

    public static String getToken() {

        return getPrincipal().map(UserDetailsPC::getToken).orElse(null);
    }


    public static Long getIdGroup() {
        return getPrincipal().map(UserDetailsPC::getIdGroup).orElse(null);
    }

    public static Long getIdStudent() {
        return getPrincipal().map(UserDetailsPC::getIdStudent).orElse(null);
    }

   }
