package com.parcom.security_client;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.parcom.security_client.TokenCreate.createToken;

public class AsyncUtils {

    static public void authByToken(String token){
        UserDetailsPC userDetails = TokenValidate.validateToken(token,true);
        userDetails.setToken(createToken(userDetails));
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }


}
