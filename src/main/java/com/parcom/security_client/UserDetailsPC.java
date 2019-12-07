package com.parcom.security_client;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserDetailsPC implements UserDetails {

    private final String username;
    private final String password;
    private final Long id;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean enabled;
    private final Long idGroup;

    public UserDetailsPC(String username, String password, Long id, Collection<? extends GrantedAuthority> authorities, boolean enabled, Long idGroup) {
        this.username = username;
        this.password = password;
        this.id = id;
        this.authorities = authorities;
        this.enabled = enabled;
        this.idGroup = idGroup;
    }

    public UserDetailsPC(String username, Long id, Collection<? extends GrantedAuthority> authorities, Long idGroup) {
        this.username = username;
        this.id = id;
        this.authorities = authorities;
        this.idGroup = idGroup;
        this.password = null;
        this.enabled = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
             return authorities;
    }

    public String getAuthoritiesStr() {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
    }

    public String getRole() {
       return authorities.stream().map(Object::toString).findFirst().orElse("");
    }


    public Long getId() {
        return id;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public Long getIdGroup() {
        return idGroup;
    }


}
