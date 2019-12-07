package com.parcom.security_client;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.util.Collection;
import java.util.Date;


public class TokenValidate extends TokenUtils {

	static UserDetailsPC  validateToken(String token)
	{

		DefaultClaims claims;
		try {
			claims = (DefaultClaims) Jwts.parser().setSigningKey(MAGIC_KEY).parse(token).getBody();
		}
		catch (ExpiredJwtException ex) {
			throw new SessionAuthenticationException("exception.token_expired_date_error");
		}
		catch (Exception ex) {
			throw new SessionAuthenticationException("exception.token_corrupted");
		}
		Date expiredDate = claims.getExpiration();
		if (expiredDate == null) {
			throw new SessionAuthenticationException("exception.token_invalid");
		}
		if (!expiredDate.after(new Date())) {
			throw new SessionAuthenticationException("exception.token_expired_date_error");
		}
		String name = claims.get(JWT_USER, String.class);
		if (name == null) {
			throw new SessionAuthenticationException("exception.token_invalid");
		}

		String userName = claims.getSubject();
		Long id = claims.get(JWT_ID_USER, Long.class);
		if (id == null) {
			throw new SessionAuthenticationException("exception.token_invalid");
		}
		Long idGroup = claims.get(JWT_ID_GROUP, Long.class);
		if (idGroup == null) {
			throw new SessionAuthenticationException("exception.token_invalid");
		}

		Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(JWT_AUTHORITIES));

		return new UserDetailsPC(userName,id,authorities,idGroup, token);
	}

}