package com.parcom.security_client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.util.Collection;
import java.util.Date;


class TokenValidate extends TokenUtils {


	static UserDetailsPC  validateToken(String token)
	{
		return validateToken(token,false);
	}

	static UserDetailsPC  validateToken(String token,boolean ignoreExpired)
	{

		Claims claims;
		try {
			claims = (Claims) Jwts.parser().setSigningKey(MAGIC_KEY).parse(token).getBody();
		}
		catch (ExpiredJwtException ex) {
			if (ignoreExpired)
				claims = ex.getClaims();
			else
		     	throw new SessionAuthenticationException("security.token_expired_date_error");
		}
		catch (Exception ex) {
			throw new SessionAuthenticationException("security.token_invalid");
		}
		Date expiredDate = claims.getExpiration();
		if (expiredDate == null) {
			throw new SessionAuthenticationException("security.token_invalid");
		}
		if (expiredDate.before(new Date())&&!ignoreExpired) {
			throw new SessionAuthenticationException("security.token_expired_date_error");
		}
		String name = claims.get(JWT_USER, String.class);
		if (name == null) {
			throw new SessionAuthenticationException("security.token_invalid");
		}

		String userName = claims.getSubject();
		Long id = claims.get(JWT_ID_USER, Long.class);
		if (id == null) {
			throw new SessionAuthenticationException("security.token_invalid");
		}
		Long idGroup = claims.get(JWT_ID_GROUP, Long.class);
		if (idGroup == null) {
			throw new SessionAuthenticationException("security.token_invalid");
		}

		Long idStudent = claims.get(JWT_ID_STUDENT, Long.class);
	
		Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(JWT_AUTHORITIES));

		return new UserDetailsPC(userName,id,authorities,idGroup, idStudent,token);
	}

}