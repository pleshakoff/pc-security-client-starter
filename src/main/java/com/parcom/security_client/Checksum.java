package com.parcom.security_client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;


@Slf4j
public class Checksum extends TokenUtils {

	private static final String KEY =  "bF$HTVG4t\"BB\"JLY/W>)uX!";
	public static final String CHECKSUM = "checksum";
	private static final String CHECKSUM_ERROR = "access.wrong_check_sum";
	private static final String IDENTIFIER = "IDENTIFIER";

	public static String createChecksum(@NotNull Long id) {
        if (id == null) {
			 throw new  RuntimeException("Id can't be null");
		}

		Date now = new Date();
		Claims claims = Jwts.claims().setSubject(CHECKSUM);
		claims.put(IDENTIFIER, id);

		return Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(new Date())
				.setExpiration( new Date(now.getTime() + TimeUnit.MINUTES.toMillis(5)))
				.signWith(SignatureAlgorithm.HS512, KEY)
				.compact();
	}


	static public void validateCheckSum(String checksum,Long id)	{

		DefaultClaims claims;
		try {
			claims = (DefaultClaims) Jwts.parser().setSigningKey(KEY).parse(checksum).getBody();
		} catch (Exception ex) {
			log.error("Check sum error",ex);
			throw new RuntimeException(CHECKSUM_ERROR);
		}
		Date expiredDate = claims.getExpiration();
		if (expiredDate == null) {
			throw new RuntimeException(CHECKSUM_ERROR);		}
		if (!expiredDate.after(new Date())) {
			throw new RuntimeException(CHECKSUM_ERROR);
		}
		Long checksumId = claims.get(IDENTIFIER, Long.class);
		if (checksumId == null||!checksumId.equals(id)) {
			throw new RuntimeException(CHECKSUM_ERROR);
		}
	}

}