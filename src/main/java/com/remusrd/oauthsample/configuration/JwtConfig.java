package com.remusrd.oauthsample.configuration;

import org.springframework.beans.factory.annotation.Value;

public class JwtConfig {

	@Value("${security.jwt.uri:/auth/**}")
	private String Uri;

	@Value("${security.jwt.header:Authorization}")
	private String header;

	@Value("${security.jwt.prefix:Bearer }")
	private String prefix;

	@Value("${security.jwt.expiration:#{24*60*60}}")
	private int expiration;

	public String getUri() {
		return Uri;
	}

	public String getHeader() {
		return header;
	}

	public String getPrefix() {
		return prefix;
	}

	public int getExpiration() {
		return expiration;
	}

}

