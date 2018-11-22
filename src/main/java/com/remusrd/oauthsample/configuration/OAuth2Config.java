package com.remusrd.oauthsample.configuration;

import com.remusrd.oauthsample.util.SecretKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Configuration
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(OAuth2Config.class);

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	SecretKeyService secretKeyService;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
				.withClient("client1")
				.secret(passwordEncoder.encode("client1secret"))
				.authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials",
						"refresh_token")
				.scopes("cursos")
				.and()
				.withClient("client2")
				.secret(passwordEncoder.encode("client1secret"))
				.authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials",
						"refresh_token")
				.scopes("profesor")

		;
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager);
		endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer())
				.authenticationManager(authenticationManager);
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtTokenEnhancer());
	}

	@Bean
	protected JwtAccessTokenConverter jwtTokenEnhancer() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		try {
			converter.setKeyPair(secretKeyService.getKeyPair());
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			logger.error("Error with keyPair" + e);
		}
		return converter;
	}
}
