package com.remusrd.oauthsample.util;

import java.security.*;
import java.util.Base64;

public class KeyPairGenerator {

	public static void main(String[] args) {
		try {
			java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");

			// Initialize KeyPairGenerator.
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);

			// Generate Key Pairs, a private key and a public key.
			KeyPair keyPair = keyGen.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			Base64.Encoder encoder = Base64.getEncoder();
			System.out.println("privateKey: " + encoder.encodeToString(privateKey.getEncoded()));
			System.out.println("publicKey: " + encoder.encodeToString(publicKey.getEncoded()));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error generating key" + e);
		}
	}
}
