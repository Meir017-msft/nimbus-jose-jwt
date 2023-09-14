/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.util.StandardCharset;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @author Ulrich Winter
 * @version 2019-09-14
 */
public abstract class MACProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the MAC provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.HS256);
		algs.add(JWSAlgorithm.HS384);
		algs.add(JWSAlgorithm.HS512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Gets the matching Java Cryptography Architecture (JCA) algorithm 
	 * name for the specified HMAC-based JSON Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return The matching JCA algorithm name.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static String getJCAAlgorithmName(final JWSAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWSAlgorithm.HS256)) {
			return "HMACSHA256";
		} else if (alg.equals(JWSAlgorithm.HS384)) {
			return "HMACSHA384";
		} else if (alg.equals(JWSAlgorithm.HS512)) {
			return "HMACSHA512";
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * The secret, {@code null} if specified as {@link SecretKey}.
	 */
	private final byte[] secret;


	/**
	 * The secret key, {@code null} if specified as byte array.
	 */
	private final SecretKey secretKey;


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param secret        The secret. Must be at least 256 bits long and
	 *                      not {@code null}.
	 * @param supportedAlgs The supported HMAC algorithms. Must not be
	 *                      {@code null}.
	 *
	 * @throws KeyLengthException If the secret length is shorter than the
	 *                            minimum 256-bit requirement.
	 */
	protected MACProvider(final byte[] secret,
			      final Set<JWSAlgorithm> supportedAlgs)
		throws KeyLengthException {

		super(supportedAlgs);

		if (secret.length < 256 / 8) {
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}

		this.secret = secret;
		this.secretKey = null;
	}


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param secretKey     The secret key. Must be at least 256 bits long
	 *                      and not {@code null}.
	 * @param supportedAlgs The supported HMAC algorithms. Must not be
	 *                      {@code null}.
	 *
	 * @throws KeyLengthException If the secret length is shorter than the
	 *                            minimum 256-bit requirement.
	 */
	protected MACProvider(final SecretKey secretKey,
			      final Set<JWSAlgorithm> supportedAlgs)
		throws KeyLengthException {

		super(supportedAlgs);

		// An HSM based key will not expose its material and return null
		if (secretKey.getEncoded() != null && secretKey.getEncoded().length < 256 / 8) {
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}

		this.secretKey = secretKey;
		this.secret = null;
	}


	/**
	 * Gets the secret key.
	 *
	 * @return The secret key.
	 */
	public SecretKey getSecretKey() {
		if(this.secretKey != null) {
			return secretKey;
		} else if (secret != null){
			return new SecretKeySpec(secret, "MAC");
		} else {
			throw new IllegalStateException("Unexpected state");
		}
	}


	/**
	 * Gets the secret bytes.
	 *
	 * @return The secret bytes, {@code null} if this provider was
	 *         constructed with a {@link SecretKey} that doesn't expose the
	 *         key material.
	 */
	public byte[] getSecret() {
		if(this.secretKey != null) {
			return secretKey.getEncoded();
		} else if (secret != null){
			return secret;
		} else {
			throw new IllegalStateException("Unexpected state");
		}
	}


	/**
	 * Gets the secret as a UTF-8 encoded string.
	 *
	 * @return The secret as a UTF-8 encoded string, {@code null} if this
	 *         provider was constructed with a {@link SecretKey} that
	 *         doesn't expose the key material.
	 */
	public String getSecretString() {

		byte[] secret = getSecret();

		if (secret == null) {
			return null;
		}

		return new String(secret, StandardCharset.UTF_8);
	}
}
