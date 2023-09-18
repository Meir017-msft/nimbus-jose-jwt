/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.jca.JWEJCAContext;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version 2023-09-18
 */
public abstract class BaseJWEProvider implements JWEProvider {


	/**
	 * The acceptable CEK algorithms.
	 */
	private static final Set<String> ACCEPTABLE_CEK_ALGS = Collections.unmodifiableSet(
		new HashSet<>(Arrays.asList("AES", "ChaCha20"))
	);


	/**
	 * The supported algorithms by the JWE provider instance.
	 */
	private final Set<JWEAlgorithm> algs;


	/**
	 * The supported encryption methods by the JWE provider instance.
	 */
	private final Set<EncryptionMethod> encs;


	/**
	 * The JWE JCA context.
	 */
	private final JWEJCAContext jcaContext = new JWEJCAContext();


	/**
	 * The externally supplied AES content encryption key (CEK) to use,
	 * {@code null} to generate a CEK for each JWE.
	 */
	private final SecretKey cek;


	/**
	 * Creates a new base JWE provider.
	 *
	 * @param algs The supported algorithms by the JWE provider instance.
	 *             Must not be {@code null}.
	 * @param encs The supported encryption methods by the JWE provider
	 *             instance. Must not be {@code null}.
	 */
	public BaseJWEProvider(final Set<JWEAlgorithm> algs,
		               final Set<EncryptionMethod> encs) {

		this(algs, encs, null);
	}


	/**
	 * Creates a new base JWE provider.
	 *
	 * @param algs The supported algorithms by the JWE provider instance.
	 *             Must not be {@code null}.
	 * @param encs The supported encryption methods by the JWE provider
	 *             instance. Must not be {@code null}.
	 * @param cek  The content encryption key (CEK) to use. If specified
	 *             its algorithm must be "AES" or "ChaCha20" and its length
	 *             must match the expected for the JWE encryption method
	 *             ("enc"). If {@code null} a CEK will be generated for
	 *             each JWE.
	 */
	public BaseJWEProvider(final Set<JWEAlgorithm> algs,
		               final Set<EncryptionMethod> encs,
		               final SecretKey cek) {

		if (algs == null) {
			throw new IllegalArgumentException("The supported JWE algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);


		if (encs == null) {
			throw new IllegalArgumentException("The supported encryption methods must not be null");
		}

		this.encs = encs;

		if (cek != null && algs.size() > 1 && (cek.getAlgorithm() == null || ! ACCEPTABLE_CEK_ALGS.contains(cek.getAlgorithm()))) {
			throw new IllegalArgumentException("The algorithm of the content encryption key (CEK) must be AES or ChaCha20");
		}

		this.cek = cek;
	}


	@Override
	public Set<JWEAlgorithm> supportedJWEAlgorithms() {

		return algs;
	}


	@Override
	public Set<EncryptionMethod> supportedEncryptionMethods() {

		return encs;
	}


	@Override
	public JWEJCAContext getJCAContext() {

		return jcaContext;
	}


	/**
	 * Returns {@code true} if a content encryption key (CEK) was
	 * provided at construction time.
	 *
	 * @return {@code true} if a CEK was provided at construction time,
	 *         {@code false} if CEKs will be internally generated.
	 */
	protected boolean isCEKProvided() {
		return cek != null;
	}


	/**
	 * Returns the content encryption key (CEK) to use. Unless a CEK was
	 * provided at construction time this will be a new internally
	 * generated CEK.
	 *
	 * @param enc The encryption method. Must not be {@code null}.
	 *
	 * @return The content encryption key (CEK).
	 *
	 * @throws JOSEException If an internal exception is encountered.
	 */
	protected SecretKey getCEK(final EncryptionMethod enc)
		throws JOSEException {

		return (isCEKProvided() || enc == null) ? cek : ContentCryptoProvider.generateCEK(enc, jcaContext.getSecureRandom());
	}
}

