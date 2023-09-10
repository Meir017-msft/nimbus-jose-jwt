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


import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.Curve;


/**
 * The base abstract class for multi-recipient encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObjectJSON JWE objects} with a shared symmetric
 * key.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_384}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_512}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP} (deprecated)
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5} (deprecated)
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_256}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_384}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_521}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#X25519} (Curve25519)
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#XC20P}
 * </ul>
 * 
 * @version 2023-03-24
 */
public abstract class MultiCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms by the direct crypto provider class.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods by the direct crypto provider
	 * class.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * The JWE algorithms compatible with each key size in bits.
	 */
	public static final Map<Integer,Set<JWEAlgorithm>> COMPATIBLE_ALGORITHMS;


	/**
	 * The supported EC JWK curves by the ECDH crypto provider class.
	 */
	public static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES;


	static {
		Set<JWEAlgorithm> algs = new LinkedHashSet<>();
		algs.add(null);
		algs.add(JWEAlgorithm.A128KW);
		algs.add(JWEAlgorithm.A192KW);
		algs.add(JWEAlgorithm.A256KW);
		algs.add(JWEAlgorithm.A128GCMKW);
		algs.add(JWEAlgorithm.A192GCMKW);
		algs.add(JWEAlgorithm.A256GCMKW);
		algs.add(JWEAlgorithm.DIR);
		algs.add(JWEAlgorithm.ECDH_ES_A128KW);
		algs.add(JWEAlgorithm.ECDH_ES_A192KW);
		algs.add(JWEAlgorithm.ECDH_ES_A256KW);
		algs.add(JWEAlgorithm.RSA1_5);
		algs.add(JWEAlgorithm.RSA_OAEP);
		algs.add(JWEAlgorithm.RSA_OAEP_256);
		algs.add(JWEAlgorithm.RSA_OAEP_384);
		algs.add(JWEAlgorithm.RSA_OAEP_512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

		Map<Integer,Set<JWEAlgorithm>> algsMap = new HashMap<>();
		Set<JWEAlgorithm> bit128Algs = new HashSet<>();
		Set<JWEAlgorithm> bit192Algs = new HashSet<>();
		Set<JWEAlgorithm> bit256Algs = new HashSet<>();
		bit128Algs.add(JWEAlgorithm.A128GCMKW);
		bit128Algs.add(JWEAlgorithm.A128KW);
		bit192Algs.add(JWEAlgorithm.A192GCMKW);
		bit192Algs.add(JWEAlgorithm.A192KW);
		bit256Algs.add(JWEAlgorithm.A256GCMKW);
		bit256Algs.add(JWEAlgorithm.A256KW);
		algsMap.put(128,Collections.unmodifiableSet(bit128Algs));
		algsMap.put(192,Collections.unmodifiableSet(bit192Algs));
		algsMap.put(256,Collections.unmodifiableSet(bit256Algs));
		COMPATIBLE_ALGORITHMS = Collections.unmodifiableMap(algsMap);

		Set<Curve> curves = new LinkedHashSet<>();
		curves.add(Curve.P_256);
		curves.add(Curve.P_384);
		curves.add(Curve.P_521);
		curves.add(Curve.X25519);
		SUPPORTED_ELLIPTIC_CURVES = Collections.unmodifiableSet(curves);
	}


	/**
	 * Returns the names of the supported elliptic curves. These correspond
	 * to the {@code crv} EC JWK parameter.
	 *
	 * @return The supported elliptic curves.
	 */
	public Set<Curve> supportedEllipticCurves() {

		return SUPPORTED_ELLIPTIC_CURVES;
	}


	/**
	 * Creates a new multi-recipient encryption / decryption provider.
	 *
	 * @param cek The Content Encryption Key (CEK). Must be 128 bits (16
	 *            bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *            bits (48 bytes) or 512 bits (64 bytes) long. Must not be
	 *            {@code null}.
	 *
	 * @throws KeyLengthException If the CEK length is not compatible.
	 */
	protected MultiCryptoProvider(final SecretKey cek)
		throws KeyLengthException {

		super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS, cek);
	}
}
