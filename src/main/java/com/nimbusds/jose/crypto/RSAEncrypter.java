/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jose.crypto;


import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.*;
import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. Expects a
 * public RSA key.
 *
 * <p>Encrypts the plain text with a generated AES key (the Content Encryption
 * Key) according to the specified JOSE encryption method, then encrypts the
 * CEK with the public RSA key and returns it alongside the IV, cipher text and
 * authentication tag. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.2">4.2</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.3">4.3</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_384}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_512}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP} (deprecated)
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5} (deprecated)
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
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @author Jun Yu
 * @author Egor Puzanov
 * @version 2023-05-17
 */
@ThreadSafe
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


	
	/**
	 * Creates a new RSA encrypter.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey) {

		this(publicKey, null);
	}


	/**
	 * Creates a new RSA encrypter.
	 *
	 *  @param rsaJWK The RSA JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the RSA JWK extraction failed.
	 */
	public RSAEncrypter(final RSAKey rsaJWK)
		throws JOSEException {

		this(rsaJWK.toRSAPublicKey());
	}


	/**
	 * Creates a new RSA encrypter with an optionally specified content
	 * encryption key (CEK).
	 *
	 * @param publicKey            The public RSA key. Must not be
	 *                             {@code null}.
	 * @param contentEncryptionKey The content encryption key (CEK) to use.
	 *                             If specified its algorithm must be "AES"
	 *                             or "ChaCha20" and its length must match
	 *                             the expected for the JWE encryption
	 *                             method ("enc"). If {@code null} a CEK
	 *                             will be generated for each JWE.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey, final SecretKey contentEncryptionKey) {

		super(contentEncryptionKey);

		if (publicKey == null) {
			throw new IllegalArgumentException("The public RSA key must not be null");
		}
		this.publicKey = publicKey;
	}
	
	
	/**
	 * Gets the public RSA key.
	 *
	 * @return The public RSA key.
	 */
	public RSAPublicKey getPublicKey() {
		
		return publicKey;
	}


	/**
	 * Encrypts the specified clear text of a {@link JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must specify
	 *                  a supported JWE algorithm and method. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The resulting JWE crypto parts.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported or if encryption failed for some
	 *                       other internal reason.
	 */
	@Deprecated
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		return encrypt(header, clearText, AAD.compute(header));
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText, final byte[] aad)
		throws JOSEException {

		final JWEAlgorithm alg = getAlgorithmAndEnsureNotNull(header);
		final EncryptionMethod enc = header.getEncryptionMethod();
		final SecretKey cek = getCEK(enc); // Generate and encrypt the CEK according to the enc method

		final Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {
			encryptedKey = Base64URL.encode(RSA1_5.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {
			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			encryptedKey = Base64URL.encode(RSA_OAEP_SHA2.encryptCEK(publicKey, cek, 256, getJCAContext().getKeyEncryptionProvider()));
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_384)) {
			encryptedKey = Base64URL.encode(RSA_OAEP_SHA2.encryptCEK(publicKey, cek, 384, getJCAContext().getKeyEncryptionProvider()));
		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_512)) {
			encryptedKey = Base64URL.encode(RSA_OAEP_SHA2.encryptCEK(publicKey, cek, 512, getJCAContext().getKeyEncryptionProvider()));
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		return ContentCryptoProvider.encrypt(header, clearText, aad, cek, encryptedKey, getJCAContext());
	}
}