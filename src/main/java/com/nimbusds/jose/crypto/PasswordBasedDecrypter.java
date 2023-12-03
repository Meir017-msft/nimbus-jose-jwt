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


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.Set;


/**
 * Password-based decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}.
 * Expects a password.
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.8">section 4.8</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS256_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS384_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS512_A256KW}
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
 * @author Vladimir Dzhuvinov
 * @author Egor Puzanov
 * @version 2023-12-03
 */
@ThreadSafe
public class PasswordBasedDecrypter extends PasswordBasedCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The maximum allowed iteration count (1 million).
	 */
	public static final int MAX_ALLOWED_ITERATION_COUNT = 1_000_000;


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new password-based decrypter.
	 *
	 * @param password The password bytes. Must not be empty or
	 *                 {@code null}.
	 */
	public PasswordBasedDecrypter(final byte[] password) {

		super(password);
	}


	/**
	 * Creates a new password-based decrypter.
	 *
	 * @param password The password, as a UTF-8 encoded string. Must not be
	 *                 empty or {@code null}.
	 */
	public PasswordBasedDecrypter(final String password) {

		super(password.getBytes(StandardCharset.UTF_8));
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	/**
	 * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
	 *
	 * @param header       The JSON Web Encryption (JWE) header. Must
	 *                     specify a supported JWE algorithm and method.
	 *                     Must not be {@code null}.
	 * @param encryptedKey The encrypted key, {@code null} if not required
	 *                     by the JWE algorithm.
	 * @param iv           The initialisation vector, {@code null} if not
	 *                     required by the JWE algorithm.
	 * @param cipherText   The cipher text to decrypt. Must not be
	 *                     {@code null}.
	 * @param authTag      The authentication tag, {@code null} if not
	 *                     required.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported, if a critical header parameter is
	 *                       not supported or marked for deferral to the
	 *                       application, or if decryption failed for some
	 *                       other reason.
	 */
	@Deprecated
	public byte[] decrypt(final JWEHeader header,
		       final Base64URL encryptedKey,
		       final Base64URL iv,
		       final Base64URL cipherText,
		       final Base64URL authTag)
		throws JOSEException {

		return decrypt(header, encryptedKey, iv, cipherText, authTag, AAD.compute(header));
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag,
			      final byte[] aad)
		throws JOSEException {

		// Validate required JWE parts
		if (encryptedKey == null) {
			throw new JOSEException("Missing JWE encrypted key");
		}

		if (iv == null) {
			throw new JOSEException("Missing JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}

		if (header.getPBES2Salt() == null) {
			throw new JOSEException("Missing JWE p2s header parameter");
		}

		final byte[] salt = header.getPBES2Salt().decode();

		if (header.getPBES2Count() < 1) {
			throw new JOSEException("Missing JWE p2c header parameter");
		}

		final int iterationCount = header.getPBES2Count();

		if (iterationCount > MAX_ALLOWED_ITERATION_COUNT) {
			throw new JOSEException("The JWE p2c header exceeds the maximum allowed " + MAX_ALLOWED_ITERATION_COUNT + " count");
		}

		critPolicy.ensureHeaderPasses(header);

		final JWEAlgorithm alg = JWEHeaderValidation.getAlgorithmAndEnsureNotNull(header);
		final byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		final PRFParams prfParams = PRFParams.resolve(alg, getJCAContext().getMACProvider());
		final SecretKey psKey = PBKDF2.deriveKey(getPassword(), formattedSalt, iterationCount, prfParams);

		final SecretKey cek = AESKW.unwrapCEK(psKey, encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());

		return ContentCryptoProvider.decrypt(header, aad, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
	}
}
