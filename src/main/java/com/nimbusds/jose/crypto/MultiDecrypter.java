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


import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.JWEHeaderValidation;
import com.nimbusds.jose.crypto.impl.MultiCryptoProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.jcip.annotations.ThreadSafe;


/**
 * Multi-recipient decrypter of {@link com.nimbusds.jose.JWEObjectJSON JWE objects}.
 *
 * <p>This class is thread-safe.
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256} (requires 256 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384} (requires 384 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512} (requires 512 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM} (requires 128 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM} (requires 192 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM} (requires 256 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED} (requires 256 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED} (requires 512 bit key)
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#XC20P} (requires 256 bit key)
 * </ul>
 *
 * @author Egor Puzanov
 * @version 2023-09-10
 */
@ThreadSafe
public class MultiDecrypter extends MultiCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The private JWK key.
	 */
	private final JWK jwk;


	/**
	 * The key id of the private JWK key.
	 */
	private final String kid;


	/**
	 * The Cerificate URL of the private JWK key.
	 */
	private final URI x5u;


	/**
	 * The Certificate thumbprint of the private JWK key.
	 */
	private final Base64URL x5t;


	/**
	 * The Certificate SHA256 thumbprint of the private JWK key.
	 */
	private final Base64URL x5t256;


	/**
	 * The Certificate chain of the private JWK key.
	 */
	private final List<Base64> x5c;


	/**
	 * The Thumbprint of the private JWK key.
	 */
	private final Base64URL thumbprint;


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new multi-recipient decrypter.
	 *
	 * @param jwk The JSON Web Key (JWK). Must contain a private part. Must
	 *            not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 * @throws JOSEException      If an internal exception is encountered.
	 */
	public MultiDecrypter(final JWK jwk)
		throws JOSEException, KeyLengthException {

		this(jwk, null);
	}


	/**
	 * Creates a new multi-recipient decrypter.
	 *
	 * @param jwk            The JSON Web Key (JWK). Must contain a private
	 *                       part. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 * @throws JOSEException      If an internal exception is encountered.
	 */
	public MultiDecrypter(final JWK jwk, final Set<String> defCritHeaders)
		throws JOSEException, KeyLengthException {

		super(null);

		if (jwk == null) {
			throw new IllegalArgumentException("The private key (JWK) must not be null");
		}
		this.jwk = jwk;
		this.kid = jwk.getKeyID();
		this.x5c = jwk.getX509CertChain();
		this.x5u = jwk.getX509CertURL();
		this.x5t = jwk.getX509CertThumbprint();
		this.x5t256 = jwk.getX509CertSHA256Thumbprint();
		this.thumbprint = jwk.computeThumbprint();

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	private boolean jwkMatched(final JWEHeader recipientHeader)
		throws JOSEException {

		if (thumbprint.toString().equals(recipientHeader.getKeyID())) {
			return true;
		}
		JWK rjwk = recipientHeader.getJWK();
		if (rjwk != null && thumbprint.equals(rjwk.computeThumbprint())) {
			return true;
		}
		if (x5u != null && x5u.equals(recipientHeader.getX509CertURL())) {
			return true;
		}
		if (x5t != null && x5t.equals(recipientHeader.getX509CertThumbprint())) {
			return true;
		}
		if (x5t256 != null && x5t256.equals(recipientHeader.getX509CertSHA256Thumbprint())) {
			return true;
		}
		List<Base64> rx5c = recipientHeader.getX509CertChain();
		if (x5c != null && rx5c != null && x5c.containsAll(rx5c) && rx5c.containsAll(x5c)) {
			return true;
		}
		if (kid != null && kid.equals(recipientHeader.getKeyID())) {
			return true;
		}
		return false;
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

		if (iv == null) {
			throw new JOSEException("Unexpected present JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}

		if (aad == null) {
			throw new JOSEException("Missing JWE additional authenticated data (AAD)");
		}

		final JWEDecrypter decrypter;
		final KeyType kty = jwk.getKeyType();
		final Set<String> defCritHeaders = critPolicy.getDeferredCriticalHeaderParams();
		JWEObjectJSON.Recipient recipient = null;
		JWEHeader recipientHeader = null;
		try {
			// The encryptedKey value contains the Base64URL encoded JSON string
			// {"recipients":[{recipient1},{recipient2}]} if multiple recipients are used.
			for (Object recipientMap : JSONObjectUtils.getJSONArray((JSONObjectUtils.parse(encryptedKey.decodeToString())), "recipients")) {
				try {
					recipient = JWEObjectJSON.Recipient.parse((Map<String, Object>) recipientMap);
					recipientHeader = (JWEHeader) header.join(recipient.getUnprotectedHeader());
				} catch (Exception e) {
					throw new JOSEException(e.getMessage());
				}
				if (jwkMatched(recipientHeader)) {
					break;
				}
				recipientHeader = null;
			}
		} catch (Exception e) {
			// If encryptedKey can not be parsed as a JSON Object, it means the encryptedKey contains the RAW encrypted key value.
			recipientHeader = header;
			recipient = new JWEObjectJSON.Recipient(null, encryptedKey);
		}

		if (recipientHeader == null) {
			throw new JOSEException("No recipient found");
		}

		final JWEAlgorithm alg = JWEHeaderValidation.getAlgorithmAndEnsureNotNull(recipientHeader);
		critPolicy.ensureHeaderPasses(recipientHeader);

		if (KeyType.RSA.equals(kty) && RSADecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			decrypter = new RSADecrypter(jwk.toRSAKey().toRSAPrivateKey(), defCritHeaders);
		} else if (KeyType.EC.equals(kty) && ECDHDecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			decrypter = new ECDHDecrypter(jwk.toECKey().toECPrivateKey(), defCritHeaders);
		} else if (KeyType.OCT.equals(kty) && AESDecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			decrypter = new AESDecrypter(jwk.toOctetSequenceKey().toSecretKey("AES"), defCritHeaders);
		} else if (KeyType.OCT.equals(kty) && DirectDecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			decrypter = new DirectDecrypter(jwk.toOctetSequenceKey().toSecretKey("AES"), defCritHeaders);
		} else if (KeyType.OKP.equals(kty) && X25519Decrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			decrypter = new X25519Decrypter(jwk.toOctetKeyPair(), defCritHeaders);
		} else {
			throw new JOSEException("Unsupported algorithm");
		}

		return decrypter.decrypt(recipientHeader, recipient.getEncryptedKey(), iv, cipherText, authTag, aad);
	}
}
