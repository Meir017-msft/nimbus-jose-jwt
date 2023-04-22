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


import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.MultiCryptoProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.jcip.annotations.ThreadSafe;


/**
 * Multirecipient decrypter of {@link com.nimbusds.jose.JWEObjectJSON JWE objects}.
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
 * @version 2023-03-26
 */
@ThreadSafe
public class MultiDecrypter extends MultiCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The private JWK key.
	 */
	private final JWK jwk;


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new multirecipient decrypter.
	 *
	 * @param jwk                 The JSON Web Key (JWK). Must contain a
	 *                            private part. Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public MultiDecrypter(final JWK jwk)
		throws KeyLengthException {

		this(jwk, null);
	}


	/**
	 * Creates a new multirecipient decrypter.
	 *
	 * @param jwk                 The JSON Web Key (JWK). Must contain a
	 *                            private part. Must not be {@code null}.
	 * @param defCritHeaders      The names of the critical header
	 *                            parameters that are deferred to the
	 *                            application for processing, empty set or
	 *                            {@code null} if none.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public MultiDecrypter(final JWK jwk, final Set<String> defCritHeaders)
		throws KeyLengthException {

		super(null);

		if (jwk == null) {
			throw new IllegalArgumentException("The private key (JWK) must not be null");
		}
		this.jwk = jwk;

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

		final JWEDecrypter decrypter;
		final KeyType kty = jwk.getKeyType();
		final Set<String> defCritHeaders = critPolicy.getDeferredCriticalHeaderParams();
		JWEHeader recipientHeader = header;
		Base64URL recipientEncryptedKey = encryptedKey;
		try {
			for (Object recipientMap : JSONObjectUtils.getJSONArray((JSONObjectUtils.parse(encryptedKey.decodeToString())), "recipients")) {
				Map<String, Object> recipientHeaderMap = header.toJSONObject();
				recipientHeaderMap.putAll(JSONObjectUtils.getJSONObject((Map<String, Object>) recipientMap, "header"));
				String kid = JSONObjectUtils.getString(recipientHeaderMap, "kid");
				if (kid.equals(jwk.getKeyID()) || kid.equals(jwk.computeThumbprint().toString())) {
					recipientHeader = JWEHeader.parse(recipientHeaderMap);
					recipientEncryptedKey = JSONObjectUtils.getBase64URL((Map<String, Object>) recipientMap, "encrypted_key");
					break;
				}
			}
		} catch (Exception e) {
		}

		final JWEAlgorithm alg = recipientHeader.getAlgorithm();

		if (iv == null) {
			throw new JOSEException("Unexpected present JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}

		if (aad == null) {
			throw new JOSEException("Missing JWE additional authenticated data (AAD)");
		}

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

		return decrypter.decrypt(recipientHeader, recipientEncryptedKey, iv, cipherText, authTag, aad);
	}
}
