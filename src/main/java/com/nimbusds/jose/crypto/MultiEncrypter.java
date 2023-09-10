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
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.JWEHeaderValidation;
import com.nimbusds.jose.crypto.impl.MultiCryptoProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Map;


/**
 * Multi-recipient encrypter of {@link com.nimbusds.jose.JWEObjectJSON JWE
 * objects}.
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
 * @author Vladimir Dzhuvinov
 * @version 2023-09-10
 */
@ThreadSafe
public class MultiEncrypter extends MultiCryptoProvider implements JWEEncrypter {


	/**
	 * Common JWK and JWEHeader parameters.
	 */
	private static final String[] RECIPIENT_HEADER_PARAMS = {
		HeaderParameterNames.KEY_ID,
		HeaderParameterNames.ALGORITHM,
		HeaderParameterNames.X_509_CERT_URL,
		HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT,
		HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT,
		HeaderParameterNames.X_509_CERT_CHAIN
	};


	/**
	 * The JWK public keys.
	 */
	private final JWKSet keys;


	/**
	 * Creates a new multi-recipient encrypter.
	 *
	 * @param keys The keys to encrypt to. Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public MultiEncrypter(final JWKSet keys)
		throws KeyLengthException {

		this(keys, findDirectCEK(keys));
	}


	/**
	 * Creates a new multi-recipient encrypter.
	 *
	 * @param keys                 The keys to encrypt to. Must not be
	 *                             {@code null}.
	 * @param contentEncryptionKey The content encryption key (CEK) to use.
	 *                             If specified its algorithm must be "AES"
	 *                             or "ChaCha20" and its length must match
	 *                             the expected for the JWE encryption
	 *                             method ("enc"). If {@code null} a CEK
	 *                             will be generated for each JWE.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public MultiEncrypter(final JWKSet keys, final SecretKey contentEncryptionKey)
		throws KeyLengthException {
		
		super(contentEncryptionKey);

		if (keys == null) {
			throw new IllegalArgumentException("The JWK set must not be null");
		}

		for (JWK jwk : keys.getKeys()) {
			KeyType kty = jwk.getKeyType();
			if (jwk.getAlgorithm() == null) {
				throw new IllegalArgumentException("Each JWK must specify a key encryption algorithm");
			}
			JWEAlgorithm alg = JWEAlgorithm.parse(jwk.getAlgorithm().toString());
			if (JWEAlgorithm.DIR.equals(alg)
					&& KeyType.OCT.equals(kty)
					&& !jwk.toOctetSequenceKey().toSecretKey("AES").equals(contentEncryptionKey)) {
				throw new IllegalArgumentException("Bad CEK");
			}
			if (!((KeyType.RSA.equals(kty) && RSAEncrypter.SUPPORTED_ALGORITHMS.contains(alg))
					|| (KeyType.EC.equals(kty) && ECDHEncrypter.SUPPORTED_ALGORITHMS.contains(alg))
					|| (KeyType.OCT.equals(kty) && AESEncrypter.SUPPORTED_ALGORITHMS.contains(alg))
					|| (KeyType.OCT.equals(kty) && DirectEncrypter.SUPPORTED_ALGORITHMS.contains(alg))
					|| (KeyType.OKP.equals(kty) && X25519Encrypter.SUPPORTED_ALGORITHMS.contains(alg)))) {
				throw new IllegalArgumentException("Unsupported key encryption algorithm: " + alg);
			}
		}

		this.keys = keys;
	}


	/**
	 * Returns the {@link SecretKey} of the recipients with
	 * {@link JWEAlgorithm#DIR} if present.
	 *
	 * @param keys The public keys. Must not be {@code null}.
	 *
	 * @return The SecretKey.
	 */
	private static SecretKey findDirectCEK(final JWKSet keys) {
		if (keys != null) {
			for (JWK jwk : keys.getKeys()) {
				if (JWEAlgorithm.DIR.equals(jwk.getAlgorithm()) && KeyType.OCT.equals(jwk.getKeyType())) {
					return jwk.toOctetSequenceKey().toSecretKey("AES");
				}
			}
		}
		return null;
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

		if (aad == null) {
			throw new JOSEException("Missing JWE additional authenticated data (AAD)");
		}

		final EncryptionMethod enc = header.getEncryptionMethod();
		final SecretKey cek = getCEK(enc);

		JWECryptoParts jweParts;
		JWEEncrypter encrypter;
		JWEHeader recipientHeader = null;
		Base64URL encryptedKey = null;
		Base64URL cipherText = null;
		Base64URL iv = null;
		Base64URL tag = null;
		JWEAlgorithm alg;
		Payload payload = new Payload(clearText);
		List<Object> recipients = JSONArrayUtils.newJSONArray();

		for (JWK key : keys.getKeys()) {
			KeyType kty = key.getKeyType();

			// build JWEHeader from protected header and recipients public key parameters
			Map<String, Object> keyMap = key.toJSONObject();
			UnprotectedHeader.Builder unprotected = new UnprotectedHeader.Builder();
			for (String param : RECIPIENT_HEADER_PARAMS) {
				if (keyMap.containsKey(param)) {
					unprotected.param(param, keyMap.get(param));
				}
			}

			// create recipients JWEObject, select encrypter and encrypt the payload.
			try {
				recipientHeader = (JWEHeader) header.join(unprotected.build());
			} catch (Exception e) {
				throw new JOSEException(e.getMessage(), e);
			}
			alg = JWEHeaderValidation.getAlgorithmAndEnsureNotNull(recipientHeader);

			if (KeyType.RSA.equals(kty) && RSAEncrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
				encrypter = new RSAEncrypter(key.toRSAKey().toRSAPublicKey(), cek);
			} else if (KeyType.EC.equals(kty) && ECDHEncrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
				encrypter = new ECDHEncrypter(key.toECKey().toECPublicKey(), cek);
			} else if (KeyType.OCT.equals(kty) && AESEncrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
				encrypter = new AESEncrypter(key.toOctetSequenceKey().toSecretKey("AES"), cek);
			} else if (KeyType.OCT.equals(kty) && DirectEncrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
				encrypter = new DirectEncrypter(key.toOctetSequenceKey().toSecretKey("AES"));
			} else if (KeyType.OKP.equals(kty) && X25519Encrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
				encrypter = new X25519Encrypter(key.toOctetKeyPair().toPublicJWK(), cek);
			} else {
				continue;
			}
			jweParts = encrypter.encrypt(recipientHeader, payload.toBytes(), aad);

			// build recipients header object by removing protected header params from recipients JWEHeader
			Map<String, Object> recipientHeaderMap = jweParts.getHeader().toJSONObject();
			for (String param : header.getIncludedParams()) {
				recipientHeaderMap.remove(param);
			}
			Map<String, Object> recipient = JSONObjectUtils.newJSONObject();
			recipient.put("header", recipientHeaderMap);

			// do not put symmetric keys into JWE JSON object
			if (!JWEAlgorithm.DIR.equals(alg)) {
				recipient.put("encrypted_key", jweParts.getEncryptedKey().toString());
			}
			recipients.add(recipient);

			// update the iv, cipherText and tag parameters only after first round. Set payload to empty string.
			if (recipients.size() == 1) {
				payload = new Payload("");
				encryptedKey = jweParts.getEncryptedKey();
				iv = jweParts.getInitializationVector();
				cipherText = jweParts.getCipherText();
				tag = jweParts.getAuthenticationTag();
			}
		}
		if (recipients.size() > 1) {
			Map<String, Object> jweJsonObject = JSONObjectUtils.newJSONObject();
			jweJsonObject.put("recipients", recipients);
			encryptedKey = Base64URL.encode(JSONObjectUtils.toJSONString(jweJsonObject));
		}
		return new JWECryptoParts(header, encryptedKey, iv, cipherText, tag);
	}
}