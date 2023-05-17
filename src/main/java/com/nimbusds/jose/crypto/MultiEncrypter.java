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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.MultiCryptoProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Multirecipient encrypter of {@link com.nimbusds.jose.JWEObjectJSON JWE
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
 * @version 2023-03-26
 */
@ThreadSafe
public class MultiEncrypter extends MultiCryptoProvider implements JWEEncrypter {


	/**
	 * The JWK public keys.
	 */
	private final JWKSet keys;


	/**
	 * The parameters are common for JWK and JWEHeader.
	 */
	private final String[] recipientHeaderParams = {"kid", "alg", "x5u", "x5t", "x5t#S256", "x5c"};


	/**
	 * Creates a new multirecipient encrypter.
	 *
	 * @param keys                 The public keys. Must not be
	 *                             {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public MultiEncrypter(final JWKSet keys)
		throws KeyLengthException {

		this(keys, findDirectCek(keys));
	}


	/**
	 * Creates a new multirecipient encrypter.
	 *
	 * @param keys                 The public keys. Must not be
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
			throw new IllegalArgumentException("The public key set (JWKSet) must not be null");
		}
		for (JWK jwk : keys.getKeys()) {
			if ("dir".equals(String.valueOf(jwk.getAlgorithm()))
					&& KeyType.OCT.equals(jwk.getKeyType())
					&& !jwk.toOctetSequenceKey().toSecretKey("AES").equals(contentEncryptionKey)) {
				throw new IllegalArgumentException("Bad CEK");
			}
		}

		this.keys = keys;
	}


	/**
	 * Returns the list of parameters which are common for JWK and JWEHeader.
	 *
	 * @return The recipient header parameters.
	 */
	public String[] getRecipientHeaderParams() {
		return recipientHeaderParams;
	}


	/**
	 * Returns the SecrectKey of the recipients with JWEAlgorithm.DIR if present.
	 *
	 * @param keys                 The public keys. Must not be
	 *                             {@code null}.
	 * @return The SecretKey.
	 */
	private static SecretKey findDirectCek(final JWKSet keys) {
		if (keys != null) {
			for (JWK jwk : keys.getKeys()) {
				if ("dir".equals(String.valueOf(jwk.getAlgorithm())) && KeyType.OCT.equals(jwk.getKeyType())) {
					return jwk.toOctetSequenceKey().toSecretKey("AES");
				}
			}
		}
		return null;
	}


	/**
	 * Split the AAD string and return the first part as the header map. As
	 * described in the step 14 of the
	 * https://www.rfc-editor.org/rfc/rfc7516#section-5.1.
	 *
	 * @param aad       The additional authenticated data. Must not be
	 *                  {@code null}.
	 *
	 * @return The header map.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported or if encryption failed for some
	 *                       other internal reason.
	 */
	private static Map<String, Object> getHeaderMapFromAAD(final byte[] aad)
		throws JOSEException {
		try {
			String protectedHeader = new String(aad).split("\\.")[0];
			return JSONObjectUtils.parse(Base64URL.from(protectedHeader).decodeToString());
		} catch (Exception e) {
			throw new JOSEException(e.getMessage(), e);
		}
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
		final String aadStr = new String(aad, StandardCharsets.US_ASCII);
		final Map<String, Object> headerMap = getHeaderMapFromAAD(aad);
		final SecretKey cek = getCEK(enc);

		JWECryptoParts jweParts;
		JWEEncrypter encrypter;
		JWEHeader recipientHeader = null;
		Base64URL encryptedKey = null;
		Base64URL cipherText = null;
		Base64URL iv = null;
		Base64URL tag = null;
		JWEAlgorithm alg  = header.getAlgorithm();
		Payload payload = new Payload(clearText);
		List<Object> recipients = JSONArrayUtils.newJSONArray();

		for (JWK key : keys.getKeys()) {
			KeyType kty = key.getKeyType();

			// build JWEHeader from protected header and recipients public key parameters
			Map<String, Object> keyMap = key.toJSONObject();
			Map<String, Object> recipientHeaderMap = JSONObjectUtils.newJSONObject();
			for (String param : recipientHeaderParams) {
				if (keyMap.containsKey(param)) {
					recipientHeaderMap.put(param, keyMap.get(param));
				}
			}
			if (recipientHeaderMap.get("kid") == null) {
				recipientHeaderMap.put("kid", key.computeThumbprint().toString());
			}
			if (recipientHeaderMap.get("alg") == null) {
				recipientHeaderMap.put("alg", header.getAlgorithm().toString());
			}
			recipientHeaderMap.putAll(headerMap);

			// create recipients JWEObject, select encrypter and encrypt the payload.
			try {
				recipientHeader = JWEHeader.parse(recipientHeaderMap);
			} catch (Exception e) {
				throw new JOSEException(e.getMessage(), e);
			}
			alg = recipientHeader.getAlgorithm();
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
			recipientHeader = jweParts.getHeader();
			recipientHeaderMap = recipientHeader.toJSONObject();
			for (String param : headerMap.keySet()) {
				recipientHeaderMap.remove(param);
			}
			Map<String, Object> recipient = JSONObjectUtils.newJSONObject();
			recipient.put("header", recipientHeaderMap);

			// do not put symetric keys into JWE JEON object
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
		if (!headerMap.containsKey("alg")) {
			Map<String, Object> jweJsonObject = JSONObjectUtils.newJSONObject();
			jweJsonObject.put("recipients", recipients);
			encryptedKey = Base64URL.encode(JSONObjectUtils.toJSONString(jweJsonObject));
		}
		return new JWECryptoParts(recipientHeader, encryptedKey, iv, cipherText, tag);
	}
}