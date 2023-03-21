/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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


import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Tests Multiple Recipients encryption and decryption.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2023-03-21
 */
public class JWEMultipleRecipientsTest extends TestCase {

	private static final Logger LOGGER = Logger.getLogger(JWEMultipleRecipientsTest.class.getName());

	private static JWKSet generateJWKSet()
		throws Exception {

		List<JWK> keys = new ArrayList<>();

		keys.add(new ECKeyGenerator(Curve.P_256)
			.keyID("ECRecipient")
			.algorithm(JWEAlgorithm.ECDH_ES_A128KW)
			.generate());

		keys.add(new RSAKeyGenerator(2048)
			.keyID("RSARecipient")
			.algorithm(JWEAlgorithm.RSA_OAEP_256)
			.generate());
		
		return new JWKSet(keys);
	}

	private static SecretKey generateCEK(final int keySize)
		throws Exception {

		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(keySize);
		return generator.generateKey();
	}

	private static Map<String, Object> encrypt(final String plainText, final JWKSet keys)
		throws Exception {

		final EncryptionMethod enc = EncryptionMethod.A256GCM;
		final SecretKey cek = generateCEK(enc.cekBitLength());

		JWEObject jweo;
		JWEEncrypter encrypter;
		Map<String, Object> jweJsonObject = JSONObjectUtils.newJSONObject();
		JWEAlgorithm alg  = JWEAlgorithm.RSA_OAEP_256;
		Payload payload = new Payload(plainText);
		JWEHeader header = new JWEHeader.Builder(alg, enc).
						compressionAlgorithm(CompressionAlgorithm.DEF).
						build();
		Map<String, Object> aadMap = header.toJSONObject();
		aadMap.remove("alg");
		jweJsonObject.put("protected", Base64URL.encode(JSONObjectUtils.toJSONString(aadMap)).toString());
		final byte[] aad = jweJsonObject.get("protected").toString().getBytes();
		List<Object> recipients = JSONArrayUtils.newJSONArray();
		for (JWK key : keys.getKeys()) {
			String kid = key.getKeyID();
			alg = JWEAlgorithm.parse(key.getAlgorithm().toString());
			header = new JWEHeader.Builder(alg, enc)
				.compressionAlgorithm(CompressionAlgorithm.DEF)
				.keyID(kid)
				.build();
			jweo = new JWEObject(header, payload);
			if (RSAEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
				encrypter = new RSAEncrypter(key.toRSAKey().toRSAPublicKey(), cek, aad);
			} else if (ECDHEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
				encrypter = new ECDHEncrypter(key.toECKey().toECPublicKey(), cek, aad);
			} else {
				continue;
			}
			jweo.encrypt(encrypter);
			Map<String, Object> recipientsHeader = jweo.getHeader().toJSONObject();
			recipientsHeader.remove("enc");
			recipientsHeader.remove("zip");
			Map<String, Object> recipient = JSONObjectUtils.newJSONObject();
			recipient.put("header", recipientsHeader);
			recipient.put("encrypted_key", jweo.getEncryptedKey().toString());
			recipients.add(recipient);
			if (!jweJsonObject.containsKey("ciphertext")) {
				payload = new Payload("");
				jweJsonObject.put("iv", jweo.getIV().toString());
				jweJsonObject.put("ciphertext", jweo.getCipherText().toString());
				jweJsonObject.put("tag", jweo.getAuthTag().toString());
			}
		}
		jweJsonObject.put("recipients", recipients);
		return jweJsonObject;
	}
	
	
	private static Object getOrDefault(final Map<String, Object> jweJsonObject, final String key, final Object defaultValue) {
		
		Object value = jweJsonObject.get(key);
		
		return value != null ? value : defaultValue;
	}


	private static String decrypt(final Map<String, Object> jweJsonObject, final JWK key)
		throws Exception {

		final JWEAlgorithm alg = JWEAlgorithm.parse(key.getAlgorithm().toString());
		final String protectedHeader = getOrDefault(jweJsonObject, "protected", "e30").toString();
		final byte[] aad = protectedHeader.getBytes();
		final String kid = key.getKeyID();
		Map<String, Object> headerMap = JSONObjectUtils.parse(Base64URL.from(protectedHeader).decodeToString());
		String encryptedKey = getOrDefault(jweJsonObject, "encrypted_key", "").toString();
		List<Map<String, Object>> recipients = (List<Map<String, Object>>) jweJsonObject.get("recipients");
		for (Map<String, Object> recipient : recipients) {
			Map<String, Object> recipientHeader = (Map<String, Object>) recipient.get("header");
			if (kid.equals(recipientHeader.get("kid").toString())) {
				encryptedKey = recipient.get("encrypted_key").toString();
				headerMap.putAll(recipientHeader);
				break;
			}
		}
		JWEObject jweo = new JWEObject( Base64URL.encode(JSONObjectUtils.toJSONString(headerMap)),
						Base64URL.from(encryptedKey),
						Base64URL.from((String) jweJsonObject.get("iv")),
						Base64URL.from((String) jweJsonObject.get("ciphertext")),
						Base64URL.from((String) jweJsonObject.get("tag")));
		if (RSADecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			jweo.decrypt(new RSADecrypter(key.toRSAKey().toRSAPrivateKey(), null, false, aad));
		} else if (ECDHDecrypter.SUPPORTED_ALGORITHMS.contains(alg)) {
			jweo.decrypt(new ECDHDecrypter(key.toECKey().toECPrivateKey(), null, aad));
		}
		return jweo.getPayload().toString();
	}

	public void testMultipleRecipients()
		throws Exception {

		final String plainText = "Hello world!";

		final JWKSet keys = generateJWKSet();
		Map<String, Object> jweJsonObject = encrypt(plainText, keys);

		LOGGER.info("JWE JSON Object: " + JSONObjectUtils.toJSONString(jweJsonObject));

		assertEquals(plainText, decrypt(jweJsonObject, keys.getKeyByKeyId("ECRecipient")));
		assertEquals(plainText, decrypt(jweJsonObject, keys.getKeyByKeyId("RSARecipient")));
	}
}
