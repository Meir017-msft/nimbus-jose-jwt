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


import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.logging.Logger;


/**
 * Tests Multiple Recipients encryption and decryption.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2023-03-26
 */
public class JWEMultipleRecipientsTest extends TestCase {

	private static final Logger LOGGER = Logger.getLogger(JWEMultipleRecipientsTest.class.getName());

	private static JWKSet generateJWKSet(final EncryptionMethod enc)
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

		keys.add(new OctetKeyPairGenerator(Curve.X25519)
			.keyID("X25519Recipient")
			.algorithm(JWEAlgorithm.ECDH_ES_A128KW)
			.generate());

		keys.add(new OctetSequenceKeyGenerator(128)
			.keyID("AESRecipient")
			.algorithm(JWEAlgorithm.A128KW)
			.generate());

		keys.add(new OctetSequenceKeyGenerator(enc.cekBitLength())
			.keyID("DirRecipient")
			.algorithm(JWEAlgorithm.DIR)
			.generate());

		return new JWKSet(keys);
	}


	public void testEncrypterParameters()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		final JWKSet keys = generateJWKSet(EncryptionMethod.A256GCM);

		JWEEncrypter encrypter = new MultiEncrypter(keys);

		try {
			encrypter.encrypt(header, null, null);
			fail();
		} catch (Exception e) {
			assertEquals("Missing JWE additional authenticated data (AAD)", e.getMessage());
		}
	}


	public void testDecryptParameters()
		throws Exception {

		final Base64URL value = Base64URL.encode("12345");
		final byte[] aad = "12345".getBytes();
		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		final JWK key = new OctetSequenceKeyGenerator(EncryptionMethod.A256GCM.cekBitLength())
			.keyID("DirRecipient")
			.algorithm(JWEAlgorithm.DIR)
			.generate();

		JWEDecrypter decrypter = new MultiDecrypter(key);

		try {
			decrypter.decrypt(header, null, null, value, value, aad);
			fail();
		} catch (Exception e) {
			assertEquals("Unexpected present JWE initialization vector (IV)", e.getMessage());
		}

		try {
			decrypter.decrypt(header, null, value, value, null, aad);
			fail();
		} catch (Exception e) {
			assertEquals("Missing JWE authentication tag", e.getMessage());
		}

		try {
			decrypter.decrypt(header, null, value, value, value, null);
			fail();
		} catch (Exception e) {
			assertEquals("Missing JWE additional authenticated data (AAD)", e.getMessage());
		}

		try {
			decrypter.decrypt(new JWEHeader(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A256GCM), null, value, value, value, aad);
			fail();
		} catch (Exception e) {
			assertEquals("Unsupported algorithm", e.getMessage());
		}

		try {
			decrypter = new MultiDecrypter(null);
			fail();
		} catch (Exception e) {
			assertEquals("The private key (JWK) must not be null", e.getMessage());
		}
	}


	public void testMultipleRecipients()
		throws Exception {

		final String plainText = "Hello world!";
		final EncryptionMethod enc = EncryptionMethod.A256GCM;
		final JWKSet keys = generateJWKSet(enc);
		final Set recipientHeader = new HashSet<>(Arrays.asList("alg", "kid"));
		final Set ecRecipientHeader = new HashSet<>(Arrays.asList("epk", "alg", "kid"));

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, enc)
						.compressionAlgorithm(CompressionAlgorithm.DEF)
						.build();
		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload(plainText));
		JWEEncrypter encrypter = new MultiEncrypter(keys);

		jwe.encrypt(encrypter);
		String json = jwe.serializeGeneral();

		LOGGER.fine("JWE JSON Object: " + json);

		Map<String, Object> jsonJWEObject = JSONObjectUtils.parse(json);
		Map<String, Object>[] recipients = JSONObjectUtils.getJSONObjectArray(jsonJWEObject, "recipients");
		assertEquals(keys.size(), recipients.length);
		LOGGER.info("Number of recipients: " + recipients.length);

		assertEquals(new HashSet<>(Arrays.asList("zip", "enc")), JSONObjectUtils.parse(JSONObjectUtils.getBase64URL(jsonJWEObject, "protected").decodeToString()).keySet());

		assertEquals("ECRecipient", ((Map<String, String>) recipients[0].get("header")).get("kid"));
		assertEquals(ecRecipientHeader, ((Map<String, Object>) recipients[0].get("header")).keySet());
		assertEquals(true, recipients[0].containsKey("encrypted_key"));

		assertEquals("RSARecipient", ((Map<String, String>) recipients[1].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[1].get("header")).keySet());
		assertEquals(true, recipients[1].containsKey("encrypted_key"));

		assertEquals("X25519Recipient", ((Map<String, String>) recipients[2].get("header")).get("kid"));
		assertEquals(ecRecipientHeader, ((Map<String, Object>) recipients[2].get("header")).keySet());
		assertEquals(true, recipients[2].containsKey("encrypted_key"));

		assertEquals("AESRecipient", ((Map<String, String>) recipients[3].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[3].get("header")).keySet());
		assertEquals(true, recipients[3].containsKey("encrypted_key"));

		assertEquals("DirRecipient", ((Map<String, String>) recipients[4].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[4].get("header")).keySet());
		assertEquals(false, recipients[4].containsKey("encrypted_key"));

		for (JWK key : keys.getKeys()) {
			jwe = JWEObjectJSON.parse(json);
			jwe.decrypt(new MultiDecrypter(key));
			assertEquals(plainText, jwe.getPayload().toString());
		}

		try {
			encrypter = new MultiEncrypter(null, null);
			fail();
		} catch (Exception e) {
			assertEquals("The public key set (JWKSet) must not be null", e.getMessage());
		}

		try {
			SecretKey cek = new OctetSequenceKeyGenerator(enc.cekBitLength()).generate().toOctetSequenceKey().toSecretKey("AES");
			encrypter = new MultiEncrypter(keys, cek);
			fail();
		} catch (Exception e) {
			assertEquals("Bad CEK", e.getMessage());
		}
	}
}
