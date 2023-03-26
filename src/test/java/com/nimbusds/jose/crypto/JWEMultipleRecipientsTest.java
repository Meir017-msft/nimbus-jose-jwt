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
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;


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


	public void testMultipleRecipients()
		throws Exception {

		final String plainText = "Hello world!";
		final EncryptionMethod enc = EncryptionMethod.A256GCM;
		final JWKSet keys = generateJWKSet(enc);
		final SecretKey cek = keys.getKeyByKeyId("DirRecipient").toOctetSequenceKey().toSecretKey("AES");

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, enc)
						.compressionAlgorithm(CompressionAlgorithm.DEF)
						.build();
		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload(plainText));
		JWEEncrypter encrypter = new MultiEncrypter(keys, cek);

		jwe.encrypt(encrypter);
		String json = jwe.serializeGeneral();

		LOGGER.info("JWE JSON Object: " + json);

		for (JWK key : keys.getKeys()) {
			jwe = JWEObjectJSON.parse(json);
			jwe.decrypt(new MultiDecrypter(key));
			assertEquals(plainText, jwe.getPayload().toString());
		}
	}
}
