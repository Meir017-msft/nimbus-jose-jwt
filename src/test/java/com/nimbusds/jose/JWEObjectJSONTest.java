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

package com.nimbusds.jose;


import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import java.text.ParseException;
import java.util.*;
import java.util.logging.Logger;


/**
 * Tests JWE JSON object methods.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2023-05-17
 */
public class JWEObjectJSONTest extends TestCase {

	private static final Logger LOGGER = Logger.getLogger(JWEObjectJSONTest.class.getName());

	private static final String jweMultiRecipientJsonString =
		"{" +
			"\"ciphertext\":\"oxEERGR4AgFcRMKLgeU\"," +
			"\"protected\":\"eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0\"," +
			"\"recipients\":[" +
				"{" +
					"\"header\":{" +
						"\"kid\":\"DirRecipient\"," +
						"\"alg\":\"dir\"" +
					"}" +
				"},{" +
					"\"encrypted_key\":\"cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g\"," +
					"\"header\":{" +
						"\"kid\":\"AESRecipient\"," +
						"\"alg\":\"A128KW\"" +
					"}" +
				"}" +
			"]," +
			"\"tag\":\"lhNLaDMKVVvjlGaeYdqbrQ\"," +
			"\"iv\":\"BCNhlw39FueuKrwH\"" +
		"}";

	private static final String jweGeneralJsonString =
		"{" +
			"\"ciphertext\":\"oxEERGR4AgFcRMKLgeU\"," +
			"\"protected\":\"eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0\"," +
			"\"recipients\":[" +
				"{" +
					"\"encrypted_key\":\"cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g\"," +
					"\"header\":{" +
						"\"kid\":\"AESRecipient\"," +
						"\"alg\":\"A128KW\"" +
					"}" +
				"}" +
			"]," +
			"\"tag\":\"lhNLaDMKVVvjlGaeYdqbrQ\"," +
			"\"iv\":\"BCNhlw39FueuKrwH\"" +
		"}";

	private static final String jweFlattenedJsonString =
		"{" +
			"\"ciphertext\":\"oxEERGR4AgFcRMKLgeU\"," +
			"\"protected\":\"eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0\"," +
			"\"encrypted_key\":\"cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g\"," +
			"\"unprotected\":{" +
				"\"kid\":\"AESRecipient\"," +
				"\"alg\":\"A128KW\"" +
			"}," +
			"\"tag\":\"lhNLaDMKVVvjlGaeYdqbrQ\"," +
			"\"iv\":\"BCNhlw39FueuKrwH\"" +
		"}";

	public void testGeneralJSONParser_twoRecipients()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweMultiRecipientJsonString);

		assertNull(jwe.getPayload());

		assertEquals(JWEAlgorithm.DIR, jwe.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, jwe.getHeader().getCompressionAlgorithm());
		assertEquals("DirRecipient", jwe.getHeader().getKeyID());
		assertEquals(4, jwe.getHeader().toJSONObject().size());

		assertNull(jwe.getUnprotected());

		assertEquals(new Base64URL("BCNhlw39FueuKrwH"), jwe.getIV());

		assertEquals("eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0", new String(jwe.getAAD()));

		assertEquals(new Base64URL("oxEERGR4AgFcRMKLgeU"), jwe.getCipherText());

		assertEquals(new Base64URL("lhNLaDMKVVvjlGaeYdqbrQ"), jwe.getAuthTag());

		List<JWEObjectJSON.Recipient> recipients = jwe.getRecipients();

		assertEquals(JWEAlgorithm.DIR.getName(), recipients.get(0).getHeader().getParam("alg"));
		assertEquals("DirRecipient", recipients.get(0).getHeader().getKeyID());
		assertEquals(2, recipients.get(0).getHeader().toJSONObject().size());
		assertNull(recipients.get(0).getEncryptedKey());

		assertEquals(JWEAlgorithm.A128KW.getName(), recipients.get(1).getHeader().getParam("alg"));
		assertEquals("AESRecipient", recipients.get(1).getHeader().getKeyID());
		assertEquals(2, recipients.get(1).getHeader().toJSONObject().size());
		assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), recipients.get(1).getEncryptedKey());

		assertEquals(2, recipients.size());
	}

	public void testGeneralJSONParser_singleRecipient_flattened()
		throws Exception {

		for (String jweString: Arrays.asList(jweGeneralJsonString, jweFlattenedJsonString)) {

			JWEObjectJSON jwe = JWEObjectJSON.parse(jweString);

			assertNull(jwe.getPayload());

			assertEquals(JWEAlgorithm.A128KW, jwe.getHeader().getAlgorithm());
			assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
			assertEquals(CompressionAlgorithm.DEF, jwe.getHeader().getCompressionAlgorithm());
			assertEquals("AESRecipient", jwe.getHeader().getKeyID());
			assertEquals(4, jwe.getHeader().toJSONObject().size());

			assertNull(jwe.getUnprotected());

			assertEquals(new Base64URL("BCNhlw39FueuKrwH"), jwe.getIV());

			assertEquals("eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0", new String(jwe.getAAD()));

			assertEquals(new Base64URL("oxEERGR4AgFcRMKLgeU"), jwe.getCipherText());

			assertEquals(new Base64URL("lhNLaDMKVVvjlGaeYdqbrQ"), jwe.getAuthTag());

			List<JWEObjectJSON.Recipient> recipients = jwe.getRecipients();
			assertEquals(JWEAlgorithm.A128KW.getName(), recipients.get(0).getHeader().getParam("alg"));
			assertEquals("AESRecipient", recipients.get(0).getHeader().getKeyID());
			assertEquals(2, recipients.get(0).getHeader().toJSONObject().size());
			assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), recipients.get(0).getEncryptedKey());
			assertEquals(1, recipients.size());
		}
	}


	public void testGetEncryptedKeyMethod()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe;

		jwe = new JWEObjectJSON(header, new Payload("test!"));
		assertEquals(null, jwe.getEncryptedKey());

		jwe = JWEObjectJSON.parse(jweGeneralJsonString);
		assertEquals("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g", jwe.getEncryptedKey().toString());

		jwe = JWEObjectJSON.parse(jweFlattenedJsonString);
		assertEquals("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g", jwe.getEncryptedKey().toString());

		jwe = JWEObjectJSON.parse(jweMultiRecipientJsonString);

		assertEquals("eyJyZWNpcGllbnRzIjpbeyJoZWFkZXIiOnsiYWxnIjoiZGlyIiwia2l" +
			     "kIjoiRGlyUmVjaXBpZW50In19LHsiZW5jcnlwdGVkX2tleSI6ImNmRm" +
			     "YySHNLSU1NbHJvRGhoYlVkc1JvcHRPbnh0dUpLV0JwLW9BcVdEc1VDc" +
			     "XJ5R1lsNVItZyIsImhlYWRlciI6eyJhbGciOiJBMTI4S1ciLCJraWQi" +
			     "OiJBRVNSZWNpcGllbnQifX1dfQ", jwe.getEncryptedKey().toString());
	}


	public void testPartsConstructorIllegalArgumentExceptions() {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);

		try {
			new JWEObjectJSON(null, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The header must not be null", e.getMessage());
		}

		try {
			new JWEObjectJSON(header, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The cipher text must not be null", e.getMessage());
		}
	}


	public void testParseIllegalArgumentExceptions() throws ParseException {

		try {
			Map<String, Object> json = null;
			JWEObjectJSON.parse(json);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JSON object must not be null", e.getMessage());
		}

		try {
			String json = null;
			JWEObjectJSON.parse(json);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JSON object string must not be null", e.getMessage());
		}
	}


	public void testJWEObjectConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jweo = new JWEObject(
			firstPart,
			secondPart,
			thirdPart,
			fourthPart,
			fifthPart);

		JWEObjectJSON jwe = new JWEObjectJSON(jweo);

		assertEquals(JWEAlgorithm.RSA1_5, jwe.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jwe.getHeader().getEncryptionMethod());
		assertNull(jwe.getPayload());
		assertEquals(new Base64URL("abc"), jwe.getEncryptedKey());
		assertEquals(new Base64URL("def"), jwe.getIV());
		assertEquals(new Base64URL("ghi"), jwe.getCipherText());
		assertEquals(new Base64URL("jkl"), jwe.getAuthTag());

		assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
	}

	public void testFlattenedJSONSerializer()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweGeneralJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweFlattenedJsonString);

		assertEquals(rawJson.keySet(), jwe.toFlattenedJSONObject().keySet());
	}

	public void testGeneralJSONSerializer()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweFlattenedJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);

		assertEquals(rawJson.keySet(), jwe.toGeneralJSONObject().keySet());
	}

	public void testAADParsing()
		throws Exception {

		String aad = "BCNhlw39FueuKrwH";
		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);
		rawJson.put("aad", aad);

		JWEObjectJSON jwe = JWEObjectJSON.parse(rawJson);

		assertEquals(rawJson.get("protected").toString() + "." + aad, new String(jwe.getAAD()));
		assertEquals(aad, jwe.toFlattenedJSONObject().get("aad").toString());
	}

	public void testHeaderDuplicates()
		throws Exception {

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);

		rawJson.put("unprotected", JSONObjectUtils.parse("{\"kid\":\"AESRecipient\",\"alg\":\"A128KW\"}"));

		try {
			JWEObjectJSON.parse(rawJson);
			fail();
		} catch (ParseException e) {
			assertEquals("The parameters in the JWE protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}

	public void testRejectUnsupportedJWEAlgorithmOnEncrypt() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText, byte[] aad) {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(new JWEAlgorithm("xyz"));
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return null;
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The RSA1_5 algorithm is not supported by the JWE encrypter: Supported algorithms: [xyz]", e.getMessage());
		}
	}


	public void testRejectUnsupportedJWEMethodOnEncrypt() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText, byte[] aad) {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(JWEAlgorithm.RSA1_5);
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return Collections.singleton(new EncryptionMethod("xyz"));
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The A128CBC-HS256 encryption method or key size is not supported by the JWE encrypter: Supported methods: [xyz]", e.getMessage());
		}
	}
}