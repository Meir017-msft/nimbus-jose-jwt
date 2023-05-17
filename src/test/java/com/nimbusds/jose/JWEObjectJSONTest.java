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

import java.util.Collections;
import java.util.Map;
import java.util.Set;
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
						"\"alg\":\"DIR\"" +
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

	public void testGeneralJSONParser()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweGeneralJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);

		assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
		assertEquals(JWEAlgorithm.A128KW, jwe.getHeader().getAlgorithm());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "protected").toString(), new String(jwe.getAAD()));
		assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), jwe.getEncryptedKey());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "iv"), jwe.getIV());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "ciphertext"), jwe.getCipherText());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "tag"), jwe.getAuthTag());
	}

	public void testFlattenedJSONParser()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweFlattenedJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweFlattenedJsonString);

		assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
		assertEquals(JWEAlgorithm.A128KW, jwe.getHeader().getAlgorithm());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "protected").toString(), new String(jwe.getAAD()));
		assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), jwe.getEncryptedKey());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "iv"), jwe.getIV());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "ciphertext"), jwe.getCipherText());
		assertEquals(JSONObjectUtils.getBase64URL(rawJson, "tag"), jwe.getAuthTag());
	}


	public void testGetEncryptedKeyMethod()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5,
			                         EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe;

		jwe = new JWEObjectJSON(header, new Payload("test!"));
		assertEquals(null, jwe.getEncryptedKey());

		jwe = JWEObjectJSON.parse(jweGeneralJsonString);
		assertEquals("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g", jwe.getEncryptedKey().toString());

		jwe = JWEObjectJSON.parse(jweFlattenedJsonString);
		assertEquals("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g", jwe.getEncryptedKey().toString());

		jwe = JWEObjectJSON.parse(jweMultiRecipientJsonString);
		assertEquals("eyJyZWNpcGllbnRzIjpbeyJoZWFkZXIiOnsiYWxnIjoiRElSIiwia2" +
			     "lkIjoiRGlyUmVjaXBpZW50In19LHsiZW5jcnlwdGVkX2tleSI6ImNm" +
			     "RmYySHNLSU1NbHJvRGhoYlVkc1JvcHRPbnh0dUpLV0JwLW9BcVdEc1" +
			     "VDcXJ5R1lsNVItZyIsImhlYWRlciI6eyJhbGciOiJBMTI4S1ciLCJr" +
			     "aWQiOiJBRVNSZWNpcGllbnQifX1dfQ", jwe.getEncryptedKey().toString());
	}


	public void testJWEObjectJSONConstructor()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5,
			                         EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe;

		try {
			jwe = new JWEObjectJSON(null, null, null, null, null, null, null);
			fail();
		} catch (Exception e) {
			assertEquals("The header must not be null", e.getMessage());
		}

		try {
			jwe = new JWEObjectJSON(header, null, null, null, null, null, null);
			fail();
		} catch (Exception e) {
			assertEquals("The cipher text must not be null", e.getMessage());
		}

		try {
			Map<String, Object> json = null;
			jwe = JWEObjectJSON.parse(json);
			fail();
		} catch (Exception e) {
			assertEquals("The JSON object must not be null", e.getMessage());
		}

		try {
			String json = null;
			jwe = JWEObjectJSON.parse(json);
			fail();
		} catch (Exception e) {
			assertEquals("The JSON object string must not be null", e.getMessage());
		}
	}


	public void testJWEObjectConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5,
			                         EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jweo = new JWEObject(firstPart, secondPart,
				thirdPart, fourthPart,
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
			JWEObjectJSON jwe = JWEObjectJSON.parse(rawJson);
			fail();
		} catch (Exception e) {
			assertEquals("The parameters in the JWE protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}

	public void testRejectUnsupportedJWEAlgorithmOnEncrypt() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText, byte[] aad) throws JOSEException {
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
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText, byte[] aad) throws JOSEException {
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