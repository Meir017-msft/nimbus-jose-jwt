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


import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.Test;

import java.net.URI;
import java.text.ParseException;
import java.util.*;

import static org.junit.Assert.*;


/**
 * Tests JWE JSON object methods.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2024-02-06
 */
public class JWEObjectJSONTest {

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


	@Test
	public void testGeneralJSONParser_twoRecipients()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweMultiRecipientJsonString);

		assertNull(jwe.getPayload());

		assertNull(jwe.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, jwe.getHeader().getCompressionAlgorithm());
		assertEquals(2, jwe.getHeader().toJSONObject().size());

		assertNull(jwe.getUnprotectedHeader());

		assertEquals(new Base64URL("BCNhlw39FueuKrwH"), jwe.getIV());

		assertEquals("eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0", new String(jwe.getAAD()));

		assertEquals(new Base64URL("oxEERGR4AgFcRMKLgeU"), jwe.getCipherText());

		assertEquals(new Base64URL("lhNLaDMKVVvjlGaeYdqbrQ"), jwe.getAuthTag());

		List<JWEObjectJSON.Recipient> recipients = jwe.getRecipients();

		assertEquals(JWEAlgorithm.DIR.getName(), recipients.get(0).getUnprotectedHeader().getParam("alg"));
		assertEquals("DirRecipient", recipients.get(0).getUnprotectedHeader().getKeyID());
		assertEquals(2, recipients.get(0).getUnprotectedHeader().toJSONObject().size());
		assertNull(recipients.get(0).getEncryptedKey());

		assertEquals(JWEAlgorithm.A128KW.getName(), recipients.get(1).getUnprotectedHeader().getParam("alg"));
		assertEquals("AESRecipient", recipients.get(1).getUnprotectedHeader().getKeyID());
		assertEquals(2, recipients.get(1).getUnprotectedHeader().toJSONObject().size());
		assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), recipients.get(1).getEncryptedKey());

		assertEquals(2, recipients.size());
	}


	@Test
	public void testGeneralJSONParser_singleRecipient_flattened()
		throws Exception {

		for (String jweString: Arrays.asList(jweGeneralJsonString, jweFlattenedJsonString)) {

			JWEObjectJSON jwe = JWEObjectJSON.parse(jweString);

			assertNull(jwe.getPayload());

			assertNull(jwe.getHeader().getAlgorithm());
			assertEquals(EncryptionMethod.A256GCM, jwe.getHeader().getEncryptionMethod());
			assertEquals(CompressionAlgorithm.DEF, jwe.getHeader().getCompressionAlgorithm());
			assertEquals(2, jwe.getHeader().toJSONObject().size());

			assertEquals(new Base64URL("BCNhlw39FueuKrwH"), jwe.getIV());

			assertEquals("eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0", new String(jwe.getAAD()));

			assertEquals(new Base64URL("oxEERGR4AgFcRMKLgeU"), jwe.getCipherText());

			assertEquals(new Base64URL("lhNLaDMKVVvjlGaeYdqbrQ"), jwe.getAuthTag());

			UnprotectedHeader unprotected = jwe.getUnprotectedHeader();
			List<JWEObjectJSON.Recipient> recipients = jwe.getRecipients();
			assertEquals(1, recipients.size());
			assertEquals(new Base64URL("cfFf2HsKIMMlroDhhbUdsRoptOnxtuJKWBp-oAqWDsUCqryGYl5R-g"), recipients.get(0).getEncryptedKey());
			if (unprotected == null) {
				assertEquals(JWEAlgorithm.A128KW.getName(), recipients.get(0).getUnprotectedHeader().getParam("alg"));
				assertEquals("AESRecipient", recipients.get(0).getUnprotectedHeader().getKeyID());
				assertEquals(2, recipients.get(0).getUnprotectedHeader().toJSONObject().size());
			} else {
				assertEquals(JWEAlgorithm.A128KW.getName(), unprotected.getParam("alg"));
				assertEquals("AESRecipient", unprotected.getKeyID());
				assertEquals(2, unprotected.toJSONObject().size());
			}
		}
	}


	@Test
	public void testGetEncryptedKeyMethod()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObjectJSON jwe;

		jwe = new JWEObjectJSON(header, new Payload("test!"));
                assertNull(jwe.getEncryptedKey());

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


	@Test
	public void testPayloadConstructorIllegalArgumentExceptions() {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		final Payload payload = new Payload("Hello, world!");

		try {
			new JWEObjectJSON(null, payload);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWE protected header must not be null", e.getMessage());
		}

		try {
			new JWEObjectJSON(header, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The payload must not be null", e.getMessage());
		}
	}


	@Test
	public void testPartsConstructorIllegalArgumentExceptions() {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);

		try {
			new JWEObjectJSON(null, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWE protected header must not be null", e.getMessage());
		}

		try {
			new JWEObjectJSON(header, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The cipher text must not be null", e.getMessage());
		}
	}


	@Test
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


	@Test
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


	@Test
	public void testFlattenedJSONSerializer()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweGeneralJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweFlattenedJsonString);

		assertEquals(rawJson.keySet(), jwe.toFlattenedJSONObject().keySet());
	}


	@Test
	public void testGeneralJSONSerializer()
		throws Exception {

		JWEObjectJSON jwe = JWEObjectJSON.parse(jweFlattenedJsonString);
		assertNull(jwe.getPayload());

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);
		rawJson.put("unprotected", "");

		assertEquals(rawJson.keySet(), jwe.toGeneralJSONObject().keySet());
	}


	@Test
	public void testAADParsing()
		throws Exception {

		String aad = "BCNhlw39FueuKrwH";
		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);
		rawJson.put("aad", aad);

		JWEObjectJSON jwe = JWEObjectJSON.parse(rawJson);

		assertEquals(rawJson.get("protected").toString() + "." + aad, new String(jwe.getAAD()));
		assertEquals(aad, jwe.toFlattenedJSONObject().get("aad").toString());
	}


	@Test
	public void testHeaderDuplicates()
		throws Exception {

		Map<String, Object> rawJson = JSONObjectUtils.parse(jweGeneralJsonString);

		rawJson.put("unprotected", JSONObjectUtils.parse("{\"kid\":\"AESRecipient\",\"alg\":\"A128KW\"}"));

		try {
			JWEObjectJSON.parse(rawJson);
			fail();
		} catch (ParseException e) {
			assertEquals("The parameters in the protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}


	@Test
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


	@Test
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


	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4.7
	@Test
	public void testParseExample_RFC7516_A_4_7()
		throws ParseException {

		String json =
			"{" +
			" \"protected\":" +
			"  \"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\"," +
			" \"unprotected\":" +
			"  {\"jku\":\"https://server.example.com/keys.jwks\"}," +
			" \"recipients\":[" +
			"  {\"header\":" +
			"    {\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"}," +
			"   \"encrypted_key\":" +
			"    \"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-" +
			"kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx" +
			"GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3" +
			"YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh" +
			"cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg" +
			"wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A\"}," +
			"  {\"header\":" +
			"    {\"alg\":\"A128KW\",\"kid\":\"7\"}," +
			"   \"encrypted_key\":" +
			"    \"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"}]," +
			" \"iv\":" +
			"  \"AxY8DCtDaGlsbGljb3RoZQ\"," +
			" \"ciphertext\":" +
			"  \"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\"," +
			" \"tag\":" +
			"  \"Mz-VPPyU4RlcuYv1IwIvzw\"" +
			"}";

		JWEObjectJSON jweo = JWEObjectJSON.parse(json);

		JWEHeader protectedHeader = jweo.getHeader();
		assertEquals(EncryptionMethod.A128CBC_HS256, protectedHeader.getEncryptionMethod());
		assertEquals(1, protectedHeader.toJSONObject().size());

		UnprotectedHeader unprotectedHeader = jweo.getUnprotectedHeader();
		assertEquals(URI.create("https://server.example.com/keys.jwks").toString(), unprotectedHeader.getParam("jku"));
		assertEquals(1, unprotectedHeader.toJSONObject().size());

		List<JWEObjectJSON.Recipient> recipients = jweo.getRecipients();
		assertEquals(2, recipients.size());
		
		JWEObjectJSON.Recipient recipient_1 = recipients.get(0);
		UnprotectedHeader unprotectedHeader_1 = recipient_1.getUnprotectedHeader();
		assertEquals(JWEAlgorithm.RSA1_5.getName(), unprotectedHeader_1.getParam("alg"));
		assertEquals("2011-04-29", unprotectedHeader_1.getParam("kid"));
		assertEquals(2, unprotectedHeader_1.toJSONObject().size());
		Base64URL encryptedKey_1 = recipient_1.getEncryptedKey();
		assertEquals(
			new Base64URL("UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-" +
			"kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx" +
			"GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3" +
			"YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh" +
			"cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg" +
			"wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"),
			encryptedKey_1
		);

		JWEObjectJSON.Recipient recipient_2 = recipients.get(1);
		UnprotectedHeader unprotectedHeader_2 = recipient_2.getUnprotectedHeader();
		assertEquals(JWEAlgorithm.A128KW.getName(), unprotectedHeader_2.getParam("alg"));
		assertEquals("7", unprotectedHeader_2.getParam("kid"));
		assertEquals(2, unprotectedHeader_2.toJSONObject().size());
		Base64URL encryptedKey_2 = recipient_2.getEncryptedKey();
		assertEquals(
			new Base64URL("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"),
			encryptedKey_2
		);

		Base64URL iv = jweo.getIV();
		assertEquals(new Base64URL("AxY8DCtDaGlsbGljb3RoZQ"), iv);

		Base64URL cipherText = jweo.getCipherText();
		assertEquals(new Base64URL("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"), cipherText);

		Base64URL authTag = jweo.getAuthTag();
		assertEquals(new Base64URL("Mz-VPPyU4RlcuYv1IwIvzw"), authTag);
	}


	@Test(expected = NullPointerException.class)
	public void testParseRecipient_null()
		throws ParseException {

		JWEObjectJSON.Recipient.parse(null);
	}


	@Test
	public void testConstructor_jweObject_stateUnencrypted() {

		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
			new Payload("Hello, world")
		);

		assertEquals(JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEObjectJSON jweo = new JWEObjectJSON(jweObject);
		assertEquals(JWEObject.State.UNENCRYPTED, jweo.getState());

		assertEquals(0, jweo.getRecipients().size());

		try {
			jweo.toFlattenedJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The JWE object must be in an encrypted or decrypted state", e.getMessage());
		}
	}


	@Test
	public void testConstructor_jweObject_stateEncrypted()
		throws JOSEException {

		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
			new Payload("Hello, world")
		);

		RSAKey rsaKey = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();

		jweObject.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

		assertEquals(JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEObjectJSON jweo = new JWEObjectJSON(jweObject);
		assertEquals(JWEObject.State.ENCRYPTED, jweo.getState());

		assertEquals(1, jweo.getRecipients().size());

		List<JWEObjectJSON.Recipient> recipients = jweo.getRecipients();
		JWEObjectJSON.Recipient recipient = recipients.get(0);
		assertEquals(jweObject.getEncryptedKey(), recipient.getEncryptedKey());
		assertNull(recipient.getUnprotectedHeader());

		jweo.toFlattenedJSONObject();
	}


	@Test
	public void testConstructor_jweObject_stateDecrypted()
		throws JOSEException {

		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
			new Payload("Hello, world")
		);

		RSAKey rsaKey = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();

		jweObject.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

		assertEquals(JWEObject.State.ENCRYPTED, jweObject.getState());

		jweObject.decrypt(new RSADecrypter(rsaKey));

		JWEObjectJSON jweo = new JWEObjectJSON(jweObject);
		assertEquals(JWEObject.State.DECRYPTED, jweo.getState());

		assertEquals(1, jweo.getRecipients().size());

		List<JWEObjectJSON.Recipient> recipients = jweo.getRecipients();
		JWEObjectJSON.Recipient recipient = recipients.get(0);
		assertEquals(jweObject.getEncryptedKey(), recipient.getEncryptedKey());
		assertNull(recipient.getUnprotectedHeader());

		jweo.toFlattenedJSONObject();
	}
}