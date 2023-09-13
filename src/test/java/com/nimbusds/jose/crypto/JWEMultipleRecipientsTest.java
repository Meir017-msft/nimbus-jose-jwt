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
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import java.net.URI;
import java.text.ParseException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Tests Multiple Recipients encryption and decryption.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2023-09-13
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


	private static JWK extendJWK(final JWK jwk, final String paramName, final Object paramValue)
		throws Exception {
		Map<String, Object> jwkJson = jwk.toJSONObject();
		jwkJson.put(paramName, paramValue);
		return JWK.parse(jwkJson);
	}


	public void testEncrypterParameters()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		final JWKSet keys = generateJWKSet(EncryptionMethod.A256GCM);

		JWEEncrypter encrypter = new MultiEncrypter(keys);

		try {
			encrypter.encrypt(header, null, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing JWE additional authenticated data (AAD)", e.getMessage());
		}
	}


	public void testDecrypterParameters()
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
		} catch (JOSEException e) {
			assertEquals("Unexpected present JWE initialization vector (IV)", e.getMessage());
		}

		try {
			decrypter.decrypt(header, null, value, value, null, aad);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing JWE authentication tag", e.getMessage());
		}

		try {
			decrypter.decrypt(header, null, value, value, value, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing JWE additional authenticated data (AAD)", e.getMessage());
		}

		try {
			decrypter.decrypt(new JWEHeader(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A256GCM), null, value, value, value, aad);
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported algorithm", e.getMessage());
		}
	}


	public void testDecrypter_nullPrivateKey()
		throws JOSEException {

		try {
			new MultiDecrypter(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The private key (JWK) must not be null", e.getMessage());
		}
	}


	public void testMultipleRecipients()
		throws Exception {

		final String plainText = "Hello world!";
		final EncryptionMethod enc = EncryptionMethod.A256GCM;
		final JWKSet keys = generateJWKSet(enc);
		final Set<String> recipientHeader = new HashSet<>(Arrays.asList("alg", "kid"));
		final Set<String> ecRecipientHeader = new HashSet<>(Arrays.asList("epk", "alg", "kid"));

		JWEHeader header = new JWEHeader.Builder(enc)
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
		assertTrue(recipients[0].containsKey("encrypted_key"));

		assertEquals("RSARecipient", ((Map<String, String>) recipients[1].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[1].get("header")).keySet());
		assertTrue(recipients[1].containsKey("encrypted_key"));

		assertEquals("X25519Recipient", ((Map<String, String>) recipients[2].get("header")).get("kid"));
		assertEquals(ecRecipientHeader, ((Map<String, Object>) recipients[2].get("header")).keySet());
		assertTrue(recipients[2].containsKey("encrypted_key"));

		assertEquals("AESRecipient", ((Map<String, String>) recipients[3].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[3].get("header")).keySet());
		assertTrue(recipients[3].containsKey("encrypted_key"));

		assertEquals("DirRecipient", ((Map<String, String>) recipients[4].get("header")).get("kid"));
		assertEquals(recipientHeader, ((Map<String, Object>) recipients[4].get("header")).keySet());
		assertFalse(recipients[4].containsKey("encrypted_key"));

		for (JWK key : keys.getKeys()) {
			jwe = JWEObjectJSON.parse(json);
			jwe.decrypt(new MultiDecrypter(key));
			assertEquals(plainText, jwe.getPayload().toString());
		}
	}


	public void testTwoRecipients_identicalJWEAlg_noJWKAlg()
		throws JOSEException {

		RSAKeyGenerator keyGenerator = new RSAKeyGenerator(2048);
		final JWKSet keys = new JWKSet(Arrays.asList(
			(JWK)keyGenerator.keyID("1").generate(),
			(JWK)keyGenerator.keyID("2").generate())
		);

		try {
			new MultiEncrypter(keys);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Each JWK must specify a key encryption algorithm", e.getMessage());
		}
	}


	public void testTwoRecipients_identicalJWEAlg_noKeyID()
		throws JOSEException, ParseException {

		final String plainText = "Hello world!";
		final EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;
		RSAKeyGenerator keyGenerator = new RSAKeyGenerator(2048);
		final JWKSet keys = new JWKSet(Arrays.asList(
			(JWK)keyGenerator.algorithm(JWEAlgorithm.RSA_OAEP_256).generate(),
			(JWK)keyGenerator.algorithm(JWEAlgorithm.RSA_OAEP_256).generate())
		);

		JWEHeader header = new JWEHeader(enc);

		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload(plainText));
		JWEEncrypter encrypter = new MultiEncrypter(keys);

		jwe.encrypt(encrypter);
		String json = jwe.serializeGeneral();

		LOGGER.fine("JWE JSON Object: " + json);

		Map<String, Object> jsonJWEObject = JSONObjectUtils.parse(json);
		Map<String, Object>[] recipients = JSONObjectUtils.getJSONObjectArray(jsonJWEObject, "recipients");
		assertEquals(keys.size(), recipients.length);

		assertEquals(Collections.singleton("enc"), JSONObjectUtils.parse(JSONObjectUtils.getBase64URL(jsonJWEObject, "protected").decodeToString()).keySet());

		assertEquals(JWEAlgorithm.RSA_OAEP_256.getName(), ((Map<String, Object>) recipients[0].get("header")).get("alg"));
		assertEquals(1, ((Map<String, Object>) recipients[0].get("header")).size());
		assertTrue(recipients[0].containsKey("encrypted_key"));

		assertEquals(JWEAlgorithm.RSA_OAEP_256.getName(), ((Map<String, Object>) recipients[1].get("header")).get("alg"));
		assertEquals(1, ((Map<String, Object>) recipients[1].get("header")).size());
		assertTrue(recipients[1].containsKey("encrypted_key"));

		for (JWK key : keys.getKeys()) {
			jwe = JWEObjectJSON.parse(json);
			try {
				jwe.decrypt(new MultiDecrypter(key));
				fail();
			} catch (JOSEException e) {
				assertEquals("No recipient found", e.getMessage());
			}
		}
	}


	public void testRecipients_identicalJWEAlg_recipientMatch()
		throws Exception {

		final String plainText = "Hello world!";
		final EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;
		final Map<String, Object> keyAttrs = new HashMap<String, Object>() {{
			put("kid", "1");
			put("x5u", "http://localhost/local.jwks");
			put("x5t", "12345");
			put("x5t#S256", "1234567890");
		}};
		RSAKeyGenerator keyGenerator = new RSAKeyGenerator(2048);
		List<JWK> keyList = new ArrayList<>();
		JWK tmpKey = JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM + SamplePEMEncodedObjects.RSA_CERT_PEM);
		keyList.add(extendJWK(extendJWK(tmpKey, "alg", "RSA-OAEP-256"), "x5c", (List<String>) Arrays.asList(SamplePEMEncodedObjects.RSA_CERT_PEM.replaceAll("-----[^-]*-----", "").replaceAll("\n", ""))));
		for (Map.Entry<String, Object> entry : keyAttrs.entrySet()) {
			tmpKey = (JWK)keyGenerator.algorithm(JWEAlgorithm.RSA_OAEP_256).generate();
			keyList.add(extendJWK(tmpKey, entry.getKey(), entry.getValue()));
		}

		final JWKSet keys = new JWKSet(keyList);

		JWEHeader header = new JWEHeader(enc);

		JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload(plainText));
		JWEEncrypter encrypter = new MultiEncrypter(keys);

		jwe.encrypt(encrypter);
		String json = jwe.serializeGeneral();

		LOGGER.fine("JWE JSON Object: " + json);

		Map<String, Object> jsonJWEObject = JSONObjectUtils.parse(json);
		Map<String, Object>[] recipients = JSONObjectUtils.getJSONObjectArray(jsonJWEObject, "recipients");
		assertEquals(keys.size(), recipients.length);

		assertEquals(Collections.singleton("enc"), JSONObjectUtils.parse(JSONObjectUtils.getBase64URL(jsonJWEObject, "protected").decodeToString()).keySet());

		for (JWK key : keys.getKeys()) {
			jwe = JWEObjectJSON.parse(json);
			jwe.decrypt(new MultiDecrypter(key));
			assertEquals(plainText, jwe.getPayload().toString());
		}
	}


	public void testTwoRecipients_noJWKAlg()
		throws Exception {

		final JWKSet keys = new JWKSet(Arrays.asList(
			(JWK)new RSAKeyGenerator(2048).keyID("1").generate(),
			(JWK)new ECKeyGenerator(Curve.P_256).keyID("2").generate())
		);

		try {
			new MultiEncrypter(keys);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Each JWK must specify a key encryption algorithm", e.getMessage());
		}

	}


	public void testTwoRecipients_jweAlgNotSupported() throws JOSEException {

		final JWKSet keys = new JWKSet(Arrays.asList(
			(JWK)new RSAKeyGenerator(2048).keyID("1").algorithm(JWEAlgorithm.RSA_OAEP_256).generate(),
			(JWK)new ECKeyGenerator(Curve.P_256).keyID("2").algorithm(JWEAlgorithm.ECDH_1PU_A128KW).generate())
		);

		try {
			new MultiEncrypter(keys);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Unsupported key encryption algorithm: " + JWEAlgorithm.ECDH_1PU_A128KW, e.getMessage());
		}
	}


	public void testRejectNullPublicJWKSet() throws JOSEException {

		SecretKey cek = new OctetSequenceKeyGenerator(EncryptionMethod.A128GCM.cekBitLength())
			.generate()
			.toOctetSequenceKey()
			.toSecretKey("AES");

		try {
			new MultiEncrypter(null, cek);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWK set must not be null", e.getMessage());
		}
	}


	public void testRejectCEK_dirKeyMismatch() throws Exception {

		EncryptionMethod enc = EncryptionMethod.A256GCM;

		SecretKey cek = new OctetSequenceKeyGenerator(enc.cekBitLength())
			.generate()
			.toOctetSequenceKey()
			.toSecretKey("AES");

		JWKSet keys = generateJWKSet(enc);

		try {
			new MultiEncrypter(keys, cek);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Bad CEK", e.getMessage());
		}
	}


	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4.7
	public void testParseExample_RFC7516_A_4_7()
		throws ParseException, JOSEException {

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

		RSAKey recipient_1_key = RSAKey.parse(
			"{" +
			"\"kty\":\"RSA\"," +
			"\"kid\":\"2011-04-29\"," + // added "kid" to example
			"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
			"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
			"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
			"7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
			"Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
			"7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
			"\"e\":\"AQAB\"," +
			"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
			"1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
			"nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
			"0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
			"-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
			"T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
			"\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
			"ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
			"krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
			"\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
			"BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
			"-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
			"\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
			"ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
			"Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
			"\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
			"7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
			"odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
			"\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
			"tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
			"B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
			"}");

		jweo.decrypt(new MultiDecrypter(recipient_1_key));

		assertEquals("Live long and prosper.", jweo.getPayload().toString());

		OctetSequenceKey recipient_2_key = OctetSequenceKey.parse(
			"{" +
			"\"kty\":\"oct\"," +
			"\"kid\":\"7\"," +
			"\"k\":\"GawgguFyGrWKav7AX4VKUg\"" +
			"}");

		try {
			jweo.decrypt(new MultiDecrypter(recipient_2_key));
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The JWE object must be in an encrypted state", e.getMessage());
		}

		// Parse again to decrypt with second recipient key
		jweo = JWEObjectJSON.parse(json);

		jweo.decrypt(new MultiDecrypter(recipient_2_key));

		assertEquals("Live long and prosper.", jweo.getPayload().toString());
	}
}
