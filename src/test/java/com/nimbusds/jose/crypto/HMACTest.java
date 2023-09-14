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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.StandardCharset;
import junit.framework.TestCase;
import org.junit.Assert;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * Tests the HMAC helper class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2023-09-14
 */
public class HMACTest extends TestCase {


	public void testVector()
		throws Exception {

		// Vectors from http://openidtest.uninett.no/jwt#

		byte[] msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUub3JnIiwidHlwIjoiSldUIn0".getBytes(StandardCharset.UTF_8);
		byte[] mac = new Base64URL("eagkgLML8Ccrn4eIvidX4a10JBE4Q3eaOAf4Blj9P4c").decode();
		byte[] key = "1879197b29d8ec57".getBytes(StandardCharset.UTF_8);
		
		assertEquals(16, key.length);

		final Provider defaultProvider = null;
		final Provider explicitProvider = Mac.getInstance("HMACSHA256").getProvider();

		byte[] computedMac;

		for (Provider provider: Arrays.asList(defaultProvider, explicitProvider)) {

			// Key is byte[]
			computedMac = HMAC.compute("HMACSHA256", key, msg, provider);
			Assert.assertArrayEquals(mac, computedMac);

			// Key is SecretKey
			computedMac = HMAC.compute(new SecretKeySpec(key, "HMACSHA256"), msg, provider);
			Assert.assertArrayEquals(mac, computedMac);

			// Key is SecretKey with alg override
			computedMac = HMAC.compute("HMACSHA256", new SecretKeySpec(key, "xxx"), msg, provider);
			Assert.assertArrayEquals(mac, computedMac);
		}
	}
	
	
	public void testDifferentHMACWithLongerKey()
		throws Exception {
		
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		
		byte[] computedHmac = HMAC.compute("HMACSHA256", secret, "Hello, world!".getBytes(StandardCharset.UTF_8), null);
		
		byte[] secondHmac = HMAC.compute("HMACSHA256", ByteUtils.concat(secret, secret), "Hello, world!".getBytes(StandardCharset.UTF_8), null);
		
		assertFalse(Arrays.equals(computedHmac, secondHmac));
	}


	public void testGetInitMac_unsupportedAlgorithm() {

		byte[] key = "1879197b29d8ec57".getBytes(StandardCharset.UTF_8);

		try {
			HMAC.getInitMac(new SecretKeySpec(key, "xxx"), null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported HMAC algorithm: Algorithm xxx not available", e.getMessage());
		}

		try {
			HMAC.getInitMac("xxx", new SecretKeySpec(key, "HMACSHA256"), null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported HMAC algorithm: Algorithm xxx not available", e.getMessage());
		}
	}
}
