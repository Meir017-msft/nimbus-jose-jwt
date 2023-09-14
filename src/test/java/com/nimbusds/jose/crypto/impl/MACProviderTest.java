/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.util.StandardCharset;
import junit.framework.TestCase;
import org.junit.Assert;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Collections;

public class MACProviderTest extends TestCase {


        public void testSupportedAlgorithms() {

                assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS256));
                assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS384));
                assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS512));
                assertEquals(3, MACProvider.SUPPORTED_ALGORITHMS.size());
        }

        static class RegularProvider extends MACProvider {

                RegularProvider(final SecretKey secretKey) throws KeyLengthException {
                        super(secretKey, Collections.singleton(JWSAlgorithm.HS256));
                }
        }

        static class HSMProvider extends MACProvider {

                HSMProvider(final SecretKey secretKey) throws KeyLengthException {
                        super(secretKey, Collections.singleton(JWSAlgorithm.HS256));
                }
        }


        public void testWithSecretKeyThatDoesNotExposeKeyMaterial()
                throws KeyLengthException {

                SecretKey secretKey = new SecretKey() {
                        @Override
                        public String getAlgorithm() {
                                return "HMACSHA256";
                        }

                        @Override
                        public String getFormat() {
                                return null; // never called
                        }

                        @Override
                        public byte[] getEncoded() {
                                return null;
                        }
                };

                HSMProvider provider = new HSMProvider(secretKey);

                assertEquals(secretKey, provider.getSecretKey());
                assertNull(provider.getSecret());
                assertNull(provider.getSecretString());
        }


        public void testSecretKeyConstructor_nullSecretKey()
                throws KeyLengthException {

                try {
                        new RegularProvider(null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }

                try {
                        new HSMProvider(null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }
        }


        public void testSecretKeyConstructor_secretKeyTooShort() {

                byte[] keyBytes = new byte[(256 - 1) / 8];
                new SecureRandom().nextBytes(keyBytes);
                SecretKey secretKey = new SecretKeySpec(keyBytes, "HMACSHA256");

                try {
                        new RegularProvider(secretKey);
                        fail();
                } catch (KeyLengthException e) {
                        assertEquals("The secret length must be at least 256 bits", e.getMessage());
                }
        }


        public void testSecretKeyConstructor_256BitSecretKey()
                throws KeyLengthException {

                byte[] keyBytes = new byte[256 / 8];
                new SecureRandom().nextBytes(keyBytes);
                SecretKey secretKey = new SecretKeySpec(keyBytes, "HMACSHA256");

                RegularProvider regularProvider = new RegularProvider(secretKey);

                assertEquals(secretKey, regularProvider.getSecretKey());
                Assert.assertArrayEquals(secretKey.getEncoded(), regularProvider.getSecret());
                assertEquals(new String(secretKey.getEncoded(), StandardCharset.UTF_8), regularProvider.getSecretString());
        }
}
