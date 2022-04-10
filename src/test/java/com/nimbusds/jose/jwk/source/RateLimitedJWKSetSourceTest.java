/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

package com.nimbusds.jose.jwk.source;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.proc.SecurityContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.logging.Level;

public class RateLimitedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private RateLimitedJWKSetSource<SecurityContext> provider;

	private int duration = 30 * 1000;
	
	private RateLimitedJWKSetSource.Listener<SecurityContext> listener = new DefaultRateLimitedJWKSetSourceListener<SecurityContext>(Level.INFO);
	
	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new RateLimitedJWKSetSource<>(delegate, duration, listener);
	}

	@Test
	public void testShouldFailToGetWhenBucketIsEmpty() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis() + 1, false, context), jwks);
		try {
			provider.getJWKSet(System.currentTimeMillis(), false, context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
		}
	}
	
	@Test
	public void testRefillBucket() throws Exception {
		long time = System.currentTimeMillis();
		
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);
		assertEquals(provider.getJWKSet(time, false, context), jwks);
		assertEquals(provider.getJWKSet(time + 1, false, context), jwks);
		try {
			provider.getJWKSet(time + 2, false, context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
		}
		
		assertEquals(provider.getJWKSet(time + duration, false, context), jwks);
		
	}

	@Test
	public void testShouldGetWhenBucketHasTokensAvailable() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);

		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		verify(delegate).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

}