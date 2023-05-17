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


import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;


public class OutageTolerantJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private static final long TIME_TO_LIVE = 10 * 3600 * 1000;
	
	private final List<OutageTolerantJWKSetSource.OutageEvent<SecurityContext>> events = new LinkedList<>();
	
	private final EventListener<OutageTolerantJWKSetSource<SecurityContext>,SecurityContext> eventListener =
		new EventListener<OutageTolerantJWKSetSource<SecurityContext>, SecurityContext>() {
			@Override
			public void notify(Event<OutageTolerantJWKSetSource<SecurityContext>, SecurityContext> event) {
				events.add((OutageTolerantJWKSetSource.OutageEvent<SecurityContext>) event);
			}
		};
	
	private OutageTolerantJWKSetSource<SecurityContext> source;

	@Test
	public void useDelegate() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
	}

	@Test
	public void useDelegate_withListener() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.isEmpty());
	}

	@Test
	public void useDelegateWhenCached() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		
		JWKSet last = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenReturn(last);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		assertEquals(last, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
	}

	@Test
	public void useDelegateWhenCached_withListener() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, eventListener);
		
		JWKSet last = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenReturn(last);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		assertEquals(last, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.isEmpty());
	}

	@Test
	public void useCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		JWKSet cachedJwkSet = source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, cachedJwkSet);
		assertNotSame(jwkSet, cachedJwkSet);
		assertFalse(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet).requiresRefresh(cachedJwkSet));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
	}

	@Test
	public void useCacheWhenDelegateSigningKeyUnavailable_withListener() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertTrue(events.isEmpty());
		JWKSet cachedJwkSet = source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, cachedJwkSet);
		assertNotSame(jwkSet, cachedJwkSet);
		assertFalse(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet).requiresRefresh(cachedJwkSet));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		assertEquals(1, events.size());
		assertEquals("TEST", events.get(0).getException().getMessage());
		assertTrue(events.get(0).getRemainingTime() > 0L);
	}
	
	@Test
	public void throwExceptionWhenDelegateSigningKeyUnavailableAndCacheEvaluatorAlways() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		when(wrappedJWKSetSource.getJWKSet(any(JWKSetCacheRefreshEvaluator.class), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.forceRefresh(), System.currentTimeMillis(), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
			verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.forceRefresh()), anyLong(), anySecurityContext());
		}
	}

	@Test
	public void throwExceptionWhenDelegateSigningKeyUnavailableAndCacheEvaluatorAlways_withListener() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, eventListener);
		when(wrappedJWKSetSource.getJWKSet(any(JWKSetCacheRefreshEvaluator.class), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.forceRefresh(), System.currentTimeMillis(), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
			verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.forceRefresh()), anyLong(), anySecurityContext());
		}
		
		assertFalse(events.isEmpty());
	}

	@Test
	public void doNotUseExpiredCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST", e.getMessage());
		}
	}

	@Test
	public void doNotUseExpiredCacheWhenDelegateSigningKeyUnavailable_withListener() throws Exception {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertTrue(events.isEmpty());
		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST", e.getMessage());
		}
		assertTrue(events.isEmpty());
	}

	@Test
	public void getBaseProvider() {
		source = new OutageTolerantJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, null);
		assertEquals(wrappedJWKSetSource, source.getSource());
	}
}
