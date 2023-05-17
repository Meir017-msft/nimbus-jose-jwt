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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;


public class RefreshAheadCachingJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private final Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!source.getLazyLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private final Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			source.getLazyLock().unlock();
		}
	};

	private static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";
	private static final long TIME_TO_LIVE = 3600 * 1000 * 10;
	private static final long REFRESH_TIMEOUT = 15_1000;
	private static final long REFRESH_AHEAD_TIME = 10_000;
	protected static final JWKSelector KID_SELECTOR = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());
	
	private final List<Event<CachingJWKSetSource<SecurityContext>,SecurityContext>> events = new LinkedList<>();
	
	private final EventListener<CachingJWKSetSource<SecurityContext>,SecurityContext> eventListener =
		new EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>() {
			@Override
			public void notify(Event<CachingJWKSetSource<SecurityContext>, SecurityContext> event) {
				events.add(event);
			}
		};

	private RefreshAheadCachingJWKSetSource<SecurityContext> source;
	
	private JWKSetBasedJWKSource<SecurityContext> wrapper;
	
	
	private void setUp(final boolean withListener) {
		
		source = new RefreshAheadCachingJWKSetSource<>(
			wrappedJWKSetSource,
			TIME_TO_LIVE,
			REFRESH_TIMEOUT,
			REFRESH_AHEAD_TIME,
			false,
			withListener ? eventListener : null);
		
		wrapper = new JWKSetBasedJWKSource<>(source);
	}
	
	
	@Test
	public void rejectRefreshAheadTimePlusCacheRefreshTimeoutExceedingTimeToLive() {
		
		setUp(false);
		
		long timeToLive = 60_000;
		long cacheRefreshTimeout = 10_000;
		long refreshAheadTime = 50_001;
		
		assertTrue(cacheRefreshTimeout + refreshAheadTime > timeToLive);
		
		try {
			new RefreshAheadCachingJWKSetSource<>(wrappedJWKSetSource, timeToLive, cacheRefreshTimeout, refreshAheadTime, false, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The sum of the refresh-ahead time (50001ms) and the cache refresh timeout (10000ms) must not exceed the time-to-lived time (60000ms)", e.getMessage());
		}
	}

	@Test
	public void notCached() throws Exception {
		
		for (boolean withListener: new boolean[]{false, true}) {
		
			setUp(withListener);
			
			when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);
			assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
			
			if (withListener) {
				assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
				assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
				assertEquals(2, events.size());
			} else {
				assertTrue(events.isEmpty());
			}
		}
	}

	@Test
	public void useCache() throws Exception {
		
		setUp(false);
			
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void useCache_withListener() throws Exception {
		
		setUp(true);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());
		
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertEquals(2, events.size());
	}

	@Test
	public void expiredCache() throws Exception {
		
		setUp(false);
		
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void expiredCache_withListener() throws Exception {
		
		setUp(true);
		
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		// second
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}

	@Test
	public void doNotReturnExpiredOnFailedRefresh() throws Exception {
		setUp(false);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(KeySourceException e) {
			assertEquals("TEST!", e.getMessage());
		}
	}

	@Test
	public void doNotReturnExpiredOnFailedRefresh_withListener() throws Exception {
		setUp(true);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(KeySourceException e) {
			assertEquals("TEST!", e.getMessage());
		}
		
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertEquals(3, events.size());
	}

	@Test
	public void getWrappedSource() {
		setUp(false);
		assertThat(source.getSource(), equalTo(wrappedJWKSetSource));
	}

	@Test
	public void keyInCache() throws Exception {
		setUp(false);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(Collections.singletonList(jwk), wrapper.get(KID_SELECTOR, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void keyInCache_withListener() throws Exception {
		setUp(true);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(Collections.singletonList(jwk), wrapper.get(KID_SELECTOR, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());
	}

	@Test
	public void keyNotInCache() throws Exception {
		
		setUp(false);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(first.getKeys(), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		Thread.sleep(1);
		
		// second
		assertEquals(second.getKeys(), wrapper.get(bSelector, context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void keyNotInCache_withListener() throws Exception {
		
		setUp(true);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(first.getKeys(), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		Thread.sleep(1);
		
		// second
		assertEquals(second.getKeys(), wrapper.get(bSelector, context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}

	@Test
	public void refreshCacheAndReturnEmptyForUnknownKey() throws Exception {
		
		setUp(false);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(Collections.singletonList(a), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second
		List<JWK> list = wrapper.get(cSelector, context);
		assertTrue(list.isEmpty());
	}

	@Test
	public void refreshCacheAndReturnEmptyForUnknownKey_withListener() throws Exception {
		
		setUp(true);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(Collections.singletonList(a), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		// second
		List<JWK> list = wrapper.get(cSelector, context);
		assertTrue(list.isEmpty());
		
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}

	@Test
	public void refreshAhead() throws Exception {
		
		setUp(false);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		List<JWK> longBeforeExpiryKeys = wrapper.get(aSelector, context);
		assertFalse(longBeforeExpiryKeys.isEmpty());
		assertEquals(first.getKeys(), longBeforeExpiryKeys);
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// trigger a refresh ahead of expiration (by getting the keys)
		JWKSet justBeforeExpiryKeys = source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context); 
		assertFalse(justBeforeExpiryKeys.isEmpty());
		assertEquals(first.getKeys(), justBeforeExpiryKeys.getKeys()); 

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second jwks
		assertEquals( second.getKeys(), wrapper.get(bSelector, context)); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void refreshAhead_withListener() throws Exception {
		
		setUp(true);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		List<JWK> longBeforeExpiryKeys = wrapper.get(aSelector, context);
		assertFalse(longBeforeExpiryKeys.isEmpty());
		assertEquals(first.getKeys(), longBeforeExpiryKeys);
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// trigger a refresh ahead of expiration (by getting the keys)
		JWKSet justBeforeExpiryKeys = source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context);
		assertFalse(justBeforeExpiryKeys.isEmpty());
		assertEquals(first.getKeys(), justBeforeExpiryKeys.getKeys()); 

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(2) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(4) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(5) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent);
		assertEquals(6, events.size());

		// second jwks
		assertEquals( second.getKeys(), wrapper.get(bSelector, context)); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertEquals(6, events.size());
	}

	@Test
	public void noRefreshAheadIfAnotherInProgress() throws Exception {
		
		setUp(false);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		CachedObject<JWKSet> cache = source.getCachedJWKSetIfValid(System.currentTimeMillis());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers a scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		source.refreshAheadOfExpiration(cache, false, justBeforeExpiry, context); // must not trigger a scheduled refresh attempt

		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(second.getKeys(), wrapper.get(bSelector, null)); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void noRefreshAheadIfAnotherInProgress_withListener() throws Exception {
		
		setUp(true);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		CachedObject<JWKSet> cache = source.getCachedJWKSetIfValid(System.currentTimeMillis());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers a scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		
		assertTrue(events.get(2) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(4) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(5) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent);
		assertEquals(6, events.size());
		
		source.refreshAheadOfExpiration(cache, false, justBeforeExpiry, context); // must not trigger a scheduled refresh attempt

		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(second.getKeys(), wrapper.get(bSelector, null)); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertEquals(6, events.size());
	}

	@Test
	public void repeatRefreshAheadIfPreviousFailed() throws Exception {
		
		setUp(false);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenThrow(new JWKSetUnavailableException("TEST!")).thenReturn(second);

		// first jwks
		assertEquals(first.getKeys(), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers a scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers another scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		verify(wrappedJWKSetSource, times(3)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(second.getKeys(), wrapper.get(bSelector, context)); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(3)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void repeatRefreshAheadIfPreviousFailed_withListener() throws Exception {
		
		setUp(true);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenThrow(new JWKSetUnavailableException("TEST!")).thenReturn(second);

		// first jwks
		assertEquals(first.getKeys(), wrapper.get(aSelector, context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers a scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		
		assertTrue(events.get(2) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(4) instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent);
		assertEquals(5, events.size());

		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // triggers another scheduled refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		verify(wrappedJWKSetSource, times(3)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(5) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshInitiatedEvent);
		assertTrue(events.get(6) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(7) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(8) instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent);
		assertEquals(9, events.size());

		// second jwks
		assertEquals(second.getKeys(), wrapper.get(bSelector, context)); // must be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(wrappedJWKSetSource, times(3)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertEquals(9, events.size());
	}

	@Test
	public void acceptRefreshAheadOnAnotherThread() throws Exception {
		
		setUp(false);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.begin();
			
			assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // wants to update, but can't get lock

			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
	}

	@Test
	public void acceptRefreshAheadOnAnotherThread_withListener() throws Exception {
		
		setUp(true);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.begin();

			assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), justBeforeExpiry, context)); // wants to update, but can't get lock

			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
		
		assertEquals(2, events.size());
	}

	@Test
	public void scheduleRefreshAhead() throws Exception {
		long timeToLive = 1000; 
		long cacheRefreshTimeout = 150;
		long refreshAheadTime = 300;

		RefreshAheadCachingJWKSetSource<SecurityContext> source = new RefreshAheadCachingJWKSetSource<>(wrappedJWKSetSource, timeToLive, cacheRefreshTimeout, refreshAheadTime, true, null);
		
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			JWK a = mock(JWK.class);
			when(a.getKeyID()).thenReturn("a");
			JWK b = mock(JWK.class);
			when(b.getKeyID()).thenReturn("b");
			
			JWKSet first = new JWKSet(a);
			JWKSet second = new JWKSet(b);
			
			when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);
			
			long time = System.currentTimeMillis();
			
			// first jwks
			assertEquals(first.getKeys(), wrapper.get(aSelector, context));
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			ScheduledFuture<?> eagerJwkListCacheItem = source.getScheduledRefreshFuture();
			assertNotNull(eagerJwkListCacheItem);
			
			long left = eagerJwkListCacheItem.getDelay(TimeUnit.MILLISECONDS);
			
			long skew = System.currentTimeMillis() - time;
			
			assertTrue(left <= timeToLive - cacheRefreshTimeout - refreshAheadTime);
			assertTrue(left >= timeToLive - cacheRefreshTimeout - refreshAheadTime - skew - 1);
			
			// sleep and check that keys were actually updated
			Thread.sleep(left + Math.min(25, 4 * skew));
			
			source.getExecutorService().awaitTermination(Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
			verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			// no new update necessary
			assertEquals(second.getKeys(), wrapper.get(bSelector, context));
			verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
	}
}
