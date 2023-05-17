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


import java.lang.Thread.State;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource.RefreshCompletedEvent;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;


public class CachingJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {
	
	private static final long TIME_TO_LIVE = 10 * 3600 * 1000;
	
	private static final long REFRESH_TIMEOUT = 2 * 1000;

	private final Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!source.getLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private final Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			source.getLock().unlock();
		}
	};
	
	
	private final List<Event<CachingJWKSetSource<SecurityContext>,SecurityContext>> events = new LinkedList<>();
	
	private final EventListener<CachingJWKSetSource<SecurityContext>,SecurityContext> eventListener =
		new EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>() {
		@Override
		public void notify(Event<CachingJWKSetSource<SecurityContext>, SecurityContext> event) {
			events.add(event);
		}
	};
	
	private CachingJWKSetSource<SecurityContext> source;

	@Test
	public void delegateWhenNotCached() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
	}

	@Test
	public void delegateWhenNotCached_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());
		
		assertEquals(TIME_TO_LIVE, events.get(0).getSource().getTimeToLive());
		assertEquals(REFRESH_TIMEOUT, events.get(0).getSource().getCacheRefreshTimeout());
		assertEquals(0, ((CachingJWKSetSource.RefreshInitiatedEvent<SecurityContext>) events.get(0)).getThreadQueueLength());

		CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (RefreshCompletedEvent) events.get(1);
		assertNotNull(refreshCompletedEvent.getJWKSet());
	}

	@Test
	public void returnCached() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new RuntimeException("TEST!", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void returnCached_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new RuntimeException("TEST!", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());
	}

	@Test
	public void delegateWhenExpired() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void delegateWhenExpired_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		// second
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}
	
	@Test
	public void delegateWhenForceRefresh() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);

		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		// second
		source.getJWKSet(JWKSetCacheRefreshEvaluator.forceRefresh(), System.currentTimeMillis(), context);
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
	}

	@Test
	public void delegateWhenForceRefresh_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(first, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());

		// second
		source.getJWKSet(JWKSetCacheRefreshEvaluator.forceRefresh(), System.currentTimeMillis(), context);
		assertEquals(second, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());

		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}


	@Test
	public void doNotReturnExpired() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST!", e.getMessage());
		}
	}

	@Test
	public void doNotReturnExpired_withTest() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		when(wrappedJWKSetSource.getJWKSet(any(JWKSetCacheRefreshEvaluator.class), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST!", e.getMessage());
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertEquals(3, events.size());
	}

	@Test
	public void returnCachedValueForKnownKey() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());
			
			List<JWK> list = wrapper.get(selector, context);
			assertEquals(Collections.singletonList(jwk), list);
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
	}

	@Test
	public void returnCachedValueForKnownKey_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());
			
			List<JWK> list = wrapper.get(selector, context);
			assertEquals(Collections.singletonList(jwk), list);
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, events.size());
	}

	@Test
	public void getBaseProvider() {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		assertThat(source.getSource(), equalTo(wrappedJWKSetSource));
	}

	@Test
	public void refreshForUnknownKey() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);
		
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			// first
			assertEquals(first.getKeys(), wrapper.get(aSelector, context));
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			Thread.sleep(1); // cache is not refreshed if request timestamp is >= timestamp parameter
			
			// second
			assertEquals(second.getKeys(), wrapper.get(bSelector, context));
			verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
	}

	@Test
	public void refreshForUnknownKey_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);
		
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			// first
			assertEquals(first.getKeys(), wrapper.get(aSelector, context));
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			Thread.sleep(1); // cache is not refreshed if request timestamp is >= timestamp parameter
			
			// second
			assertEquals(second.getKeys(), wrapper.get(bSelector, context));
			verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}

	@Test
	public void refreshAndReturnEmptyForUnknownKey() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.referenceComparison(first)), anyLong(), anySecurityContext())).thenReturn(second);
		
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			// first
			assertEquals(first.getKeys(), wrapper.get(aSelector, context));
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			// second
			assertEquals(Collections.emptyList(), wrapper.get(cSelector, context));
			verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.referenceComparison(first)), anyLong(), anySecurityContext());
		}
	}

	@Test
	public void refreshAndReturnEmptyForUnknownKey_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);
		
		try (JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source)) {
			// first
			assertEquals(first.getKeys(), wrapper.get(aSelector, context));
			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
			
			Thread.sleep(1);
			
			// second
			assertEquals(Collections.emptyList(), wrapper.get(cSelector, context));
			verify(wrappedJWKSetSource, times(2)).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(3) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(4, events.size());
	}

	@Test
	public void throwExceptionIfAnotherThreadBlocksUpdate() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.start();
			while (helper.getState() != State.WAITING) {
				Thread.yield();
			}

			try {
				source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
				fail();
			} catch(JWKSetUnavailableException e) {
				assertEquals("Timeout while waiting for cache refresh (2000ms exceeded)", e.getMessage());
			}
		} finally {
			helper.close();
		}
	}

	@Test
	public void throwExceptionIfAnotherThreadBlocksUpdate_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.start();
			while (helper.getState() != State.WAITING) {
				Thread.yield();
			}

			try {
				source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
				fail();
			} catch(JWKSetUnavailableException e) {
				assertEquals("Timeout while waiting for cache refresh (2000ms exceeded)", e.getMessage());
			}
		} finally {
			helper.close();
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.WaitingForRefreshEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshTimedOutEvent);
		assertEquals(2, events.size());
	}

	@Test
	public void acceptIfAnotherThreadUpdatesCache() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, null);
		
		Runnable racer = new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
					source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
				} catch (Exception e) {
					throw new RuntimeException();
				}
			}
		};

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
		try {
			helper.begin();

			helper.next();

			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);

			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
	}

	@Test
	public void acceptIfAnotherThreadUpdatesCache_withListener() throws Exception {
		source = new CachingJWKSetSource<>(wrappedJWKSetSource, TIME_TO_LIVE, REFRESH_TIMEOUT, eventListener);
		
		Runnable racer = new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
					source.getJWKSet(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet), System.currentTimeMillis(), context);
				} catch (Exception e) {
					throw new RuntimeException();
				}
			}
		};

		when(wrappedJWKSetSource.getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
		try {
			helper.begin();

			helper.next();
			
			// so racer holds the lock while this thread attempts to refresh the cache

			source.getJWKSet(JWKSetCacheRefreshEvaluator.referenceComparison(jwkSet), System.currentTimeMillis(), context);

			verify(wrappedJWKSetSource, only()).getJWKSet(anyJWKSetCacheEvaluator(), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
		
		assertTrue(events.get(0) instanceof CachingJWKSetSource.WaitingForRefreshEvent);
		assertTrue(events.get(1) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(events.get(2) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(3, events.size());
	}
}
