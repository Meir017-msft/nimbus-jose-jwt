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


import java.util.LinkedList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;


public class RetryingJWKSetSourceTest extends AbstractWrappedJWKSetSourceTest {

	private RetryingJWKSetSource<SecurityContext> source;
	
	private final List<RetryingJWKSetSource.RetrialEvent<SecurityContext>> events = new LinkedList<>();
	
	private final EventListener<RetryingJWKSetSource<SecurityContext>,SecurityContext> eventListener =
		new EventListener<RetryingJWKSetSource<SecurityContext>, SecurityContext>() {
			@Override
			public void notify(Event<RetryingJWKSetSource<SecurityContext>, SecurityContext> event) {
				events.add((RetryingJWKSetSource.RetrialEvent<SecurityContext>) event);
			}
		};

	@Test
	public void success() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
	}

	@Test
	public void success_withListener() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(1)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		assertTrue(events.isEmpty());
	}

	@Test
	public void retryWhenUnavailable() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null)).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
	}

	@Test
	public void retryWhenUnavailable_withListener() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null)).thenReturn(jwkSet);
		assertEquals(jwkSet, source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context));
		verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		assertEquals(1, events.size());
		
		RetryingJWKSetSource.RetrialEvent<SecurityContext> event = events.get(0);
		assertNotNull(event.getException());
	}

	@Test
	public void doNotRetryMoreThanOnce() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, null);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null));

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST!", e.getMessage());
		} finally {
			verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		}
	}

	@Test
	public void doNotRetryMoreThanOnce_withListener() throws Exception {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, eventListener);
		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null));

		try {
			source.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			assertEquals("TEST!", e.getMessage());
		} finally {
			verify(wrappedJWKSetSource, times(2)).getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), anySecurityContext());
		}
		assertEquals(1, events.size());
	}

	
	@Test
	public void getBaseProvider() {
		source = new RetryingJWKSetSource<>(wrappedJWKSetSource, null);
		assertEquals(wrappedJWKSetSource, source.getSource());
	}
}
