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


import java.net.URL;
import java.util.Objects;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jose.util.events.EventListener;
import com.nimbusds.jose.util.health.HealthReportListener;


/**
 * {@linkplain JWKSource} builder.
 *
 * <p>Supports wrapping of a JWK set source, typically a URL, with the
 * following capabilities:
 *
 * <ul>
 *     <li>{@linkplain CachingJWKSetSource caching}
 *     <li>{@linkplain RefreshAheadCachingJWKSetSource caching with refresh ahead}
 *     <li>{@linkplain RateLimitedJWKSetSource rate limiting}
 *     <li>{@linkplain RetryingJWKSetSource retrial}
 *     <li>{@linkplain JWKSourceWithFailover fail-over}
 *     <li>{@linkplain JWKSetSourceWithHealthStatusReporting health status reporting}
 *     <li>{@linkplain OutageTolerantJWKSetSource outage tolerance}
 * </ul>
 *
 * @author Thomas Rørvik Skjølberg
 * @author Vladimir Dzhuvinov
 * @version 2023-12-10
 */
public class JWKSourceBuilder<C extends SecurityContext> {
	
	
	/**
	 * The default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds. Set to 500 milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT;
	
	
	/**
	 * The default HTTP read timeout for JWK set retrieval, in
	 * milliseconds. Set to 500 milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT = RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT;
	
	
	/**
	 * The default HTTP entity size limit for JWK set retrieval, in bytes.
	 * Set to 50 KBytes.
	 */
	public static final int DEFAULT_HTTP_SIZE_LIMIT = RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
	
	
	/**
	 * The default time to live of cached JWK sets, in milliseconds. Set to
	 * 5 minutes.
	 */
	public static final long DEFAULT_CACHE_TIME_TO_LIVE = 5 * 60 * 1000L;
	
	
	/**
	 * The default refresh timeout of cached JWK sets, in milliseconds. Set
	 * to 15 seconds.
	 */
	public static final long DEFAULT_CACHE_REFRESH_TIMEOUT = 15 * 1000L;
	
	
	/**
	 * The default afresh-ahead time of cached JWK sets, in milliseconds.
	 * Set to 30 seconds.
	 */
	public static final long DEFAULT_REFRESH_AHEAD_TIME = 30_000L;
	
	
	/**
	 * The default rate limiting minimum allowed time interval between two
	 * JWK set retrievals, in milliseconds.
	 */
	public static final long DEFAULT_RATE_LIMIT_MIN_INTERVAL = 30_000L;
	
	
	/**
	 * Creates a new JWK source builder using the specified JWK set URL
	 * and {@linkplain DefaultResourceRetriever} with default timeouts.
	 *
	 * @param jwkSetURL The JWK set URL. Must not be {@code null}.
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> create(final URL jwkSetURL) {
		
		DefaultResourceRetriever retriever = new DefaultResourceRetriever(
			DEFAULT_HTTP_CONNECT_TIMEOUT,
			DEFAULT_HTTP_READ_TIMEOUT,
			DEFAULT_HTTP_SIZE_LIMIT);
		
		JWKSetSource<C> jwkSetSource = new URLBasedJWKSetSource<>(jwkSetURL, retriever);
		
		return new JWKSourceBuilder<>(jwkSetSource);
	}
	
	
	/**
	 * Creates a new JWK source builder using the specified JWK set URL
	 * and resource retriever.
	 *
	 * @param jwkSetURL The JWK set URL. Must not be {@code null}.
	 * @param retriever The resource retriever. Must not be {@code null}.
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> create(final URL jwkSetURL, final ResourceRetriever retriever) {
		return new JWKSourceBuilder<>(new URLBasedJWKSetSource<C>(jwkSetURL, retriever));
	}
	
	
	/**
	 * Creates a new JWK source builder wrapping an existing source.
	 *
	 * @param source The JWK source to wrap. Must not be {@code null}.
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> create(final JWKSetSource<C> source) {
		return new JWKSourceBuilder<>(source);
	}

	// the wrapped source
	private final JWKSetSource<C> jwkSetSource;

	// caching
	private boolean caching = true;
	private long cacheTimeToLive = DEFAULT_CACHE_TIME_TO_LIVE;
	private long cacheRefreshTimeout = DEFAULT_CACHE_REFRESH_TIMEOUT;
	private EventListener<CachingJWKSetSource<C>, C> cachingEventListener;

	private boolean refreshAhead = true;
	private long refreshAheadTime = DEFAULT_REFRESH_AHEAD_TIME;
	private boolean refreshAheadScheduled = false;

	// rate limiting (retry on network error will not count against this)
	private boolean rateLimited = true;
	private long minTimeInterval = DEFAULT_RATE_LIMIT_MIN_INTERVAL;
	private EventListener<RateLimitedJWKSetSource<C>, C> rateLimitedEventListener;

	// retrying
	private boolean retrying = false;
	private EventListener<RetryingJWKSetSource<C>, C> retryingEventListener;

	// outage
	private boolean outageTolerant = false;
	private long outageCacheTimeToLive = -1L;
	private EventListener<OutageTolerantJWKSetSource<C>, C> outageEventListener;

	// health status reporting
	private HealthReportListener<JWKSetSourceWithHealthStatusReporting<C>, C> healthReportListener;

	// failover
	protected JWKSource<C> failover;
	

	/**
	 * Creates a new JWK set source.
	 *
	 * @param jwkSetSource The JWK set source to wrap. Must not be
	 *                     {@code null}.
	 */
	private JWKSourceBuilder(final JWKSetSource<C> jwkSetSource) {
		Objects.requireNonNull(jwkSetSource);
		this.jwkSetSource = jwkSetSource;
	}

	
	/**
	 * Toggles caching of the JWK set.
	 *
	 * @param enable {@code true} to cache the JWK set.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final boolean enable) {
		this.caching = enable;
		return this;
	}


	/**
	 * Enables caching of the retrieved JWK set.
	 * 
	 * @param timeToLive          The time to live of the cached JWK set,
	 *                            in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final long timeToLive, final long cacheRefreshTimeout) {
		this.caching = true;
		this.cacheTimeToLive = timeToLive;
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		return this;
	}


	/**
	 * Enables caching of the retrieved JWK set.
	 *
	 * @param timeToLive          The time to live of the cached JWK set,
	 *                            in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 * @param eventListener       The event listener, {@code null} if not
	 *                            specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final long timeToLive,
					 final long cacheRefreshTimeout,
					 final EventListener<CachingJWKSetSource<C>, C> eventListener) {
		this.caching = true;
		this.cacheTimeToLive = timeToLive;
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		this.cachingEventListener = eventListener;
		return this;
	}


	/**
	 * Enables caching of the JWK set forever (no expiration).
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cacheForever() {
		this.caching = true;
		this.cacheTimeToLive = Long.MAX_VALUE;
		this.refreshAhead = false; // refresh ahead not necessary
		return this;
	}
	
	
	/**
	 * Toggles refresh-ahead caching of the JWK set.
	 *
	 * @param enable {@code true} to enable refresh-ahead caching of the
	 *               JWK set.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final boolean enable) {
		if (enable) {
			this.caching = true;
		}
		this.refreshAhead = enable;
		return this;
	}
	
	
	/**
	 * Enables refresh-ahead caching of the JWK set.
	 *
	 * @param refreshAheadTime The refresh ahead time, in milliseconds.
	 * @param scheduled        {@code true} to refresh in a scheduled
	 *                         manner, regardless of requests.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final long refreshAheadTime, final boolean scheduled) {
		this.caching = true;
		this.refreshAhead = true;
		this.refreshAheadTime = refreshAheadTime;
		this.refreshAheadScheduled = scheduled;
		return this;
	}
	
	
	/**
	 * Enables refresh-ahead caching of the JWK set.
	 *
	 * @param refreshAheadTime The refresh ahead time, in milliseconds.
	 * @param scheduled        {@code true} to refresh in a scheduled
	 *                         manner, regardless of requests.
	 * @param eventListener    The event listener, {@code null} if not
	 *                         specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final long refreshAheadTime,
						     final boolean scheduled,
						     final EventListener<CachingJWKSetSource<C>, C> eventListener) {
		this.caching = true;
		this.refreshAhead = true;
		this.refreshAheadTime = refreshAheadTime;
		this.refreshAheadScheduled = scheduled;
		this.cachingEventListener = eventListener;
		return this;
	}


	/**
	 * Toggles rate limiting of the JWK set retrieval.
	 *
	 * @param enable {@code true} to rate limit the JWK set retrieval.
	 *                           
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> rateLimited(final boolean enable) {
		this.rateLimited = enable;
		return this;
	}

	
	/**
	 * Enables rate limiting of the JWK set retrieval.
	 *
	 * @param minTimeInterval The minimum allowed time interval between two
	 *                        JWK set retrievals, in milliseconds.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> rateLimited(final long minTimeInterval) {
		this.rateLimited = true;
		this.minTimeInterval = minTimeInterval;
		return this;
	}

	
	/**
	 * Enables rate limiting of the JWK set retrieval.
	 *
	 * @param minTimeInterval The minimum allowed time interval between two
	 *                        JWK set retrievals, in milliseconds.
	 * @param eventListener   The event listener, {@code null} if not
	 *                        specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> rateLimited(final long minTimeInterval,
					       final EventListener<RateLimitedJWKSetSource<C>, C> eventListener) {
		this.rateLimited = true;
		this.minTimeInterval = minTimeInterval;
		this.rateLimitedEventListener = eventListener;
		return this;
	}
	
	
	/**
	 * Sets a failover JWK source.
	 *
	 * @param failover The failover JWK source, {@code null} if none.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> failover(final JWKSource<C> failover) {
		this.failover = failover;
		return this;
	}
	
	
	/**
	 * Enables single retrial to retrieve the JWK set to work around
	 * transient network issues.
	 * 
	 * @param enable {@code true} to enable single retrial.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> retrying(final boolean enable) {
		this.retrying = enable;
		return this;
	}
	
	
	/**
	 * Enables single retrial to retrieve the JWK set to work around
	 * transient network issues.
	 *
	 * @param eventListener The event listener, {@code null} if not
	 *                      specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> retrying(final EventListener<RetryingJWKSetSource<C>, C> eventListener) {
		this.retrying = true;
		this.retryingEventListener = eventListener;
		return this;
	}

	
	/**
	 * Sets a health report listener.
	 *
	 * @param listener The health report listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> healthReporting(final HealthReportListener<JWKSetSourceWithHealthStatusReporting<C>, C> listener) {
		this.healthReportListener = listener;
		return this;
	}
	
	
	/**
	 * Toggles outage tolerance by serving a cached JWK set in case of
	 * outage.
	 *
	 * @param enable {@code true} to enable the outage cache.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final boolean enable) {
		this.outageTolerant = enable;
		return this;
	}

	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
	 * case of outage.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerantForever() {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = Long.MAX_VALUE;
		return this;
	}
	
	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
 	 * case of outage.
	 *
	 * @param timeToLive The time to live of the cached JWK set to cover
	 *                   outages, in milliseconds.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final long timeToLive) {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = timeToLive;
		return this;
	}
	
	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
 	 * case of outage.
	 *
	 * @param timeToLive    The time to live of the cached JWK set to cover
	 *                      outages, in milliseconds.
	 * @param eventListener The event listener, {@code null} if not
	 *                      specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final long timeToLive,
						  final EventListener<OutageTolerantJWKSetSource<C>, C> eventListener) {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = timeToLive;
		this.outageEventListener = eventListener;
		return this;
	}

	
	/**
	 * Builds the final {@link JWKSource}.
	 *
	 * @return The final {@link JWKSource}.
	 */
	public JWKSource<C> build() {
		
		if (! caching && rateLimited) {
			throw new IllegalStateException("Rate limiting requires caching");
		} else if (! caching && refreshAhead) {
			throw new IllegalStateException("Refresh-ahead caching requires general caching");
		}

		if (caching && rateLimited && cacheTimeToLive <= minTimeInterval) {
			throw new IllegalStateException("The rate limiting min time interval between requests must be less than the cache time-to-live");
		}
		
		if (caching && outageTolerant && cacheTimeToLive == Long.MAX_VALUE && outageCacheTimeToLive == Long.MAX_VALUE) {
			// TODO consider adjusting instead of exception
			throw new IllegalStateException("Outage tolerance not necessary with a non-expiring cache");
		}

		if (caching && refreshAhead && cacheTimeToLive == Long.MAX_VALUE) {
			// TODO consider adjusting instead of exception
			throw new IllegalStateException("Refresh-ahead caching not necessary with a non-expiring cache");
		}
		
		JWKSetSource<C> source = jwkSetSource;

		if (retrying) {
			source = new RetryingJWKSetSource<>(source, retryingEventListener);
		}
		
		if (outageTolerant) {
			if (outageCacheTimeToLive == -1L) {
				if (caching) {
					outageCacheTimeToLive = cacheTimeToLive * 10;
				} else {
					outageCacheTimeToLive = DEFAULT_CACHE_TIME_TO_LIVE * 10;
				}
			}
			source = new OutageTolerantJWKSetSource<>(source, outageCacheTimeToLive, outageEventListener);
		}

		if (healthReportListener != null) {
			source = new JWKSetSourceWithHealthStatusReporting<>(source, healthReportListener);
		}

		if (rateLimited) {
			source = new RateLimitedJWKSetSource<>(source, minTimeInterval, rateLimitedEventListener);
		}
		
		if (refreshAhead) {
			source = new RefreshAheadCachingJWKSetSource<>(source, cacheTimeToLive, cacheRefreshTimeout, refreshAheadTime, refreshAheadScheduled, cachingEventListener);
		} else if (caching) {
			source = new CachingJWKSetSource<>(source, cacheTimeToLive, cacheRefreshTimeout, cachingEventListener);
		}

		JWKSource<C> jwkSource = new JWKSetBasedJWKSource<>(source);
		if (failover != null) {
			return new JWKSourceWithFailover<>(jwkSource, failover);
		}
		return jwkSource;
	}
}
