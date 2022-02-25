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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This JWK set source implements a workaround for temporary network problems /
 * endpoint downtime, running into minutes or hours.<br>
 * <br>
 * <p>
 * It transparently caches a delegate {@linkplain JWKSetSource}, returning the
 * cached value only when the underlying delegate throws a
 * {@linkplain JWKSetUnavailableException}.
 */

public class OutageCachedJWKSetSource<C extends SecurityContext> extends AbstractCachedJWKSetSource<C> {

	private static final Logger LOGGER = Logger.getLogger(OutageCachedJWKSetSource.class.getName());

	public OutageCachedJWKSetSource(JWKSetSource<C> delegate, long duration) {
		super(delegate, duration);
	}

	@Override
	public JWKSet getJWKSet(long currentTime, boolean forceUpdate, C context) throws KeySourceException {
		try {
			// cache value, if successfully refreshed by underlying source

			JWKSet all = source.getJWKSet(currentTime, forceUpdate, context);

			this.cache = createJWKSetCacheItem(all, currentTime);

			return all;
		} catch (JWKSetUnavailableException e1) {
			// attempt to get from underlying cache
			// reuse previously stored value
			if (!forceUpdate) {
				JWKSetCacheItem cache = this.cache;
				if (cache != null && cache.isValid(currentTime)) {
					long left = cache.getExpires() - currentTime; // in millis

					// So validation of tokens will still work, but fail as soon as this cache
					// expires.
					// Note that issuing new tokens will probably not work when this operation does
					// not work either.
					//
					// Logging scheme:
					// 50% time left, or less than one hour -> error
					// 50-100% time left -> warning

					long minutes = (left % 3600000) / 60000;
					long hours = left / 3600000;

					long percent = (left * 100) / timeToLive;

					String message = "Unable to refresh keys for verification of Json Web Token signatures: " + e1.toString() + ". If this is not resolved, all incoming requests with authorization will fail as outage cache expires in "
							+ hours + " hours and " + minutes + " minutes.";
					if (percent < 50 || hours == 0) {
						LOGGER.log(Level.SEVERE, message, e1);
					} else {
						LOGGER.log(Level.WARNING, message, e1);
					}

					return cache.getValue();
				}
			}

			throw e1;
		}
	}

}
