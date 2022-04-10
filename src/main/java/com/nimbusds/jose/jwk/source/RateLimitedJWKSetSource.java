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


/**
 * 
 * {@linkplain JWKSetSource} that limits the number of invocations per time
 * unit. This guards against frequent, potentially costly, downstream calls.
 * <br>
 * <br>
 * Per default, two invocations per time period is allowed, so that, under normal
 * operations, there is always one invocation left in case the JWKs are rotated and 
 * results in an unknown key being requested (triggering a refresh of the keys) by
 * a legitimate party.
 *   
 * The other request is (sometimes) consumed by background refreshes. 
 */

public class RateLimitedJWKSetSource<C extends SecurityContext> extends BaseJWKSetSource<C> {

	public static interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		void onRateLimited(long duration, long remaining, C context);
	}
	
	private final Listener<C> listener;
	
	// interval duration
	private final long duration;
	private long nextLimit = -1L;
	private int counter = 0;

	/**
	 * Creates a new JWK set source that throttles the number of requests for a JWKSet.
	 *
	 * @param duration minimum number of milliseconds per two downstream requests.
	 * @param source source to request JWK sets from when within the rate limit.
	 */
	public RateLimitedJWKSetSource(JWKSetSource<C> source, long duration, Listener<C> listener) {
		super(source);
		this.duration = duration;
		this.listener = listener;
	}

	@Override
	public JWKSet getJWKSet(long time, boolean forceUpdate, C context) throws KeySourceException {
		
		// implementation note: this code is not intended to run many parallel threads
		// for the same instance, thus use of synchronized will not cause congestion
		
		boolean rateLimited;
		synchronized(this) {
			if (nextLimit <= time) {
				nextLimit = time + duration;
				counter = 1;
				
				rateLimited = false;
			} else {
				rateLimited = counter <= 0; 
				if(!rateLimited) {
					counter--;
				}
			}
		}
		if(rateLimited) {
			listener.onRateLimited(duration, nextLimit - time, context);
			throw new RateLimitReachedException();
		}
		return source.getJWKSet(time, forceUpdate, context);
	}

}