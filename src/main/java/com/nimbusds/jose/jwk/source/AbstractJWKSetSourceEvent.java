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

package com.nimbusds.jose.jwk.source;


import java.util.Objects;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.Event;


/**
 * Abstract {@linkplain Event}.
 *
 * @version 2022-08-28
 * @author Vladimir Dzhuvinov
 */
class AbstractJWKSetSourceEvent<S extends JWKSetSource<C>, C extends SecurityContext> implements Event<S,C> {
	
	
	private final S source;
	
	private final C context;
	
	
	/**
	 * Creates a new JWK set source event.
	 *
	 * @param source  The event source. Must not be {@code null}.
	 * @param context Optional context, {@code null} if not required.
	 */
	AbstractJWKSetSourceEvent(final S source, final C context) {
		Objects.requireNonNull(source);
		this.source = source;
		this.context = context;
	}
	
	
	@Override
	public S getSource() {
		return source;
	}
	
	
	@Override
	public C getContext() {
		return context;
	}
}
