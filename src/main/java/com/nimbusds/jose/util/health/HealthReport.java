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

package com.nimbusds.jose.util.health;


import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.Event;
import net.jcip.annotations.Immutable;

import java.util.Objects;


/**
 * Health report.
 *
 * @version 2022-08-29
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class HealthReport <S, C extends SecurityContext> implements Event<S, C> {
	
	
	/**
	 * The event source.
	 */
	private final S source;
	
	
	/**
	 * The health status.
	 */
	private final HealthStatus status;
	
	
	/**
	 * The exception in case of a {@link HealthStatus#NOT_HEALTHY}.
	 */
	private final Exception exception;
	
	
	/**
	 * The report timestamp.
	 */
	private final long timestamp;
	
	
	/**
	 * The optional context.
	 */
	private final C context;
	
	
	/**
	 * Creates a new health report.
	 *
	 * @param source    The event source.
	 * @param status    The health status. Must not be {@code null}.
	 * @param timestamp The timestamp, in milliseconds since the Unix
	 *                  epoch.
	 * @param context   The optional context, {@code null} if not required.
	 */
	public HealthReport(final S source,
			    final HealthStatus status,
			    final long timestamp,
			    final C context) {
		this(source, status, null, timestamp, context);
	}
	
	
	/**
	 * Creates a new health report.
	 *
	 * @param source    The event source.
	 * @param status    The health status. Must not be {@code null}.
	 * @param exception The exception in case of a
	 *                  {@link HealthStatus#NOT_HEALTHY}, {@code null} if
	 *                  not specified.
	 * @param timestamp The timestamp, in milliseconds since the Unix
	 *                  epoch.
	 * @param context   The optional context, {@code null} if not required.
	 */
	public HealthReport(final S source,
			    final HealthStatus status,
			    final Exception exception,
			    final long timestamp,
			    final C context) {
		Objects.requireNonNull(source);
		this.source = source;
		Objects.requireNonNull(status);
		this.status = status;
		if (exception != null && HealthStatus.HEALTHY.equals(status)) {
			throw new IllegalArgumentException("Exception not accepted for a healthy status");
		}
		this.exception = exception;
		this.timestamp = timestamp;
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
	
	
	/**
	 * Returns the health status.
	 *
	 * @return The health status.
	 */
	public HealthStatus getHealthStatus() {
		return status;
	}
	
	
	/**
	 * Returns the recorded exception in case of a
	 * {@link HealthStatus#NOT_HEALTHY}.
	 *
	 * @return The exception, {@code null} if not specified.
	 */
	public Exception getException() {
		return exception;
	}
	
	
	/**
	 * Returns the timestamp.
	 *
	 * @return The timestamp, in milliseconds since the Unix epoch.
	 */
	public long getTimestamp() {
		return timestamp;
	}
	
	
	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("HealthReport{");
		sb.append("source=").append(source);
		sb.append(", status=").append(status);
		sb.append(", exception=").append(exception);
		sb.append(", timestamp=").append(timestamp);
		sb.append(", context=").append(context);
		sb.append('}');
		return sb.toString();
	}
}