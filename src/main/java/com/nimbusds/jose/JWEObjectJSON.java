/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.jose;


import com.nimbusds.jose.JWEObject.State;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.jcip.annotations.ThreadSafe;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;


/**
 * JSON Web Encryption (JWE) secured object with
 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2">JSON
 * serialisation</a>.
 *
 * <p>This class is thread-safe.
 *
 * @author Egor Puzanov
 * @author Vladimir Dzhuvinov
 * @version 2023-09-13
 */
@ThreadSafe
public class JWEObjectJSON extends JOSEObjectJSON {


	private static final long serialVersionUID = 1L;


	/**
	 * Individual recipient in a JWE object serialisable to JSON.
	 */
	@Immutable
	public static final class Recipient {


		/**
		 * The per-recipient unprotected header.
		 */
		private final UnprotectedHeader unprotectedHeader;


		/**
		 * The encrypted key, {@code null} if none.
		 */
		private final Base64URL encryptedKey;


		/**
		 * Creates a new parsed recipient.
		 *
		 * @param unprotectedHeader The per-recipient unprotected
		 *                          header, {@code null} if none.
		 * @param encryptedKey      The encrypted key, {@code null} if
		 *                          none.
		 */
		public Recipient(final UnprotectedHeader unprotectedHeader,
				 final Base64URL encryptedKey) {
			this.unprotectedHeader = unprotectedHeader;
			this.encryptedKey = encryptedKey;
		}


		/**
		 * Returns the per-recipient unprotected header.
		 *
		 * @return The per-recipient unprotected header, {@code null}
		 *         if none.
		 */
		public UnprotectedHeader getUnprotectedHeader() {
			return unprotectedHeader;
		}


		/**
		 * Returns the encrypted key.
		 *
		 * @return The encryptedKey.
		 */
		public Base64URL getEncryptedKey() {
			return encryptedKey;
		}


		/**
		 * Returns a JSON object representation for use in the general
		 * and flattened serialisations.
		 *
		 * @return The JSON object.
		 */
		public Map<String, Object> toJSONObject() {
			Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
			
			if (unprotectedHeader != null && ! unprotectedHeader.getIncludedParams().isEmpty()) {
				jsonObject.put("header", unprotectedHeader.toJSONObject());
			}
			if (encryptedKey != null) {
				jsonObject.put("encrypted_key", encryptedKey.toString());
			}
			return jsonObject;
		}


		/**
		 * Parses a recipients object from the specified JSON object.
		 *
		 * @param jsonObject The JSON object to parse. Must not be
		 *             {@code null}.
		 *
		 * @return The recipient object.
		 *
		 * @throws ParseException If the string couldn't be parsed to a
		 *                        JWE object.
		 */
		public static Recipient parse(final Map<String, Object> jsonObject)
			throws ParseException {

			final UnprotectedHeader header = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(jsonObject, "header"));
			final Base64URL encryptedKey = JSONObjectUtils.getBase64URL(jsonObject, "encrypted_key");

			return new Recipient(header, encryptedKey);
		}
	}


	/**
	 * The JWE protected header.
	 */
	private final JWEHeader header;


	/**
	 * The shared unprotected header.
	 */
	private UnprotectedHeader unprotectedHeader;


	/**
	 * The recipients list.
	 */
	private final List<Recipient> recipients = new LinkedList<>();


	/**
	 * The initialisation vector, {@code null} if not generated or
	 * applicable.
	 */
	private Base64URL iv;


	/**
	 * The cipher text, {@code null} if not computed.
	 */
	private Base64URL cipherText;


	/**
	 * The authentication tag, {@code null} if not computed or applicable.
	 */
	private Base64URL authTag;


	/**
	 * The additional authenticated data, {@code null} if not computed or
	 * applicable.
	 */
	private final byte[] aad;


	/**
	 * The JWE object state.
	 */
	private JWEObject.State state;


	/**
	 * Creates a new JWE JSON object from the specified JWE object with
	 * compact serialisation. The initial state is copied from the JWE
	 * object.
	 *
	 * @param jweObject  The JWE object. Must not be {@code null}.
	 */
	public JWEObjectJSON(final JWEObject jweObject) {

		super(jweObject.getPayload());

		this.header = jweObject.getHeader();
		this.aad = null;
		this.iv = jweObject.getIV();
		this.cipherText = jweObject.getCipherText();
		this.authTag = jweObject.getAuthTag();
		if (jweObject.getState() == JWEObject.State.ENCRYPTED) {
			this.recipients.add(new Recipient(null, jweObject.getEncryptedKey()));
			this.state = State.ENCRYPTED;
		} else if (jweObject.getState() == JWEObject.State.DECRYPTED) {
			this.recipients.add(new Recipient(null, jweObject.getEncryptedKey()));
			this.state = State.DECRYPTED;
		} else {
			this.state = State.UNENCRYPTED;
		}
	}


	/**
	 * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with
	 * the specified JWE protected header and payload. The initial state
	 * will be {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @param header  The JWE protected header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public JWEObjectJSON(final JWEHeader header, final Payload payload) {

	    this(header, payload, null, null);
	}


	/**
	 * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with
	 * the specified JWE protected header, payload and Additional
	 * Authenticated Data (AAD). The initial state will be
	 * {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @param header            The JWE protected header. Must not be
	 *                          {@code null}.
	 * @param payload           The payload. Must not be {@code null}.
	 * @param unprotectedHeader The shared unprotected header, empty or
	 *                          {@code null} if none.
	 * @param aad               The additional authenticated data (AAD),
	 *                          {@code null} if none.
	 */
	public JWEObjectJSON(final JWEHeader header,
		             final Payload payload,
		             final UnprotectedHeader unprotectedHeader,
		             final byte[] aad) {

		super(payload);

		if (header == null) {
			throw new IllegalArgumentException("The JWE protected header must not be null");
		}
		this.header = header;

		if (payload == null) {
			throw new IllegalArgumentException("The payload must not be null");
		}
		setPayload(payload);

		this.unprotectedHeader = unprotectedHeader;
		this.aad = aad;
		this.cipherText = null;
		this.state = State.UNENCRYPTED;
	}


	/**
	 * Creates a new encrypted JSON Web Encryption (JWE) object. The state
	 * will be {@link State#ENCRYPTED encrypted}.
	 *
	 * @param header            The JWE protected header. Must not be
	 *                          {@code null}.
	 * @param cipherText        The cipher text. Must not be {@code null}.
	 * @param iv                The initialisation vector, empty or
	 *                          {@code null} if none.
	 * @param authTag           The authentication tag, empty or
	 *                          {@code null} if none.
	 * @param recipients        The recipients list. Must not be
	 *                          {@code null}.
	 * @param unprotectedHeader The shared unprotected header, empty or
	 *                          {@code null} if none.
	 * @param aad               The additional authenticated data. Must not
	 *                          be {@code null}.
	 *
	 */
	public JWEObjectJSON(final JWEHeader header,
		             final Base64URL cipherText,
		             final Base64URL iv,
		             final Base64URL authTag,
		             final List<Recipient> recipients,
		             final UnprotectedHeader unprotectedHeader,
		             final byte[] aad) {

		super(null); // Payload not decrypted yet, must be null

		if (header == null) {
			throw new IllegalArgumentException("The JWE protected header must not be null");
		}

		if (cipherText == null) {
			throw new IllegalArgumentException("The cipher text must not be null");
		}

		this.header = header;
		this.recipients.addAll(recipients);
		this.unprotectedHeader = unprotectedHeader;
		this.aad = aad;
		this.iv = iv;
		this.cipherText = cipherText;
		this.authTag = authTag;

		state = State.ENCRYPTED; // but not decrypted yet!
	}


	/**
	 * Returns the JWE protected header of this JWE object.
	 *
	 * @return The JWE protected header.
	 */
	public JWEHeader getHeader() {
		return header;
	}


	/**
	 * Returns the shared unprotected header of this JWE object.
	 *
	 * @return The shared unprotected header, empty or {@code null} if
	 *         none.
	 */
	public UnprotectedHeader getUnprotectedHeader() {
		return unprotectedHeader;
	}


	/**
	 * Returns the encrypted key of this JWE object.
	 *
	 * @return The encrypted key, {@code null} not applicable or the JWE
	 *         object has not been encrypted yet.
	 */
	public Base64URL getEncryptedKey() {
		if (recipients.isEmpty()) {
			return null;
		} else if (recipients.size() == 1) {
			return recipients.get(0).getEncryptedKey();
		}
		List<Object> recipientsList = JSONArrayUtils.newJSONArray();
		for (Recipient recipient : recipients) {
			recipientsList.add(recipient.toJSONObject());
		}
		Map<String, Object> recipientsMap = JSONObjectUtils.newJSONObject();
		recipientsMap.put("recipients", recipientsList);
		return Base64URL.encode(JSONObjectUtils.toJSONString(recipientsMap));
	}


	/**
	 * Returns the initialisation vector (IV) of this JWE object.
	 *
	 * @return The initialisation vector (IV), {@code null} if not
	 *         applicable or the JWE object has not been encrypted yet.
	 */
	public Base64URL getIV() {
		return iv;
	}


	/**
	 * Returns the cipher text of this JWE object.
	 *
	 * @return The cipher text, {@code null} if the JWE object has not been
	 *         encrypted yet.
	 */
	public Base64URL getCipherText() {
		return cipherText;
	}


	/**
	 * Returns the authentication tag of this JWE object.
	 *
	 * @return The authentication tag, {@code null} if not applicable or
	 *         the JWE object has not been encrypted yet.
	 */
	public Base64URL getAuthTag() {
		return authTag;
	}


	/**
	 * Returns the Additional Authenticated Data (AAD) of this JWE object.
	 *
	 * @return The Additional Authenticated Data (AAD).
	 */
	public byte[] getAAD() {
		StringBuilder aadSB = new StringBuilder(header.toBase64URL().toString());
		if (aad != null && aad.length > 0) {
			aadSB.append(".").append(new String(aad, StandardCharsets.US_ASCII));
		}
		return aadSB.toString().getBytes(StandardCharsets.US_ASCII);
	}


	/**
	 * Returns the recipients list of the JWE object.
	 *
	 * @return The recipients list.
	 */
	public List<Recipient> getRecipients() {
		return Collections.unmodifiableList(recipients);
	}


	/**
	 * Returns the state of this JWE object.
	 *
	 * @return The state.
	 */
	public State getState() {
		return state;
	}


	/**
	 * Ensures the current state is {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @throws IllegalStateException If the current state is not 
	 *                               unencrypted.
	 */
	private void ensureUnencryptedState() {
		if (state != State.UNENCRYPTED) {
			throw new IllegalStateException("The JWE object must be in an unencrypted state");
		}
	}


	/**
	 * Ensures the current state is {@link State#ENCRYPTED encrypted}.
	 *
	 * @throws IllegalStateException If the current state is not encrypted.
	 */
	private void ensureEncryptedState() {
		if (state != State.ENCRYPTED) {
			throw new IllegalStateException("The JWE object must be in an encrypted state");
		}
	}


	/**
	 * Ensures the current state is {@link State#ENCRYPTED encrypted} or
	 * {@link State#DECRYPTED decrypted}.
	 *
	 * @throws IllegalStateException If the current state is not encrypted
	 *                               or decrypted.
	 */
	private void ensureEncryptedOrDecryptedState() {
		if (state != State.ENCRYPTED && state != State.DECRYPTED) {
			throw new IllegalStateException("The JWE object must be in an encrypted or decrypted state");
		}
	}


	/**
	 * Ensures the specified JWE encrypter supports the algorithms of this
	 * JWE object.
	 *
	 * @throws JOSEException If the JWE algorithms are not supported.
	 */
	private void ensureJWEEncrypterSupport(final JWEEncrypter encrypter)
		throws JOSEException {

		if (! encrypter.supportedJWEAlgorithms().contains(getHeader().getAlgorithm())) {
			throw new JOSEException("The " + getHeader().getAlgorithm() +
						" algorithm is not supported by the JWE encrypter: Supported algorithms: " + encrypter.supportedJWEAlgorithms());
		}

		if (! encrypter.supportedEncryptionMethods().contains(getHeader().getEncryptionMethod())) {
			throw new JOSEException("The " + getHeader().getEncryptionMethod() +
						" encryption method or key size is not supported by the JWE encrypter: Supported methods: " + encrypter.supportedEncryptionMethods());
		}
	}


	/**
	 * Encrypts this JWE object with the specified encrypter. The JWE
	 * object must be in an {@link State#UNENCRYPTED unencrypted} state.
	 *
	 * @param encrypter The JWE encrypter. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWE object is not in an
	 *                               {@link State#UNENCRYPTED unencrypted
	 *                               state}.
	 * @throws JOSEException         If the JWE object couldn't be
	 *                               encrypted.
	 */
	public synchronized void encrypt(final JWEEncrypter encrypter)
		throws JOSEException {

		ensureUnencryptedState();

		ensureJWEEncrypterSupport(encrypter);

		JWECryptoParts parts;

		JWEHeader jweJoinedHeader = getHeader();
		try {
			jweJoinedHeader = (JWEHeader) getHeader().join(unprotectedHeader);
			parts = encrypter.encrypt(jweJoinedHeader, getPayload().toBytes(), getAAD());
		} catch (JOSEException e) {
			throw e;
		} catch (Exception e) {
			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		Base64URL encryptedKey = parts.getEncryptedKey();
		try {
			for (Map<String, Object> recipientMap : JSONObjectUtils.getJSONObjectArray((JSONObjectUtils.parse(encryptedKey.decodeToString())), "recipients")) {
				recipients.add(Recipient.parse(recipientMap));
			}
		} catch (Exception e) {
			Map<String, Object> recipientHeader = parts.getHeader().toJSONObject();
			for (String param : jweJoinedHeader.getIncludedParams()) {
				if (recipientHeader.containsKey(param)) {
					recipientHeader.remove(param);
				}
			}
			try {
				recipients.add(new Recipient(UnprotectedHeader.parse(recipientHeader), encryptedKey));
			} catch (Exception ex) {
				throw new JOSEException(ex.getMessage(), ex);
			}
		}
		iv = parts.getInitializationVector();
		cipherText = parts.getCipherText();
		authTag = parts.getAuthenticationTag();

		state = State.ENCRYPTED;
	}


	/**
	 * Decrypts this JWE object with the specified decrypter. The JWE
	 * object must be in a {@link State#ENCRYPTED encrypted} state.
	 *
	 * @param decrypter The JWE decrypter. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWE object is not in an
	 *                               {@link State#ENCRYPTED encrypted
	 *                               state}.
	 * @throws JOSEException         If the JWE object couldn't be
	 *                               decrypted.
	 */
	public synchronized void decrypt(final JWEDecrypter decrypter)
		throws JOSEException {

		ensureEncryptedState();

		try {
			setPayload(new Payload(decrypter.decrypt(getHeader(),
					       getEncryptedKey(),
					       getIV(),
					       getCipherText(),
					       getAuthTag(),
					       getAAD())));
		} catch (JOSEException e) {
			throw e;
		} catch (Exception e) {
			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		state = State.DECRYPTED;
	}


	/**
	 * Returns the JSON object with the common members in general and
	 * flattened JWE JSON serialisation.
	 */
	private Map<String,Object> toBaseJSONObject() {
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("protected", header.toBase64URL().toString());
		if (aad != null) {
			jsonObject.put("aad", new String(aad, StandardCharsets.US_ASCII));
		}
		jsonObject.put("ciphertext", cipherText.toString());
		jsonObject.put("iv", iv.toString());
		jsonObject.put("tag", authTag.toString());
		return jsonObject;
	}


	@Override
	public Map<String, Object> toGeneralJSONObject() {

		ensureEncryptedOrDecryptedState();

		if (recipients.isEmpty() || (recipients.get(0).getUnprotectedHeader() == null && recipients.get(0).getEncryptedKey() == null)) {
			throw new IllegalStateException("The general JWE JSON serialization requires at least one recipient");
		}

		Map<String, Object> jsonObject = toBaseJSONObject();

		if (unprotectedHeader != null) {
			jsonObject.put("unprotected", unprotectedHeader.toJSONObject());
		}

		List<Object> recipientsJSONArray = JSONArrayUtils.newJSONArray();

		for (Recipient recipient: recipients) {
			Map<String, Object> recipientJSONObject = recipient.toJSONObject();
			recipientsJSONArray.add(recipientJSONObject);
		}

		jsonObject.put("recipients", recipientsJSONArray);
		return jsonObject;
	}


	@Override
	public Map<String, Object> toFlattenedJSONObject() {

		ensureEncryptedOrDecryptedState();

		if (recipients.size() != 1) {
			throw new IllegalStateException("The flattened JWE JSON serialization requires exactly one recipient");
		}

		Map<String, Object> jsonObject = toBaseJSONObject();

		Map<String, Object> recipientHeader = JSONObjectUtils.newJSONObject();
		if (recipients.get(0).getUnprotectedHeader() != null) {
			recipientHeader.putAll(recipients.get(0).getUnprotectedHeader().toJSONObject());
		}
		if (unprotectedHeader != null) {
			recipientHeader.putAll(unprotectedHeader.toJSONObject());
		}
		if (recipientHeader.size() > 0) {
			jsonObject.put("unprotected", recipientHeader);
		}
		if (recipients.get(0).getEncryptedKey() != null) {
			jsonObject.put("encrypted_key", recipients.get(0).getEncryptedKey().toString());
		}
		return jsonObject;
	}


	@Override
	public String serializeGeneral() {
		return JSONObjectUtils.toJSONString(toGeneralJSONObject());
	}


	@Override
	public String serializeFlattened() {
		return JSONObjectUtils.toJSONString(toFlattenedJSONObject());
	}


	/**
	 * Parses a JWE object from the specified JSON object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWE secured object.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        JWE secured object.
	 */
	public static JWEObjectJSON parse(final Map<String, Object> jsonObject)
		throws ParseException {

		if (jsonObject == null) {
			throw new IllegalArgumentException("The JSON object must not be null");
		}

		if (!jsonObject.containsKey("protected")) {
			throw new ParseException("The JWE protected header mast be present", 0);
		}

		List<Recipient> recipientList = new LinkedList<>();
		final JWEHeader jweHeader = JWEHeader.parse(JSONObjectUtils.getBase64URL(jsonObject, "protected"));
		final UnprotectedHeader unprotected = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(jsonObject, "unprotected"));
		final Base64URL cipherText = JSONObjectUtils.getBase64URL(jsonObject, "ciphertext");
		final Base64URL iv = JSONObjectUtils.getBase64URL(jsonObject, "iv");
		final Base64URL authTag = JSONObjectUtils.getBase64URL(jsonObject, "tag");
		final Base64URL aad = JSONObjectUtils.getBase64URL(jsonObject, "aad");
		final JWEHeader jweJoinedHeader = (JWEHeader) jweHeader.join(unprotected);

		if (jsonObject.containsKey("recipients")) {
			Map<String, Object>[] recipients = JSONObjectUtils.getJSONObjectArray(jsonObject, "recipients");
			if (recipients == null || recipients.length == 0) {
				throw new ParseException("The \"recipients\" member must be present in general JSON Serialization", 0);
			}
			for (Map<String, Object> recipientJSONObject: recipients) {
				Recipient recipient = Recipient.parse(recipientJSONObject);
				try {
					HeaderValidation.ensureDisjoint(jweJoinedHeader, recipient.getUnprotectedHeader());
				} catch (IllegalHeaderException e) {
					throw new ParseException(e.getMessage(), 0);
				}
				recipientList.add(recipient);
			}
		} else {
			Base64URL encryptedKey = JSONObjectUtils.getBase64URL(jsonObject, "encrypted_key");
			recipientList.add(new Recipient(null, encryptedKey));
		}

		return new JWEObjectJSON(jweHeader, cipherText, iv, authTag, recipientList, unprotected, aad == null ? null : aad.toString().getBytes(StandardCharsets.US_ASCII));
	}


	/**
	 * Parses a JWE object from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The JWE object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a JWE
	 *                        object.
	 */
	public static JWEObjectJSON parse(final String json)
		throws ParseException {

		if (json == null) {
			throw new IllegalArgumentException("The JSON object string must not be null");
		}

		return parse(JSONObjectUtils.parse(json));
	}
}