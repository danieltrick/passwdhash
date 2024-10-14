package de.fraunhofer.sit.passwordhash.hasher;

import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import de.fraunhofer.sit.passwordhash.hasher.impl.PasswordHasher_AES;

public class PasswordManager {

	private static final PasswordMode DEFAULT = PasswordMode.AES;

	private static final class Base64Holder {
		static final Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
		static final Decoder DECODER = Base64.getUrlDecoder();
	}

	private static final String SEPARATOR = ":"; 

	private PasswordManager() {
		throw new IllegalAccessError();
	}

	public static String create(final String password) {
		return create(password, DEFAULT);
	}

	public static String create(final String password, final PasswordMode mode) {
		if (password == null) {
			throw new NullPointerException("Password must not be null!");
		}

		final PasswordHasher hasher = getInstance(mode);
		final byte[] salt = hasher.generateSalt();
		final byte[] hash = hasher.compute(password, salt);
		
		final StringBuilder builder = new StringBuilder();

		builder.append(Long.toString(mode.id));
		builder.append(SEPARATOR);
		builder.append(Base64Holder.ENCODER.encodeToString(salt));
		builder.append(SEPARATOR);
		builder.append(Base64Holder.ENCODER.encodeToString(hash));

		return builder.toString();
	}

	public static boolean verify(final String password, final String encodedHash) {
		final StringTokenizer tokenizer = new StringTokenizer(encodedHash, SEPARATOR);

		final PasswordMode mode;
		final byte[] salt, hash; 
		try {
			mode = PasswordMode.parseId(Long.parseLong(tokenizer.nextToken()));
			salt = Base64Holder.DECODER.decode(tokenizer.nextToken());
			hash = Base64Holder.DECODER.decode(tokenizer.nextToken());
		} catch (final NoSuchElementException | IllegalArgumentException e) {
			return false;
		}

		final PasswordHasher hasher = getInstance(mode);

		final byte[] computedHash;
		try {
			computedHash = hasher.compute(password, salt);
		} catch (final IllegalArgumentException e) {
			return false;
		}

		return Arrays.equals(computedHash, hash);
	}

	public static PasswordHasher getInstance(final PasswordMode mode) {
		return getInstance(mode, -1L);
	}

	public static PasswordHasher getInstance(final PasswordMode mode, final long rounds) {
		switch (mode) {
		case AES:
			return new PasswordHasher_AES(rounds);
		default:
			throw new IllegalArgumentException("Unsupported password mode specified!");
		}
	}
}
