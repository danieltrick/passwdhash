package de.fraunhofer.sit.passwordhash.impl;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import de.fraunhofer.sit.passwordhash.PasswordHasher;

public class PasswordHasher_ChaCha20 implements PasswordHasher {

	private static final String ALGORITHM_NAME_CIPHER = "ChaCha20/None/NoPadding";

	private static final String PARAMETER_SPEC_CLASS = "javax.crypto.spec.ChaCha20ParameterSpec";

	private static final int BLOCK_SIZE = 32, SALT_SIZE = 12, DEFAULT_ROUNDS = 1499977;

	private static final byte[] INITIALIZER = {
		(byte) 0xB7, (byte) 0xE1, (byte) 0x51, (byte) 0x62, (byte) 0x8A, (byte) 0xED, (byte) 0x2A, (byte) 0x6A,
		(byte) 0xBF, (byte) 0x71, (byte) 0x58, (byte) 0x80, (byte) 0x9C, (byte) 0xF4, (byte) 0xF3, (byte) 0xC7,
		(byte) 0x62, (byte) 0xE7, (byte) 0x16, (byte) 0x0F, (byte) 0x38, (byte) 0xB4, (byte) 0xDA, (byte) 0x56,
		(byte) 0xA7, (byte) 0x84, (byte) 0xD9, (byte) 0x04, (byte) 0x51, (byte) 0x90, (byte) 0xCF, (byte) 0xEF
	};

	private final long rounds;

	private final KeyHolder key0 = new KeyHolder();
	private final KeyHolder key1 = new KeyHolder();

	private final Cipher cipher;

	private final Constructor<?> parameterSpecConstructor;

	public PasswordHasher_ChaCha20() {
		this(DEFAULT_ROUNDS);
	}

	public PasswordHasher_ChaCha20(final long rounds) {
		this.rounds = (rounds > 0) ? PrimeFinder.findPrime(Math.max(31L, rounds)) : DEFAULT_ROUNDS;

		try {
			cipher = Cipher.getInstance(ALGORITHM_NAME_CIPHER);
		} catch (final GeneralSecurityException e) {
			throw new Error("failed to create cipher instance!", e);
		}

		try {
			final Class<?> clazz = Class.forName(PARAMETER_SPEC_CLASS);
			parameterSpecConstructor = clazz.getConstructor(byte[].class, int.class);
		} catch (final Exception e) {
			throw new Error("failed to initialize parameter spec constructor!", e);
		}
	}

	@Override
	public byte[] compute(final String text, final byte[] salt) {
		if (text == null) {
			throw new NullPointerException("text to be hashed must not be null!");
		}

		return compute(text.getBytes(StandardCharsets.UTF_8), salt);
	}

	@Override
	public byte[] compute(final byte[] data, final byte[] salt) {
		if (data == null) {
			throw new NullPointerException("data to be hashed must not be null!");
		}

		if (salt == null) {
			throw new NullPointerException("salt value must not be null!");
		}

		if (salt.length != SALT_SIZE) {
			throw new IllegalArgumentException("salt has an invalid size! (must be 12 bytes)");
		}

		System.arraycopy(INITIALIZER, 0, key0.bytes, 0, BLOCK_SIZE);
		Arrays.fill(key1.bytes, (byte) 0);

		final AlgorithmParameterSpec param0 = initParameterSpec(salt, (byte) 0xAA);
		final AlgorithmParameterSpec param1 = initParameterSpec(salt, (byte) 0x55);

		final byte[] padded = PaddingHelper.addPadding(BLOCK_SIZE, data);

		try {
			processBlock(longToBytes(rounds), 0, param0, param1);
			for (long round = 0L; round < rounds; ++round) {
				invertKey();
				for (int offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
					processBlock(padded, offset, param0, param1);
				}
			}
			return key0.bytes.clone();
		} catch (final GeneralSecurityException e) {
			throw new RuntimeException("failed to compute hash value for password!", e);
		} finally {
			key0.destroy();
			key1.destroy();
			Arrays.fill(padded, (byte) 0);
		}
	}

	@Override
	public byte[] generateSalt() {
		return SaltGenerator.generateSalt(SALT_SIZE);
	};

	private void processBlock(final byte[] data, final int dataOffset, final AlgorithmParameterSpec param0, final AlgorithmParameterSpec param1) throws GeneralSecurityException {
		cipher.init(Cipher.ENCRYPT_MODE, key0, param0);
		cipher.doFinal(data, dataOffset, BLOCK_SIZE, key1.bytes, 0);

		cipher.init(Cipher.ENCRYPT_MODE, key1, param1);
		cipher.doFinal(data, dataOffset, BLOCK_SIZE, key0.bytes, 0);
	}

	private void invertKey() {
		for (int iPos = 0; iPos < BLOCK_SIZE; ++iPos) {
			key0.bytes[iPos] ^= 0xA5;
		}
	}

	private static byte[] longToBytes(final long val) {
		final ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
		return buffer
			.putLong(mix64(val ^ 0x5555555555555555L))
			.putLong(mix64(val ^ 0x5A5A5A5A5A5A5A5AL))
			.putLong(mix64(val ^ 0xA5A5A5A5A5A5A5A5L))
			.putLong(mix64(val ^ 0xAAAAAAAAAAAAAAAAL)).array();
	}

	private static long mix64(long val) {
		val = (val ^ (val >>> 30)) * 0xBF58476D1CE4E5B9L;
		val = (val ^ (val >>> 27)) * 0x94D049BB133111EBL;
		return val ^ (val >>> 31);
	}

	private AlgorithmParameterSpec initParameterSpec(final byte[] salt, final byte tweak) {
		final byte[] nonce = salt.clone();
		for (int iPos = 0; iPos < SALT_SIZE; ++iPos) {
			nonce[iPos] ^= tweak;
		}

		try {
			return (AlgorithmParameterSpec) parameterSpecConstructor.newInstance(nonce, 1);
		} catch (final Exception e) {
			throw new Error("failed to create parameter spec instance!", e);
		} finally {
			Arrays.fill(nonce,(byte) 0);
		}
	}

	@SuppressWarnings("serial")
	private final class KeyHolder implements SecretKey {
		final byte[] bytes = new byte[BLOCK_SIZE];

		@Override
		public String getAlgorithm() {
			return "ChaCha20";
		}

		@Override
		public String getFormat() {
			return "RAW";
		}

		@Override
		public byte[] getEncoded() {
			return bytes;
		}

		@Override
		public void destroy() {
			Arrays.fill(bytes, (byte) 0);
		}
	}
}
