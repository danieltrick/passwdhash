package de.fraunhofer.sit.passwordhash.impl;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

import de.fraunhofer.sit.passwordhash.PasswordHasher;

public class PasswordHasher_ChaCha20 implements PasswordHasher {

	private static final String ALGORITHM_NAME_CIPHER = "ChaCha20/None/NoPadding";

	private static final int BLOCK_SIZE = 32, SALT_SIZE = 12, DEFAULT_ROUNDS = 2499997;

	private static final byte[] INITIALIZER = {
		(byte) 0xB7, (byte) 0xE1, (byte) 0x51, (byte) 0x62, (byte) 0x8A, (byte) 0xED, (byte) 0x2A, (byte) 0x6A,
		(byte) 0xBF, (byte) 0x71, (byte) 0x58, (byte) 0x80, (byte) 0x9C, (byte) 0xF4, (byte) 0xF3, (byte) 0xC7,
		(byte) 0x62, (byte) 0xE7, (byte) 0x16, (byte) 0x0F, (byte) 0x38, (byte) 0xB4, (byte) 0xDA, (byte) 0x56,
		(byte) 0xA7, (byte) 0x84, (byte) 0xD9, (byte) 0x04, (byte) 0x51, (byte) 0x90, (byte) 0xCF, (byte) 0xEF
	};

	private final long rounds;

	private final KeyHolder key = new KeyHolder();

	private final byte[] buffer = new byte[BLOCK_SIZE];

	private final Cipher cipher;

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

		System.arraycopy(INITIALIZER, 0, key.bytes, 0, BLOCK_SIZE);
		final byte[] padded = PaddingHelper.addPadding(BLOCK_SIZE, data);

		try {
			processBlock(longToBytes(rounds), 0, salt);
			for (long round = 0L; round < rounds; ++round) {
				invertState();
				for (int offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
					processBlock(padded, offset, salt);
				}
			}
			return key.bytes.clone();
		} catch (final GeneralSecurityException e) {
			throw new RuntimeException("failed to compute hash value for password!", e);
		} finally {
			key.destroy();
			Arrays.fill(padded, (byte) 0);
			Arrays.fill(buffer, (byte) 0);
		}
	}

	@Override
	public byte[] generateSalt() {
		return SaltGenerator.generateSalt(SALT_SIZE);
	};

	private void processBlock(final byte[] data, final int dataOffset, final byte[] salt) throws GeneralSecurityException {
		cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(salt, 1));
		cipher.doFinal(data, dataOffset, BLOCK_SIZE, buffer, 0);

		buffer[0] |= 0x40;

		for (int iPos = 0; iPos < BLOCK_SIZE; ++iPos) {
			key.bytes[iPos] ^= buffer[iPos];
		}
	}

	private void invertState() {
		for (int iPos = 0; iPos < BLOCK_SIZE; ++iPos) {
			key.bytes[iPos] ^= 0xA5;
			key.bytes[iPos] ^= 0xA5;
		}
	}

	private static byte[] longToBytes(long val) {
		final ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
		for (int step = 0; step < 2; ++step, val = ~val) {
			buffer.putLong(Long.BYTES, val);
			buffer.putLong(Long.BYTES, mix64(val));
		}
		return buffer.array();
	}

	private static long mix64(long val) {
		val = (val ^ (val >>> 30)) * 0xBF58476D1CE4E5B9L;
		val = (val ^ (val >>> 27)) * 0x94D049BB133111EBL;
		return val ^ (val >>> 31);
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
			return bytes.clone();
		}
		
		@Override
		public void destroy() {
			Arrays.fill(bytes, (byte) 0);
		}
	}
}
