package de.fraunhofer.sit.passwordhash.impl;

import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.utils.KeyHolder;
import de.fraunhofer.sit.passwordhash.utils.PrimeFinder;
import de.fraunhofer.sit.passwordhash.utils.SaltGenerator;

public class PasswordHasher_AES implements PasswordHasher {

	private static final String ALGORITHM_NAME_CIPHER = "AES/ECB/NoPadding";

	private static final int BLOCK_SIZE = 16, KEY_SIZE = 2 * BLOCK_SIZE, DEFAULT_ROUNDS = 499979;

	private final byte[] INITIALIZER_0 = hexToBytes("B7E151628AED2A6ABF7158809CF4F3C7"); // the 1st 128 bits of 'e'
	private final byte[] INITIALIZER_1 = hexToBytes("62E7160F38B4DA56A784D9045190CFEF"); // the 2nd 128 bits of 'e'

	private final long rounds;

	private final byte[] state0 = new byte[BLOCK_SIZE];
	private final byte[] state1 = new byte[BLOCK_SIZE];

	private final KeyHolder key0 = new KeyHolder(KEY_SIZE);
	private final KeyHolder key1 = new KeyHolder(KEY_SIZE);

	private final Cipher cipher;

	public PasswordHasher_AES() {
		this(DEFAULT_ROUNDS);
	}

	public PasswordHasher_AES(final long rounds) {
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

		if (salt.length != BLOCK_SIZE) {
			throw new IllegalArgumentException("salt has an invalid size! (must be 16 bytes)");
		}

		System.arraycopy(INITIALIZER_0, 0, state0, 0, BLOCK_SIZE);
		System.arraycopy(INITIALIZER_1, 0, state1, 0, BLOCK_SIZE);

		final byte[] digest = new byte[KEY_SIZE];
		final byte[] padded = PaddingHelper.addPadding(BLOCK_SIZE, data);

		try {
			processBlock(longToBytes(rounds), 0);
			processBlock(salt, 0);
			for (long round = 0L; round < rounds; ++round) {
				invertState();
				for (int offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
					processBlock(padded, offset);
				}
			}
			concat(digest, state0, state1);
		} catch (final GeneralSecurityException e) {
			throw new RuntimeException("failed to compute hash value for password!", e);
		} finally {
			key0.destroy();
			key1.destroy();
			Arrays.fill(padded, (byte) 0);
			Arrays.fill(state0, (byte) 0);
			Arrays.fill(state1, (byte) 0);
		}

		return digest;
	}

	@Override
	public byte[] generateSalt() {
		return SaltGenerator.generateSalt(BLOCK_SIZE);
	};

	private void processBlock(final byte[] data, final int dataOffset) throws GeneralSecurityException {
		concat(key0.bytes, state0, state1);
		concat(key1.bytes, state1, state0);

		key0.bytes[0] &= 0xBF;
		key1.bytes[0] |= 0x40;

		compressBlock(key0, state0, data, dataOffset);
		compressBlock(key1, state1, data, dataOffset);
	}

	private void compressBlock(final KeyHolder key, final byte[] stateOut, final byte[] data, final int dataOffset) throws GeneralSecurityException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipher.doFinal(data, dataOffset, BLOCK_SIZE, stateOut, 0);

		for (int iPos = 0; iPos < BLOCK_SIZE; ++iPos) {
			stateOut[iPos] ^= data[dataOffset + iPos];
		}
	}

	private void invertState() {
		for (int iPos = 0; iPos < BLOCK_SIZE; ++iPos) {
			state0[iPos] ^= 0xA5;
			state1[iPos] ^= 0xA5;
		}
	}

	private static void concat(final byte[] dst, final byte[] src0, final byte[] src1) {
		System.arraycopy(src0, 0, dst,          0, BLOCK_SIZE);
		System.arraycopy(src1, 0, dst, BLOCK_SIZE, BLOCK_SIZE);
	}

	private static byte[] longToBytes(final long val) {
		final ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
		return buffer
			.putLong(mix64(val ^ 0x5555555555555555L))
			.putLong(mix64(val ^ 0xAAAAAAAAAAAAAAAAL)).array();
	}

	private static long mix64(long val) {
		val = (val ^ (val >>> 30)) * 0xBF58476D1CE4E5B9L;
		val = (val ^ (val >>> 27)) * 0x94D049BB133111EBL;
		return val ^ (val >>> 31);
	}
}
