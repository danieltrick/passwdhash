package de.fraunhofer.sit.passwordhash.impl;

import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.utils.KeyHolder;
import de.fraunhofer.sit.passwordhash.utils.PrimeFinder;
import de.fraunhofer.sit.passwordhash.utils.SaltGenerator;

public class PasswordHasher_ChaCha20 implements PasswordHasher {

	private static final String ALGORITHM_NAME_CIPHER = "ChaCha20/None/NoPadding";

	private static final int BLOCK_SIZE = 32, SALT_SIZE = 12, DEFAULT_ROUNDS = 1499977;

	private static final class ParameterSpecHolder {
		static final String CLASS_NAME = "javax.crypto.spec.ChaCha20ParameterSpec";

		static final Constructor<?> CONSTRUCTOR;
		static {
			try {
				CONSTRUCTOR = Class.forName(CLASS_NAME).getConstructor(byte[].class, int.class);
			} catch (final Exception e) {
				throw new Error("failed to initialize parameter spec constructor!", e);
			}			
		}

		public static AlgorithmParameterSpec newInstance(final byte[] nonce, final int counter) {
			try {
				return (AlgorithmParameterSpec) CONSTRUCTOR.newInstance(nonce, counter);
			} catch (Exception e) {
				throw new RuntimeException("failed to create instance!", e);
			}
		}
	}

	private final byte[] INITIALIZER_0 = hexToBytes("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"); // the first 256 bits of 'pi'
	private final byte[] INITIALIZER_1 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000"); // zero bits

	private final long rounds;

	private final KeyHolder key0 = new KeyHolder(BLOCK_SIZE);
	private final KeyHolder key1 = new KeyHolder(BLOCK_SIZE);

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

		System.arraycopy(INITIALIZER_0, 0, key0.bytes, 0, BLOCK_SIZE);
		System.arraycopy(INITIALIZER_1, 0, key1.bytes, 0, BLOCK_SIZE);

		final AlgorithmParameterSpec param0 = initParameters(salt, (byte) 0xAA);
		final AlgorithmParameterSpec param1 = initParameters(salt, (byte) 0x55);

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
		cipher.doFinal(INITIALIZER_1, 0, BLOCK_SIZE, key0.bytes, 0);
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

	private AlgorithmParameterSpec initParameters(final byte[] salt, final byte tweak) {
		assert (salt != null) && (salt.length == SALT_SIZE) && (tweak != 0);

		final byte[] nonce = salt.clone();
		for (int iPos = 0; iPos < SALT_SIZE; ++iPos) {
			nonce[iPos] ^= tweak;
		}

		try {
			return (AlgorithmParameterSpec) ParameterSpecHolder.newInstance(nonce, 1);
		} catch (final Exception e) {
			throw new Error("failed to create parameter spec instance!", e);
		} finally {
			Arrays.fill(nonce,(byte) 0);
		}
	}
}
