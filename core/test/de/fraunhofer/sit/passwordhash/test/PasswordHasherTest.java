package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.fraunhofer.sit.passwordhash.PasswordHasher;

abstract class PasswordHasherTest {

	protected final String MESSAGE_EMPTY = "";
	protected final String MESSAGE_ST024 = "abc";
	protected final String MESSAGE_ST344 = "The quick brown fox jumps over the lazy dog";
	protected final String MESSAGE_ST352 = "The quick brown fox jumps over the lazy dog.";
	protected final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	protected final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	protected static void doTestHash(final PasswordHasher hasher, final String message, final byte[] salt, final byte[] expected) {
		assertNotNull(message);
		assertNotNull(salt);
		assertNotNull(expected);

		assertTrue(salt.length >= 12);
		assertTrue(expected.length == 32);

		final byte[] computed = hasher.compute(message, salt);
		System.out.printf("%s <-- \"%s\" (0x%s)%n", bytesToHex(computed), message, bytesToHex(salt));

		assertArrayEquals(expected, computed);
	}

}
