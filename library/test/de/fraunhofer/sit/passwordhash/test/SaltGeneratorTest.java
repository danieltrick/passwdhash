package de.fraunhofer.sit.passwordhash.test;

import java.nio.ByteBuffer;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.impl.SaltGenerator;

public class SaltGeneratorTest {

	@Test
	public void testUniqueness() {
		final SortedSet<ByteBuffer> set = new TreeSet<ByteBuffer>();
		for (int i = 0; i < 100000; ++i) {
			final byte[] salt = SaltGenerator.generateSalt(16);
			Assert.assertTrue(set.add(ByteBuffer.wrap(salt).asReadOnlyBuffer()));
		}
	}

	@Test
	public void testLength() {
		for (int len = 8; len <= 24; ++len) {
			final byte[] salt = SaltGenerator.generateSalt(len);
			final int remainder = len % 4;
			final int expectedLen = (remainder == 0) ? len : (len + (4 - remainder));
			Assert.assertEquals(expectedLen, salt.length);
		}
	}

	@Test
	public void testInvalidArgs() {
		Assert.assertThrows(IllegalArgumentException.class, () -> SaltGenerator.generateSalt(0));
	}
}
