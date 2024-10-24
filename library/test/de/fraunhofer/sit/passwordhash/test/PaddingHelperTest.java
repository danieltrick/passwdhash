package de.fraunhofer.sit.passwordhash.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.impl.PaddingHelper;

public class PaddingHelperTest {

	private static final int BLOCK_SIZE = 16;
	
	@Test
	public void testPadding() {
		for (int length = 0; length <= 128; ++length) {
			for (int iteration = 0; iteration < 3; ++iteration) {
				final byte[] data = new byte[length];
				ThreadLocalRandom.current().nextBytes(data);

				final int expectedLength = nextMultiple(data.length);
				final byte[] expected = new byte[expectedLength];
				final int extraBytes = expected.length - data.length;

				for (int i = 0; i < expected.length; ++i) {
					expected[i] = (i < data.length) ? data[i] : (byte)extraBytes;
				}

				final byte[] padded = PaddingHelper.addPadding(BLOCK_SIZE, data);
				assertArrayEquals(expected, padded);
			}
		}
	}

	private static int nextMultiple(final int length) {
		int result = 0;
		while (result <= length) {
			result = Math.addExact(result, BLOCK_SIZE);
		}
		return result;
	}
}
