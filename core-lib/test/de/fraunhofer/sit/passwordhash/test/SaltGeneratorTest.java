package de.fraunhofer.sit.passwordhash.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.SortedSet;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.utils.SaltGenerator;

public class SaltGeneratorTest {

	@Test
	public void testUniqueness() {
		final SortedSet<String> saltSet = new TreeSet<String>();
		final Encoder base64encoder = Base64.getEncoder().withoutPadding();
		for (int i = 0; i < 10000; ++i) {
			final byte[] salt = SaltGenerator.generateSalt(12);
			final String encoded = base64encoder.encodeToString(salt);
			System.out.println(encoded);
			assertTrue(saltSet.add(encoded));
		}
	}

	@Test
	public void testLength() {
		for (int expectedLen = 12; expectedLen <= 24; ++expectedLen) {
			final byte[] generatedSalt = SaltGenerator.generateSalt(expectedLen);
			assertEquals(expectedLen, generatedSalt.length);
		}
	}

	@Test
	public void testInvalidArgs() {
		assertThrows(IllegalArgumentException.class, () -> SaltGenerator.generateSalt(0));
		assertThrows(IllegalArgumentException.class, () -> SaltGenerator.generateSalt(7));
	}
}
