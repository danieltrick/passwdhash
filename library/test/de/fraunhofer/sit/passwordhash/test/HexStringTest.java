package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class HexStringTest {

	private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
	
	@Test
	public void testBytesToHex() {
		assertEquals("", bytesToHex(new byte[0]));

		for (int value = 0; value < 256; ++value) {
			final String expected = Character.toString(HEX_CHARS[value / 16]) + Character.toString(HEX_CHARS[value % 16]);
			assertEquals(new String(expected), bytesToHex(new byte[] { (byte)value }));
		}

		assertEquals("0123456789ABCDEF", bytesToHex(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }));
		assertEquals("FEDCBA9876543210", bytesToHex(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }));
	}

	@Test
	public void testHexToBytes() {
		assertArrayEquals(new byte[0], hexToBytes(""));
	
		for (int value = 0; value < 256; ++value) {
			final String hexString = Character.toString(HEX_CHARS[value / 16]) + Character.toString(HEX_CHARS[value % 16]);
			assertArrayEquals(new byte[] { (byte)value }, hexToBytes(hexString));
		}

		assertArrayEquals(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }, hexToBytes("0123456789ABCDEF"));
		assertArrayEquals(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }, hexToBytes("FEDCBA9876543210"));
	}
}
