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

		for (int valueHi = 0; valueHi < 256; ++valueHi) {
			for (int valueLo = 0; valueLo < 256; ++valueLo) {
				final String expected =
					Character.toString(HEX_CHARS[valueHi / 16]) + Character.toString(HEX_CHARS[valueHi % 16]) +
					Character.toString(HEX_CHARS[valueLo / 16]) + Character.toString(HEX_CHARS[valueLo % 16]);
				System.out.println(expected);
				assertEquals(expected, bytesToHex(new byte[] { (byte)valueHi, (byte)valueLo }));
			}
		}

		assertEquals("0000000000000000", bytesToHex(new byte[] { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 }));
		assertEquals("FFFFFFFFFFFFFFFF", bytesToHex(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF }));
		assertEquals("5A5A5A5A5A5A5A5A", bytesToHex(new byte[] { (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A }));
		assertEquals("A5A5A5A5A5A5A5A5", bytesToHex(new byte[] { (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5 }));
		assertEquals("0123456789ABCDEF", bytesToHex(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }));
		assertEquals("FEDCBA9876543210", bytesToHex(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }));
	}

	@Test
	public void testHexToBytes() {
		assertArrayEquals(new byte[0], hexToBytes(""));
	
		for (int valueHi = 0; valueHi < 256; ++valueHi) {
			for (int valueLo = 0; valueLo < 256; ++valueLo) {
				final String hexString =
					Character.toString(HEX_CHARS[valueHi / 16]) + Character.toString(HEX_CHARS[valueHi % 16]) +
					Character.toString(HEX_CHARS[valueLo / 16]) + Character.toString(HEX_CHARS[valueLo % 16]);
				System.out.println(hexString);
				assertArrayEquals(new byte[] { (byte)valueHi, (byte)valueLo }, hexToBytes(hexString));
			}
		}

		assertArrayEquals(new byte[] { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 }, hexToBytes("0000000000000000"));
		assertArrayEquals(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF }, hexToBytes("FFFFFFFFFFFFFFFF"));
		assertArrayEquals(new byte[] { (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A, (byte)0x5A }, hexToBytes("5A5A5A5A5A5A5A5A"));
		assertArrayEquals(new byte[] { (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5, (byte)0xA5 }, hexToBytes("A5A5A5A5A5A5A5A5"));
		assertArrayEquals(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }, hexToBytes("0123456789ABCDEF"));
		assertArrayEquals(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }, hexToBytes("FEDCBA9876543210"));
	}
}
