package de.fraunhofer.sit.passwordhash.test;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.utils.Utilities;

public class UtilitiesTest {

	private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
	
	@Test
	public void testBytesToHex() {
		Assert.assertEquals("", Utilities.bytesToHex(new byte[0]));

		for (int value = 0; value < 256; ++value) {
			final String expected = Character.toString(HEX_CHARS[value / 16]) + Character.toString(HEX_CHARS[value % 16]);
			Assert.assertEquals(new String(expected), Utilities.bytesToHex(new byte[] { (byte)value }));
		}

		Assert.assertEquals("0123456789ABCDEF", Utilities.bytesToHex(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }));
		Assert.assertEquals("FEDCBA9876543210", Utilities.bytesToHex(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }));
	}

	@Test
	public void testHexToBytes() {
		Assert.assertArrayEquals(new byte[0], Utilities.hexToBytes(""));
	
		for (int value = 0; value < 256; ++value) {
			final String hexString = Character.toString(HEX_CHARS[value / 16]) + Character.toString(HEX_CHARS[value % 16]);
			Assert.assertArrayEquals(new byte[] { (byte)value }, Utilities.hexToBytes(hexString));
		}

		Assert.assertArrayEquals(new byte[] { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF }, Utilities.hexToBytes("0123456789ABCDEF"));
		Assert.assertArrayEquals(new byte[] { (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10 }, Utilities.hexToBytes("FEDCBA9876543210"));
	}
}
