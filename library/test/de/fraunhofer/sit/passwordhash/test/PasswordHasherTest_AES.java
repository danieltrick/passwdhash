package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;

public class PasswordHasherTest_AES {

	private static final byte[] SALT_0 = hexToBytes("00000000000000000000000000000000");
	private static final byte[] SALT_1 = hexToBytes("55555555555555555555555555555555");
	private static final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	private static final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	private static final String MESSAGE_EMPTY = "";
	private static final String MESSAGE_ST024 = "abc";
	private static final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private static final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	private static final byte[] EXPECTED_EMPTY_0 = hexToBytes("41C42B45921267761293ACC97310E425DCFDC92849D02127D4563040F89007E6");
	private static final byte[] EXPECTED_EMPTY_1 = hexToBytes("63BB2F872ECF2DA3231A0874218476D6F5AAF7879D8E75423BFDE846F26D0FB8");
	private static final byte[] EXPECTED_EMPTY_2 = hexToBytes("388A30F3770B481300F312867597F493C09D93823C05E32F8044453DE00BD716");
	private static final byte[] EXPECTED_EMPTY_3 = hexToBytes("5FB6EE365152C67693BBDEFB5AF53D778C5F5DC9D89D06A7C1BF81A86A2CE677");

	private static final byte[] EXPECTED_ST024_0 = hexToBytes("8D3307174F0F65EAD78FC03E8FAFED37F21662C462670F9A0358A0244C8DAD26");
	private static final byte[] EXPECTED_ST024_1 = hexToBytes("AD32F2FDE8C16754EA733CCF0CC63D9970DDB68074F6EA2C44072135E8523310");
	private static final byte[] EXPECTED_ST024_2 = hexToBytes("CCBCB114C43DEE9E6699BE280011A7E206B072ABD2A999D6C5AF0B3290660556");
	private static final byte[] EXPECTED_ST024_3 = hexToBytes("2FFF23BAC4D4E88E33A836499FEE72B867A5D1D6B649BB95D21832E52A256B3E");

	private static final byte[] EXPECTED_ST448_0 = hexToBytes("8734258A294353384F7339E307E28059EB9B82C2601BCC612C61459FBD56E639");
	private static final byte[] EXPECTED_ST448_1 = hexToBytes("4EDF4BD1E39B08ED756B81676A4B2D71C144F11C2FE1F32318A71B549E188045");
	private static final byte[] EXPECTED_ST448_2 = hexToBytes("7B88A347C18B53FAEBDBF3F9FA8A8970CCF6F0856FE45252AE95D211D84E2278");
	private static final byte[] EXPECTED_ST448_3 = hexToBytes("AAC8489B8E417A7ED1AF4494762B93FD9F799D207A046847006C331871493D68");

	private static final byte[] EXPECTED_ST896_0 = hexToBytes("EA82671558534508FCD7F3809F5416B13131F59549EE72D566A6BF53DC290CC7");
	private static final byte[] EXPECTED_ST896_1 = hexToBytes("6B3F5AB5245D3CC2CEE12373C2F4163046A25CF170BD2036349BD6E82287B19C");
	private static final byte[] EXPECTED_ST896_2 = hexToBytes("452226A930EAD214D13983CF84DBAD44216FF60556EE56E5177F69A6E5527F2D");
	private static final byte[] EXPECTED_ST896_3 = hexToBytes("D48EE6ED756CD48198DF39DB76F914B27922D520922B34615FEEC0FC5A7A0CEF");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
			doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
			doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
			doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
			doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
			doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
			doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
			doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
			doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
			doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		Assert.assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	private static void doTestHash(final PasswordHasher hasher, final String message, final byte[] salt, final byte[] expected) {
		Assert.assertNotNull(message);
		Assert.assertNotNull(salt);
		Assert.assertNotNull(expected);

		Assert.assertTrue(salt.length > 0);
		Assert.assertTrue(expected.length > 0);

		final byte[] computed = hasher.compute(message, salt);
		System.out.printf("%s <- \"%s\"%n", bytesToHex(computed), message);

		Assert.assertArrayEquals(expected, computed);
	}
}
