package de.fraunhofer.sit.passwordhash.test;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.hasher.PasswordHasher;
import de.fraunhofer.sit.passwordhash.hasher.PasswordManager;
import de.fraunhofer.sit.passwordhash.hasher.PasswordMode;
import de.fraunhofer.sit.passwordhash.utils.Utilities;

public class PasswordHasherTest_AES {

	private static final byte[] SALT_0 = Utilities.hexToBytes("00000000000000000000000000000000");
	private static final byte[] SALT_1 = Utilities.hexToBytes("55555555555555555555555555555555");
	private static final byte[] SALT_2 = Utilities.hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	private static final byte[] SALT_3 = Utilities.hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	private static final String MESSAGE_EMPTY = "";
	private static final String MESSAGE_ST024 = "abc";
	private static final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private static final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	private static final byte[] EXPECTED_EMPTY_0 = Utilities.hexToBytes("41C42B45921267761293ACC97310E425DCFDC92849D02127D4563040F89007E6");
	private static final byte[] EXPECTED_EMPTY_1 = Utilities.hexToBytes("63BB2F872ECF2DA3231A0874218476D6F5AAF7879D8E75423BFDE846F26D0FB8");
	private static final byte[] EXPECTED_EMPTY_2 = Utilities.hexToBytes("388A30F3770B481300F312867597F493C09D93823C05E32F8044453DE00BD716");
	private static final byte[] EXPECTED_EMPTY_3 = Utilities.hexToBytes("5FB6EE365152C67693BBDEFB5AF53D778C5F5DC9D89D06A7C1BF81A86A2CE677");

	private static final byte[] EXPECTED_ST024_0 = Utilities.hexToBytes("8D3307174F0F65EAD78FC03E8FAFED37F21662C462670F9A0358A0244C8DAD26");
	private static final byte[] EXPECTED_ST024_1 = Utilities.hexToBytes("AD32F2FDE8C16754EA733CCF0CC63D9970DDB68074F6EA2C44072135E8523310");
	private static final byte[] EXPECTED_ST024_2 = Utilities.hexToBytes("CCBCB114C43DEE9E6699BE280011A7E206B072ABD2A999D6C5AF0B3290660556");
	private static final byte[] EXPECTED_ST024_3 = Utilities.hexToBytes("2FFF23BAC4D4E88E33A836499FEE72B867A5D1D6B649BB95D21832E52A256B3E");

	private static final byte[] EXPECTED_ST448_0 = Utilities.hexToBytes("8734258A294353384F7339E307E28059EB9B82C2601BCC612C61459FBD56E639");
	private static final byte[] EXPECTED_ST448_1 = Utilities.hexToBytes("4EDF4BD1E39B08ED756B81676A4B2D71C144F11C2FE1F32318A71B549E188045");
	private static final byte[] EXPECTED_ST448_2 = Utilities.hexToBytes("7B88A347C18B53FAEBDBF3F9FA8A8970CCF6F0856FE45252AE95D211D84E2278");
	private static final byte[] EXPECTED_ST448_3 = Utilities.hexToBytes("AAC8489B8E417A7ED1AF4494762B93FD9F799D207A046847006C331871493D68");

	private static final byte[] EXPECTED_ST896_0 = Utilities.hexToBytes("EA82671558534508FCD7F3809F5416B13131F59549EE72D566A6BF53DC290CC7");
	private static final byte[] EXPECTED_ST896_1 = Utilities.hexToBytes("6B3F5AB5245D3CC2CEE12373C2F4163046A25CF170BD2036349BD6E82287B19C");
	private static final byte[] EXPECTED_ST896_2 = Utilities.hexToBytes("452226A930EAD214D13983CF84DBAD44216FF60556EE56E5177F69A6E5527F2D");
	private static final byte[] EXPECTED_ST896_3 = Utilities.hexToBytes("D48EE6ED756CD48198DF39DB76F914B27922D520922B34615FEEC0FC5A7A0CEF");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			assertHashValue(EXPECTED_EMPTY_0, hasher.compute(MESSAGE_EMPTY, SALT_0));
			assertHashValue(EXPECTED_EMPTY_1, hasher.compute(MESSAGE_EMPTY, SALT_1));
			assertHashValue(EXPECTED_EMPTY_2, hasher.compute(MESSAGE_EMPTY, SALT_2));
			assertHashValue(EXPECTED_EMPTY_3, hasher.compute(MESSAGE_EMPTY, SALT_3));
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			assertHashValue(EXPECTED_ST024_0, hasher.compute(MESSAGE_ST024, SALT_0));
			assertHashValue(EXPECTED_ST024_1, hasher.compute(MESSAGE_ST024, SALT_1));
			assertHashValue(EXPECTED_ST024_2, hasher.compute(MESSAGE_ST024, SALT_2));
			assertHashValue(EXPECTED_ST024_3, hasher.compute(MESSAGE_ST024, SALT_3));
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			assertHashValue(EXPECTED_ST448_0, hasher.compute(MESSAGE_ST448, SALT_0));
			assertHashValue(EXPECTED_ST448_1, hasher.compute(MESSAGE_ST448, SALT_1));
			assertHashValue(EXPECTED_ST448_2, hasher.compute(MESSAGE_ST448, SALT_2));
			assertHashValue(EXPECTED_ST448_3, hasher.compute(MESSAGE_ST448, SALT_3));
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			assertHashValue(EXPECTED_ST896_0, hasher.compute(MESSAGE_ST896, SALT_0));
			assertHashValue(EXPECTED_ST896_1, hasher.compute(MESSAGE_ST896, SALT_1));
			assertHashValue(EXPECTED_ST896_2, hasher.compute(MESSAGE_ST896, SALT_2));
			assertHashValue(EXPECTED_ST896_3, hasher.compute(MESSAGE_ST896, SALT_3));
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		Assert.assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	private static void assertHashValue(final byte[] expected, final byte[] computed) {
		System.out.println(Utilities.bytesToHex(computed));
		Assert.assertArrayEquals(expected, computed);
	}
}
