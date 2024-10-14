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

	private static final byte[] EXPECTED_EMPTY_0 = Utilities.hexToBytes("ECE6BED12D5004FDE39C46274403323502EDA79D83F3EC8274B09E798AC21A3C");
	private static final byte[] EXPECTED_EMPTY_1 = Utilities.hexToBytes("C11E410BCF9771549A3512F41C40C6C53C1B818CB6CCAF495A56585267DCCF0A");
	private static final byte[] EXPECTED_EMPTY_2 = Utilities.hexToBytes("83BFF3E56D4B69F684FFDB6768C932041D03AE936AB1E9EE1A9761DCDF92E5BE");
	private static final byte[] EXPECTED_EMPTY_3 = Utilities.hexToBytes("A1EE7EF99033B31D1463F8F38F1A3E8B9308B8FEDB3342FCB1CCC05256C0409A");

	private static final byte[] EXPECTED_ST024_0 = Utilities.hexToBytes("569DAD363E1BFC9160382EA8A99C8CB3147D873705562E8547F0D3BC8E837FCE");
	private static final byte[] EXPECTED_ST024_1 = Utilities.hexToBytes("F47F8EFFA65959DE519786BBC2076E686E830184D1DE223D57D68E306086B8E1");
	private static final byte[] EXPECTED_ST024_2 = Utilities.hexToBytes("DBC8F8577BFBA4BBED7DCDCEB1211B05F644D8E7A62BCFDD1CAF14C2593B5853");
	private static final byte[] EXPECTED_ST024_3 = Utilities.hexToBytes("38B7EA3A326B7F15156CB9DBA8DD7C596F8918EA3122455AF0E870B45302262F");

	private static final byte[] EXPECTED_ST448_0 = Utilities.hexToBytes("4721EC3D801BE5127BB18D23DA5CA76A921703AF79B4D588054461D293F65B06");
	private static final byte[] EXPECTED_ST448_1 = Utilities.hexToBytes("1253AC6F3DB3E590FFDD077B050D14045C7D76518E5426F25F6031AA44CF8319");
	private static final byte[] EXPECTED_ST448_2 = Utilities.hexToBytes("EEBB21A48EFCBCDD5137A66CB6A289B2B528A844A1FED5424DAD5A5ECF6EEA1F");
	private static final byte[] EXPECTED_ST448_3 = Utilities.hexToBytes("9D15A2092E41DB110DA7B633A7F57DEAD5ACAA90A16949A4C8E6200FE1104ECA");

	private static final byte[] EXPECTED_ST896_0 = Utilities.hexToBytes("9D1D5F06800E328AF8A25CA1A80A64A4F1155973227F9D6747F5B776EC4449DF");
	private static final byte[] EXPECTED_ST896_1 = Utilities.hexToBytes("2683BE6455500EDE30C92A5AADF8F868BFAE7F2C75396F8A1752C64DDEF6E2B8");
	private static final byte[] EXPECTED_ST896_2 = Utilities.hexToBytes("BC3CF68D77AE6F93927E4B846B1E1241035EE9D41135C2BA22DB87E58814F1C1");
	private static final byte[] EXPECTED_ST896_3 = Utilities.hexToBytes("F9350FBD53021FC13DF0F834B8C674204E1758E6824CFED10BCA86FD5D0483EE");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			Assert.assertArrayEquals(EXPECTED_EMPTY_0, hasher.compute(MESSAGE_EMPTY, SALT_0));
			Assert.assertArrayEquals(EXPECTED_EMPTY_1, hasher.compute(MESSAGE_EMPTY, SALT_1));
			Assert.assertArrayEquals(EXPECTED_EMPTY_2, hasher.compute(MESSAGE_EMPTY, SALT_2));
			Assert.assertArrayEquals(EXPECTED_EMPTY_3, hasher.compute(MESSAGE_EMPTY, SALT_3));
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			Assert.assertArrayEquals(EXPECTED_ST024_0, hasher.compute(MESSAGE_ST024, SALT_0));
			Assert.assertArrayEquals(EXPECTED_ST024_1, hasher.compute(MESSAGE_ST024, SALT_1));
			Assert.assertArrayEquals(EXPECTED_ST024_2, hasher.compute(MESSAGE_ST024, SALT_2));
			Assert.assertArrayEquals(EXPECTED_ST024_3, hasher.compute(MESSAGE_ST024, SALT_3));
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			Assert.assertArrayEquals(EXPECTED_ST448_0, hasher.compute(MESSAGE_ST448, SALT_0));
			Assert.assertArrayEquals(EXPECTED_ST448_1, hasher.compute(MESSAGE_ST448, SALT_1));
			Assert.assertArrayEquals(EXPECTED_ST448_2, hasher.compute(MESSAGE_ST448, SALT_2));
			Assert.assertArrayEquals(EXPECTED_ST448_3, hasher.compute(MESSAGE_ST448, SALT_3));
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			Assert.assertArrayEquals(EXPECTED_ST896_0, hasher.compute(MESSAGE_ST896, SALT_0));
			Assert.assertArrayEquals(EXPECTED_ST896_1, hasher.compute(MESSAGE_ST896, SALT_1));
			Assert.assertArrayEquals(EXPECTED_ST896_2, hasher.compute(MESSAGE_ST896, SALT_2));
			Assert.assertArrayEquals(EXPECTED_ST896_3, hasher.compute(MESSAGE_ST896, SALT_3));
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		Assert.assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}
}
