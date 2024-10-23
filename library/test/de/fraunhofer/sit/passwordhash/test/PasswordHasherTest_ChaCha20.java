package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;

public class PasswordHasherTest_ChaCha20 {

	private static final byte[] SALT_0 = hexToBytes("000000000000000000000000");
	private static final byte[] SALT_1 = hexToBytes("555555555555555555555555");
	private static final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAA");
	private static final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFF");

	private static final String MESSAGE_EMPTY = "";
	private static final String MESSAGE_ST024 = "abc";
	private static final String MESSAGE_ST344 = "The quick brown fox jumps over the lazy dog";
	private static final String MESSAGE_ST352 = "The quick brown fox jumps over the lazy dog.";
	private static final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private static final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	private static final byte[] EXPECTED_EMPTY_0 = hexToBytes("39C398652E33E3D2B53A5D44BF0B2B450DF4D0FA15F219BD00512A8EBE379F62");
	private static final byte[] EXPECTED_EMPTY_1 = hexToBytes("A1BC866280953D63AD64EB6A527436A9AD3D51248F326B4C2F1E3813A4C7484C");
	private static final byte[] EXPECTED_EMPTY_2 = hexToBytes("1A850F56D884951B1790EF36C928E29D86FBD7A1FDDAD0AE258DD7D0D0870318");
	private static final byte[] EXPECTED_EMPTY_3 = hexToBytes("A440AC51282181F75870839DA9FE7AEBD57C56666A4158396DDC8C5DAB5E84F0");

	private static final byte[] EXPECTED_ST024_0 = hexToBytes("90045E2A33DC0F6008FD2C99CFA11D5A2A5CB8596DC5B8895D23A469AB053707");
	private static final byte[] EXPECTED_ST024_1 = hexToBytes("945800565831DB507AB6ABC1E4FC966428EA99709B39A916C886A40A42C28C02");
	private static final byte[] EXPECTED_ST024_2 = hexToBytes("03FA2ACBC56A83C5B7FACEC10C12A7DD3B3B252414A7CD6753FF722C2F3949F4");
	private static final byte[] EXPECTED_ST024_3 = hexToBytes("8D9389BA21D5A76C1BBC637F89E65835CC50AD5EDEF38F946847D60C22E908B8");

	private static final byte[] EXPECTED_ST344_0 = hexToBytes("D84282C769B8D7D731AFF72001E2EAA11CC4837CB9D627845436D6EF8D6501F8");
	private static final byte[] EXPECTED_ST344_1 = hexToBytes("CD5DB2A50AAE1B94F56513FE9E8324A4DAFDA82BFCC6D1261C681CF75D5E87CC");
	private static final byte[] EXPECTED_ST344_2 = hexToBytes("5FC95EA6A6F15971256727F449D6F7B8E016181E4466F5E005F52F1B9E7D96F2");
	private static final byte[] EXPECTED_ST344_3 = hexToBytes("4E342A2F7EB6270AF41F0220E340FDBA03E1680D1E25F28DDF1B7DCAA8BC2430");

	private static final byte[] EXPECTED_ST352_0 = hexToBytes("F691BD9355A88BAC25D0985389F8F72E6BC72A32BDD0DE3BFAE61AB91CF2D2AA");
	private static final byte[] EXPECTED_ST352_1 = hexToBytes("75504AA6D09FE7384A79A3AA16B7267099782D5E13048C37F112F353870F39EC");
	private static final byte[] EXPECTED_ST352_2 = hexToBytes("516B234712C2ED35C44F6ADD9A936D21AD14B5311723909497EEADEC55039566");
	private static final byte[] EXPECTED_ST352_3 = hexToBytes("5D884112D6E04D7F0C879FEB01EC536A187DB2B95DABDA679004F0EAF2ABC87F");

	private static final byte[] EXPECTED_ST448_0 = hexToBytes("CBD9ABC8B8FA9771448D7CB6E4894028D98B39D70CCED48711D2B29287C9A853");
	private static final byte[] EXPECTED_ST448_1 = hexToBytes("4D9649FBA158434455311FE84497A2C9F2F8978FA32BE25F5FA1C79B23CE372B");
	private static final byte[] EXPECTED_ST448_2 = hexToBytes("448CD482B8530522A7CF7B3F73A2CA3B91464CDD74E59D14DE43E1517842618E");
	private static final byte[] EXPECTED_ST448_3 = hexToBytes("F2C802D74AB8A81ED272E231D9BF710A321623EC95BD4846FF655B4329192674");

	private static final byte[] EXPECTED_ST896_0 = hexToBytes("71FD18E30119BCD492294E5B86F2A8345228690F4D1EE775956DB3777D4F90E0");
	private static final byte[] EXPECTED_ST896_1 = hexToBytes("5EBE3CA7C4B4F2C47CFE49DB7DEA2B888737ABD6DFDFC3AC288B1E15A799AB41");
	private static final byte[] EXPECTED_ST896_2 = hexToBytes("5BC37CE79246300FEFB92B27A06BA70C4847A0EBB8E7C521F5AC5D5A2688EDBD");
	private static final byte[] EXPECTED_ST896_3 = hexToBytes("D2142D895BD556638973CDA97E3B192BD73D0AAD5764CB66D524AA19DB219B34");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
			doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
			doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
			doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
		}
	}

	@Test
	void testHashST344() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST344, SALT_0, EXPECTED_ST344_0);
			doTestHash(hasher, MESSAGE_ST344, SALT_1, EXPECTED_ST344_1);
			doTestHash(hasher, MESSAGE_ST344, SALT_2, EXPECTED_ST344_2);
			doTestHash(hasher, MESSAGE_ST344, SALT_3, EXPECTED_ST344_3);
		}
	}

	@Test
	void testHashST352() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST352, SALT_0, EXPECTED_ST352_0);
			doTestHash(hasher, MESSAGE_ST352, SALT_1, EXPECTED_ST352_1);
			doTestHash(hasher, MESSAGE_ST352, SALT_2, EXPECTED_ST352_2);
			doTestHash(hasher, MESSAGE_ST352, SALT_3, EXPECTED_ST352_3);
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
			doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
			doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
			doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
			doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
			doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
			doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);
		Assert.assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	private static void doTestHash(final PasswordHasher hasher, final String message, final byte[] salt, final byte[] expected) {
		Assert.assertNotNull(message);
		Assert.assertNotNull(salt);
		Assert.assertNotNull(expected);

		Assert.assertTrue(salt.length == 12);
		Assert.assertTrue(expected.length == 32);

		final byte[] computed = hasher.compute(message, salt);
		System.out.printf("%s <- \"%s\"%n", bytesToHex(computed), message);

		Assert.assertArrayEquals(expected, computed);
	}
}
