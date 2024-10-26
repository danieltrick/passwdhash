package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;
import de.fraunhofer.sit.passwordhash.test.helper.DisabledOnJava8;

@DisabledOnJava8
public class PasswordHasherTest_ChaCha20 extends PasswordHasherTest {

	protected final byte[] SALT_0 = hexToBytes("000000000000000000000000");
	protected final byte[] SALT_1 = hexToBytes("555555555555555555555555");
	protected final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAA");
	protected final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFF");
	
	private final byte[] EXPECTED_EMPTY_0 = hexToBytes("7F29A2D612C5B0BBE43C90E71F8102F21873A2DE79B919C4EC279A8384A7A098");
	private final byte[] EXPECTED_EMPTY_1 = hexToBytes("FDBE7288153C8AEFE74A5A3C64FCBA7F3B3160CEBD7AA681EAB5035F0E465008");
	private final byte[] EXPECTED_EMPTY_2 = hexToBytes("2E6D90789C80203610D45918139F7DC88BA83B3E183CD07B16D1AE441FA8C669");
	private final byte[] EXPECTED_EMPTY_3 = hexToBytes("C104C7EC3390EFECF26251E0646AB6092FE5813C7D3F9FE69F13DD989A41542A");

	private final byte[] EXPECTED_ST024_0 = hexToBytes("DCABEF8C27EBB3FF9075F3DD65969BBDA94878AB6A7C154E2B9939439F50AA2B");
	private final byte[] EXPECTED_ST024_1 = hexToBytes("7117FF9CB63E3E424D20F05673910F66BB4D0E8A71A995E9311D1B1FBBC3DEAF");
	private final byte[] EXPECTED_ST024_2 = hexToBytes("E06819549283C388BDFBB9C8B0AE4F5B4346B2AC71BC58D900AF01A656207444");
	private final byte[] EXPECTED_ST024_3 = hexToBytes("6475BAC83C5CF30DA9F70AFB4B0180858522675484A9009FCC1B64AE08A85FAB");

	private final byte[] EXPECTED_ST344_0 = hexToBytes("60FBDF40ADB83E246953C8F37EB08789C4CA685F038BE8EE2DCD8EBA6D67302A");
	private final byte[] EXPECTED_ST344_1 = hexToBytes("7B94FAF20A49842FE2902998A57774A574566AC35EE245868B0ED0BD847821EC");
	private final byte[] EXPECTED_ST344_2 = hexToBytes("DAEE6B3C46DB02F9070A2AAB8B0391446015890B263D44373D5C13F8592F81C5");
	private final byte[] EXPECTED_ST344_3 = hexToBytes("81CF8E9B7D1A738F30CCCC290121024F8C5C7DF74953238ACCF7E5CE139D4D18");

	private final byte[] EXPECTED_ST352_0 = hexToBytes("12E3EB53CFFBAA9A7ACA74D964C8F3281F5B1F9BDB10B9464BDF1DD45F3BCAE1");
	private final byte[] EXPECTED_ST352_1 = hexToBytes("2F5A7DCA6ABE3B876B6D774D94D19FBE34C17B15145CCBFEE2E71A58B83DF0EA");
	private final byte[] EXPECTED_ST352_2 = hexToBytes("96648A51BBC1D7FE07DBCCDAEBAFE66ECD8BB262F8E3DBDF7F4D294959A402A9");
	private final byte[] EXPECTED_ST352_3 = hexToBytes("B053015BE50D5A922DFC15D3AA3D9249CA00F9AD161A5D7C3A2A50BB25AEB0C2");

	private final byte[] EXPECTED_ST448_0 = hexToBytes("D98EDC00FE0D5A37B92937FA249EDECABCE1298E4C322EF21D6E6DF252F92241");
	private final byte[] EXPECTED_ST448_1 = hexToBytes("4DEE90957A12076A65DC73962B3B4E67AEA6FD1F7AB72C3EE66ED4B11618EF37");
	private final byte[] EXPECTED_ST448_2 = hexToBytes("5E1A74FFAC501ED4CD4494CF42EBE0000057970F4EA499A5E8EB47F097CC119B");
	private final byte[] EXPECTED_ST448_3 = hexToBytes("3CC13F6865B50F8984FC10BC3CA2DEBD4C6A60A07F76E0E49E605B51D0AC07AC");

	private final byte[] EXPECTED_ST896_0 = hexToBytes("A84D7C45CA08704D174CE1E67C5E3F3B939E727DDEF0F984F5F9EA4BC7681891");
	private final byte[] EXPECTED_ST896_1 = hexToBytes("AC5C9C2A3E4A00F3F3953CBE5DFAAACCAB592CB059C399C51A6C4825B42E0CF5");
	private final byte[] EXPECTED_ST896_2 = hexToBytes("2ADC5AA7AFB074361CE8B3D94E3D3EB6DF51DA7B2BB88C8CDAC82AB2BFDD87B3");
	private final byte[] EXPECTED_ST896_3 = hexToBytes("728A5126CDD8AF058A422CA1E327C066CF47C7EF2A59B0671D3E99A223CE040C");

	@RepeatedTest(4)
	void testHashEmpty(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST024(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST344(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST344, SALT_0, EXPECTED_ST344_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST344, SALT_1, EXPECTED_ST344_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST344, SALT_2, EXPECTED_ST344_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST344, SALT_3, EXPECTED_ST344_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST352(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST352, SALT_0, EXPECTED_ST352_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST352, SALT_1, EXPECTED_ST352_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST352, SALT_2, EXPECTED_ST352_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST352, SALT_3, EXPECTED_ST352_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST448(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST896(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);
		assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	@AfterEach
	public void finalizerFunction() {
		System.out.println();
	}
}
