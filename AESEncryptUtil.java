
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;

import com.gws.common.log.GwsLogger;

/**
 * AES 128bit 加密解密工具类
 * 
 * @version
 * @author leiyongping 2017年7月12日 下午8:25:42
 * 
 */
public final class AESEncryptUtil {
	private final static byte[] ivBytes = "0102030405060708".getBytes();

	private AESEncryptUtil() {
		throw new Error("工具类不能实例化！");
	}

	/**
	 * 加密
	 *
	 * @author leiyongping 2017年7月12日 下午8:32:31
	 * @param data
	 *            需要加密的数据
	 * @param key
	 *            加密key
	 * @return
	 */
	public static String encrypt(String data, String key) {
		if (data == null || data.length() == 0) {
			// 当待加密码明文为空时，原值返回
			return data;
		}
		try {
			SecretKeySpec skeySpec = generateKey(key);
			// "算法/模式/补码方式"
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
			IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
			byte[] encrypted = cipher.doFinal(data.getBytes());

			// 此处使用BAES64做转码功能，同时能起到2次加密的作用。
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception e) {
			GwsLogger.error("Exception:", e);
		}
		return data;
	}

	/**
	 * 解密
	 *
	 * @author leiyongping 2017年7月12日 下午8:32:55
	 * @param data
	 *            需要解密数据
	 * @param key
	 *            解密key
	 * @return
	 */
	public static String decrypt(String data, String key) {
		if (data == null || data.length() == 0) {
			// 当待解密的密文为空时，原值返回
			return data;
		}
		try {

			SecretKeySpec skeySpec = generateKey(key);
			// "算法/模式/补码方式"
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
			IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
			// 先用bAES64解密
			byte[] encrypted1 = Base64.getDecoder().decode(data);
			byte[] original = cipher.doFinal(encrypted1);
			String originalString = new String(original);
			return originalString;
		} catch (Exception e) {
		}
		return data;
	}

	private static SecretKeySpec generateKey(String key) throws NoSuchAlgorithmException {
		String secretKeyCurrent = key;
		if (StringUtils.isBlank(secretKeyCurrent)) {
			secretKeyCurrent = "SdhJiaoyi2017";
		}

		// 判断Key是否为16位
		if (secretKeyCurrent.length() >= 16) {
			secretKeyCurrent = secretKeyCurrent.substring(0, 16);
		} else {
			secretKeyCurrent = StringUtils.leftPad(secretKeyCurrent, 16, "O");
		}

		byte[] raw = secretKeyCurrent.getBytes();
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		return skeySpec;
	}
}
