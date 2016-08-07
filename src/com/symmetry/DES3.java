package com.symmetry;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 3DES对称加密
 * @author huazai
 *
 */
public class DES3 {

	/**
	 * 初始化，生成密匙
	 * @return
	 */
	public byte[] initSecret(){
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("DESedc");
			keyGen.init(168);
			SecretKey secretKey = keyGen.generateKey();
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 3DES加密
	 * @param key
	 * @param data
	 * @return
	 */
	public byte[] eccryptDES3(byte[] key, String data){
		try {
			SecretKey secretKey = new SecretKeySpec(key, "DESedc");
			Cipher cipher = Cipher.getInstance("DESedc");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] cipterByte = cipher.doFinal(data.getBytes());
			return cipterByte;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
