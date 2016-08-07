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
 * DES对称加密
 * @author huazai
 *
 */
public class DES {

	/**
	 * 生成密匙
	 * @return
	 */
	public String getSecret(){
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("DES");
			keyGen.init(56);
			SecretKey secretKey = keyGen.generateKey();
			return secretKey.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * 加密
	 * @param key
	 * @param data
	 * @return
	 */
	public String EncryptDES(String key, String data){
		try {
			//恢复密匙
			SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DES");
			//Cipher 初始化
			Cipher cipher = Cipher.getInstance("DES");
			//根据密匙，对Cipter进行加密 ENCRYPT_MODE--加密  DECRYPT_MODE--解密
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			byte[] cipherByte = cipher.doFinal(data.getBytes());
			
			return cipherByte.toString();
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
