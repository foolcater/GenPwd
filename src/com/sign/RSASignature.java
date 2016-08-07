package com.sign;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSASignature {

	public static final String KEY_ALGORITHM = "RSA";
	public static final String RSA_PUBLIC_KEY = "RSA_PUBLIC_KEY";
	public static final String RSA_PRIVATE_KEY = "RSA_PRIVATE_KEY";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	
	/**
	 * 初始化 生成公匙，私匙
	 * @return
	 */
	public static Map<String, Object> initKey(){
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey  = (RSAPrivateKey) keyPair.getPrivate();
			Map<String, Object> keyMap = new HashMap<String, Object>();
			keyMap.put(RSA_PUBLIC_KEY, publicKey);
			keyMap.put(RSA_PRIVATE_KEY, privateKey);
			return keyMap;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 获取公匙
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(RSA_PUBLIC_KEY);
		return publicKey.getEncoded();
	}
	/**
	 * 获取私匙
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(RSA_PRIVATE_KEY);
		return privateKey.getEncoded();
	}
	/**
	 * 签名
	 * @param privateKey
	 * @param data
	 * @return
	 */
	public static byte[] sign(byte[] privateKey, byte[] data){
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PrivateKey priKey =  keyFactory.generatePrivate(keySpec);
			
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(priKey);
			signature.update(data);
			byte[] result =  signature.sign();
			return result;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 签名验证
	 * @param data 签名数据
	 * @param publicKey 公匙
	 * @param sign 签名值
	 * @return
	 */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign){
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(pubKey);
			signature.update(data);
			boolean isValid = signature.verify(sign);
			return isValid;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}
}
