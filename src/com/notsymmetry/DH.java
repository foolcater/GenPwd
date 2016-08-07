package com.notsymmetry;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * DH非对称加密算法
 * @author huazai
 *
 */
public class DH {

	public static final String PUBLIC_KEY = "DHPublicKey";
	public static final String PRIVATE_KEY = "DHPrivateKey";
	/**
	 * 甲方初始化并返回密匙对
	 * @return
	 */
	public static Map<String, Object> initKey(){
		//实例化密匙对生成器
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("DH");
			//初始化密匙对生成器 
			keyPairGenerator.initialize(1024);
			//生成密匙对
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			//得到甲方公匙
			DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
			//得到甲方私钥
			DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
			// 将公匙和私匙封装在map中
			Map<String, Object> keyMap = new HashMap<String, Object>();
			keyMap.put(PUBLIC_KEY, publicKey);
			keyMap.put(PRIVATE_KEY, privateKey);
			return keyMap;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 乙方根据甲方公匙初始化并返回密匙对
	 * @param key 甲方公匙
	 * @return
	 */
	public static Map<String, Object> initKey(byte[] key){
		try {
			//将甲方公匙从字节数组中转换成PublicKey
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
			//实例化密匙工厂
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			//产生甲方的公匙pubKey
			DHPublicKey dhPublicKey = (DHPublicKey) keyFactory.generatePrivate(keySpec);
			//解析甲方公匙，得到其参数
			DHParameterSpec dhParameterSpec =  dhPublicKey.getParams();
			//实例化密匙生成器
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
			//用甲方公匙初始化密匙生成器
			keyPairGenerator.initialize(dhParameterSpec);
			//产生密匙对
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			//得到乙方公匙
			DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
			//得到乙方私钥
			DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
			//将公匙和私钥封装在map中
			Map<String, Object> keyMap = new HashMap<String, Object>();
			keyMap.put(PUBLIC_KEY, publicKey);
			keyMap.put(PRIVATE_KEY, privateKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * 根据对方的公钥和自己的秘钥生成本地秘钥
	 * @param publicKey 对方公钥
	 * @param privateKey 自己的私钥
	 * @return
	 */
	public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey){
		try {
			//实例化秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			//将公钥从字节数组转换为PublicKey
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
			//将私钥从字节数组转换为privateKey
			PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
			PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
			//准备根据以上公钥私钥生成本地秘钥 SecretKey
			//先实例化KeyAgreement
			KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			//用自己的私钥初始化keyAgreement
			keyAgreement.init(priKey);
			//结合对方的公钥进行运算
			keyAgreement.doPhase(pubKey, true);
			//开始生成本地SecretKey 秘钥算法为对称密码算法
			SecretKey secretKey =  keyAgreement.generateSecret("AES");
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 从map取得公钥
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		DHPublicKey key = (DHPublicKey) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
	/**
	 * 从map中取得 
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		DHPrivateKey key = (DHPrivateKey) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
}
