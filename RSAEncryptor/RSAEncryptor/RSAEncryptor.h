//
//  RSAEncryptor.h
//  RSAEncryptor
//
//  Created by Fly on 2018/4/14.
//  Copyright © 2018年 Fly. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAEncryptor : NSObject

/**
 der公钥加密
 
 @param string  需要加密的字符串
 @param path    '.der'格式的公钥文件路径
 @return 加密后base64
 */
+ (NSString *)encryptString:(NSString *)string publicKeyWithContentsOfFile:(NSString *)path;

/**
 p12私钥解密
 
 @param string  需要解密的字符串
 @param path    '.p12'格式的私钥文件路径
 @param password    私钥文件密码
 @return base64后解密
 */
+ (NSString *)decryptString:(NSString *)string privateKeyWithContentsOfFile:(NSString *)path password:(NSString *)password;

/**
 pem公钥加密

 @param string 需要加密的字符串
 @param path '.pem'格式的公钥文件路径
 @return 加密后base64
 */
+ (NSString *)encryptString:(NSString *)string publicKeyWithContentsOfPEMFile:(NSString *)path;

/**
 pem私钥解密

 @param string 需要解密的字符串
 @param path '.pem'格式的私钥文件路径
 @return 明文
 */
+ (NSString *)decryptString:(NSString *)string privateKeyWithContentsOfPEMFile:(NSString *)path;

/**
 公钥加密
 
 @param string  需要加密的字符串
 @param pubKey  公钥字符串
 @return 加密后base64
 */
+ (NSString *)encryptString:(NSString *)string publicKey:(NSString *)pubKey;

/**
 私钥解密
 
 @param string  需要解密的字符串
 @param privKey 私钥字符串
 @return base64后解密
 */
+ (NSString *)decryptString:(NSString *)string privateKey:(NSString *)privKey;

/**
 私钥签名
 
 @param string 需要签名的字符串
 @param path '.pem'格式的私钥文件路径
 @return 签名base64
 */
+ (NSString *)signString:(NSString *)string privateKeyWithContentsOfFile:(NSString *)path;

/**
 私钥字符串签名
 
 @param string 需要签名的字符串
 @param privKey 私钥字符串
 @return 签名base64
 */
+ (NSString *)signString:(NSString *)string privateKey:(NSString *)privKey;

/**
 公钥验签
 
 @param string 需要签名的字符串
 @param signString 已签名的字符串
 @param path '.pem'格式的公钥文件路径
 @return 验签是否通过
 */
+ (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString publicKeyWithContentsOfFile:(NSString *)path;

/**
 公钥字符串验签
 
 @param string 需要签名的字符串
 @param signString 已签名的字符串
 @param pubKey 公钥字符串
 @return 验签是否通过
 */
+ (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString publicKey:(NSString *)pubKey;

@end
