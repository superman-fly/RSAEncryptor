# RSA
NSString *content = @"hello word";

// 私钥签名 公钥验签

NSString *signedString = [RSAEncryptor signString:content privateKey:private_key];

NSLog(@"签名：%@",signedString);

BOOL verify = [RSAEncryptor verifyString:content withSign:signedString publicKey:publick_key];

NSLog(@"验签：%@",verify?@"成功":@"失败");

// key公钥加密 key私钥解密

NSString *encryptString = [RSAEncryptor encryptString:content publicKey:publick_key];

NSLog(@"key加密：%@",encryptString);

NSString *decryptString = [RSAEncryptor decryptString:encryptString privateKey:private_key];

NSLog(@"key解密：%@",decryptString);

// .pem公钥加密 .pem私钥解密

NSString *publicPemPath = [[NSBundle mainBundle] pathForResource:@"rsa_public_key" ofType:@"pem"];

NSString *pemEncryptString = [RSAEncryptor encryptString:content publicKeyWithContentsOfPEMFile:publicPemPath];

NSLog(@"pem加密：%@",pemEncryptString);

NSString *privatePemPath = [[NSBundle mainBundle] pathForResource:@"rsa_private_key" ofType:@"pem"];

NSString *pemDecryptString = [RSAEncryptor decryptString:pemEncryptString privateKeyWithContentsOfPEMFile:privatePemPath];

NSLog(@"pem解密：%@",pemDecryptString);

// .der加密 .p12解密

NSString *derPath = [[NSBundle mainBundle] pathForResource:@"rsacert" ofType:@"der"];

NSString *derEncryptString = [RSAEncryptor encryptString:content publicKeyWithContentsOfFile:derPath];

NSLog(@"der加密：%@",derEncryptString);

NSString *pPath = [[NSBundle mainBundle] pathForResource:@"p" ofType:@"p12"];

NSString *p12Decrypt = [RSAEncryptor decryptString:derEncryptString privateKeyWithContentsOfFile:pPath password:@"123456"];

NSLog(@"p12解密：%@",p12Decrypt);
