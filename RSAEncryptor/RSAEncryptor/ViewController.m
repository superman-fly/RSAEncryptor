//
//  ViewController.m
//  RSAEncryptor
//
//  Created by Fly on 2018/4/14.
//  Copyright © 2018年 Fly. All rights reserved.
//

#import "ViewController.h"
#import "RSAEncryptor.h"

#define publick_key @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP7YWZxADsXBAjXSjBOEwy9CRQqVrAyoPY1spereB29PRBoNnSwycBywDV0eb2K9lPihUk+OOAT3Hgi+ZOYmRFnUojqQBkW+1XwHw5aN792GcORK4ZMiMQxWUxC168dnIWS1SzlA8pDXf/+TObrB1VRJ8HGvN4VW0Yqmw7c1WiiwIDAQAB"

#define private_key @"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM/thZnEAOxcECNdKME4TDL0JFCpWsDKg9jWyl6t4Hb09EGg2dLDJwHLANXR5vYr2U+KFST444BPceCL5k5iZEWdSiOpAGRb7VfAfDlo3v3YZw5ErhkyIxDFZTELXrx2chZLVLOUDykNd//5M5usHVVEnwca83hVbRiqbDtzVaKLAgMBAAECgYBRgMBCwsK942RsCENGYeP0gSCPAaNSOM+vupn+vNdkqaXo570aUWbD3CgKqEmJKyz2caDSKkE69Wkk5JG1HfpBXZA9xr1LxGPVwYTWipT1g0XzipCWYVTKtabOOi3e/Yq8Pb3PR4GZY/uQMdtzNHmm0EdcOsm2qdlE73KPbjdNwQJBAP+f2A1EETvee47xZdeg7gGBsrqiaRR78gVc5RTZnl9nU2kHh4KgCR68+jXnowuz3VCMNU2YBxULlXqZIYyYdmECQQDQO7x+/q3QJltjRgFN3Jb8vV5TC6snZa/rxnJmRT91ucFLdJMvut9XXgObLgZR20Uhe+ET3NaIo+8GVXqoPShrAkA1brEXnMnJbOkA6R6zovT9JaI5dudmG75sNo2//Pko0g1SX/uIZ3FglnnquJ+RO6igRJ6DuKqKUKCPPuEPZXMhAkB1fq9ebO/AOlRokJCd0XE0jNmTPEtHwJ3iCKh2Qm6LS9Pgcpe2X9gzoO2h+vc/6tx4B0E6BuraUL3HMiYylcefAkAGpdV8/8rwZ0YfwPVbvO2KXLYDX+VNz22y3i8Eknlar6bjev4DYxrmAzITB3/OgzxkoNaWtZ8mrsjGQQ7q4ZU1"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSString *content = @"hello word";
    
    // 私钥签名 公钥解密
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
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
