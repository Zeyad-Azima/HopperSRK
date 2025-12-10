/*
 KeychainAnalyzer.m
 Keychain & Credential Security Analyzer Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "KeychainAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation KeychainAnalyzer

#pragma mark - Plugin Initialization

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

+ (int)sdkVersion {
    return 6; // Hopper v5 compatibility
}

#pragma mark - Plugin Metadata

- (NSObject<HPHopperUUID> *)pluginUUID {
    return [self.services UUIDWithString:@"2E4F5A8D-9C3B-4E7A-A2D9-7F1E4B8C5D6E"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Keychain & Credential Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive keychain and credential operation detection: Security.framework, CommonCrypto, LocalAuthentication, and credential strings";
}

- (NSString *)pluginAuthor {
    return @"Zeyad Azima";
}

- (NSString *)pluginCopyright {
    return @"©2025 Zeyad Azima";
}

- (NSString *)pluginVersion {
    return @"2.0.0";
}

- (NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"keychain-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Keychain & Credential Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeKeychain:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeKeychain:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[KeychainAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[KeychainAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing Keychain & Credentials..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[KeychainAnalyzer]      KEYCHAIN & CREDENTIAL SECURITY ANALYSIS REPORT"];
    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[KeychainAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"          KEYCHAIN & CREDENTIAL SECURITY ANALYSIS REPORT               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    // Phase 1: Keychain API Detection (C & Objective-C)
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[KeychainAnalyzer] Phase 1: Analyzing Keychain APIs (C & Objective-C)..."];
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *keychainAPIs = [self analyzeKeychainAPIs:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] KEYCHAIN APIS (C & OBJECTIVE-C)\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *secItemAPIs = keychainAPIs[@"secitem"];
    NSArray *legacyAPIs = keychainAPIs[@"legacy"];
    NSArray *attributeAPIs = keychainAPIs[@"attributes"];

    if (secItemAPIs.count > 0) {
        [report appendFormat:@"Modern SecItem APIs: %lu\n\n", (unsigned long)secItemAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Modern SecItem APIs: %lu", (unsigned long)secItemAPIs.count]];
        for (NSDictionary *op in secItemAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (legacyAPIs.count > 0) {
        [report appendFormat:@"Legacy Keychain APIs: %lu\n\n", (unsigned long)legacyAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Legacy Keychain APIs: %lu", (unsigned long)legacyAPIs.count]];
        for (NSDictionary *op in legacyAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (attributeAPIs.count > 0) {
        [report appendFormat:@"Keychain Attributes/Constants: %lu\n\n", (unsigned long)attributeAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Keychain Attributes: %lu", (unsigned long)attributeAPIs.count]];
        for (NSDictionary *op in attributeAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalKeychainAPIs = secItemAPIs.count + legacyAPIs.count + attributeAPIs.count;
    if (totalKeychainAPIs == 0) {
        [report appendString:@"⚠️  No keychain APIs detected\n\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ⚠️  No keychain APIs detected"];
    }

    // Phase 2: CommonCrypto & Cryptographic APIs
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[KeychainAnalyzer] Phase 2: Analyzing Cryptographic APIs..."];
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *cryptoAPIs = [self analyzeCryptographicAPIs:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] CRYPTOGRAPHIC APIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *commonCrypto = cryptoAPIs[@"commoncrypto"];
    NSArray *secKeyAPIs = cryptoAPIs[@"seckey"];
    NSArray *enclaveAPIs = cryptoAPIs[@"enclave"];

    if (commonCrypto.count > 0) {
        [report appendFormat:@"CommonCrypto APIs: %lu\n\n", (unsigned long)commonCrypto.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] CommonCrypto APIs: %lu", (unsigned long)commonCrypto.count]];
        for (NSDictionary *op in commonCrypto) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (secKeyAPIs.count > 0) {
        [report appendFormat:@"SecKey Cryptography APIs: %lu\n\n", (unsigned long)secKeyAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] SecKey APIs: %lu", (unsigned long)secKeyAPIs.count]];
        for (NSDictionary *op in secKeyAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (enclaveAPIs.count > 0) {
        [report appendFormat:@"Secure Enclave APIs: %lu\n\n", (unsigned long)enclaveAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Secure Enclave APIs: %lu", (unsigned long)enclaveAPIs.count]];
        for (NSDictionary *op in enclaveAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalCryptoAPIs = commonCrypto.count + secKeyAPIs.count + enclaveAPIs.count;
    if (totalCryptoAPIs == 0) {
        [report appendString:@"⚠️  No cryptographic APIs detected\n\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ⚠️  No cryptographic APIs detected"];
    }

    // Phase 3: LocalAuthentication & Biometrics (Objective-C & Swift)
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[KeychainAnalyzer] Phase 3: Analyzing LocalAuthentication (ObjC & Swift)..."];
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *authAPIs = [self analyzeLocalAuthentication:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] LOCALAUTHENTICATION & BIOMETRICS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *objcAuth = authAPIs[@"objc"];
    NSArray *swiftAuth = authAPIs[@"swift"];

    if (objcAuth.count > 0) {
        [report appendFormat:@"Objective-C LocalAuthentication: %lu\n\n", (unsigned long)objcAuth.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Objective-C LocalAuthentication: %lu", (unsigned long)objcAuth.count]];
        for (NSDictionary *op in objcAuth) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (swiftAuth.count > 0) {
        [report appendFormat:@"Swift LocalAuthentication: %lu\n\n", (unsigned long)swiftAuth.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Swift LocalAuthentication: %lu", (unsigned long)swiftAuth.count]];
        for (NSDictionary *op in swiftAuth) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalAuthAPIs = objcAuth.count + swiftAuth.count;
    if (totalAuthAPIs == 0) {
        [report appendString:@"⚠️  No authentication APIs detected\n\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ⚠️  No authentication APIs detected"];
    }

    // Phase 4: Certificate & Trust APIs
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[KeychainAnalyzer] Phase 4: Analyzing Certificate & Trust APIs..."];
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *certAPIs = [self analyzeCertificateAPIs:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] CERTIFICATE & TRUST APIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *certOps = certAPIs[@"certificate"];
    NSArray *trustOps = certAPIs[@"trust"];
    NSArray *identityOps = certAPIs[@"identity"];

    if (certOps.count > 0) {
        [report appendFormat:@"Certificate APIs: %lu\n\n", (unsigned long)certOps.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Certificate APIs: %lu", (unsigned long)certOps.count]];
        for (NSDictionary *op in certOps) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (trustOps.count > 0) {
        [report appendFormat:@"Trust Evaluation APIs: %lu\n\n", (unsigned long)trustOps.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Trust APIs: %lu", (unsigned long)trustOps.count]];
        for (NSDictionary *op in trustOps) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    if (identityOps.count > 0) {
        [report appendFormat:@"Identity APIs: %lu\n\n", (unsigned long)identityOps.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Identity APIs: %lu", (unsigned long)identityOps.count]];
        for (NSDictionary *op in identityOps) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalCertAPIs = certOps.count + trustOps.count + identityOps.count;
    if (totalCertAPIs == 0) {
        [report appendString:@"⚠️  No certificate/trust APIs detected\n\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ⚠️  No certificate/trust APIs detected"];
    }

    // Phase 5: Credential String Extraction
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[KeychainAnalyzer] Phase 5: Extracting Credential Strings..."];
    [document logInfoMessage:@"[KeychainAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *credentials = [self extractCredentialStrings:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] CREDENTIAL STRING EXTRACTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (credentials.count > 0) {
        [report appendFormat:@"Found %lu potential credential string(s)\n\n", (unsigned long)credentials.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Found %lu potential credential string(s)", (unsigned long)credentials.count]];
        for (NSDictionary *cred in credentials) {
            [report appendFormat:@"  [0x%llx] [%@] \"%@\"\n",
                [cred[@"address"] unsignedLongLongValue], cred[@"type"], cred[@"string"]];
            NSString *displayStr = [cred[@"string"] length] > 60 ?
                [[cred[@"string"] substringToIndex:60] stringByAppendingString:@"..."] : cred[@"string"];
            [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer]   [0x%llx] [%@] \"%@\"",
                [cred[@"address"] unsignedLongLongValue], cred[@"type"], displayStr]];
        }
    } else {
        [report appendString:@"⚠️  No credential strings detected\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ⚠️  No credential strings detected"];
    }
    [report appendString:@"\n"];

    // Summary
    NSUInteger totalFindings = totalKeychainAPIs + totalCryptoAPIs + totalAuthAPIs + totalCertAPIs + credentials.count;

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"SUMMARY\n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Findings: %lu\n", (unsigned long)totalFindings];
    [report appendFormat:@"  - Keychain APIs: %lu\n", (unsigned long)totalKeychainAPIs];
    [report appendFormat:@"    • SecItem APIs: %lu\n", (unsigned long)secItemAPIs.count];
    [report appendFormat:@"    • Legacy APIs: %lu\n", (unsigned long)legacyAPIs.count];
    [report appendFormat:@"    • Attributes: %lu\n", (unsigned long)attributeAPIs.count];
    [report appendFormat:@"  - Cryptographic APIs: %lu\n", (unsigned long)totalCryptoAPIs];
    [report appendFormat:@"    • CommonCrypto: %lu\n", (unsigned long)commonCrypto.count];
    [report appendFormat:@"    • SecKey: %lu\n", (unsigned long)secKeyAPIs.count];
    [report appendFormat:@"    • Secure Enclave: %lu\n", (unsigned long)enclaveAPIs.count];
    [report appendFormat:@"  - LocalAuthentication: %lu\n", (unsigned long)totalAuthAPIs];
    [report appendFormat:@"    • Objective-C: %lu\n", (unsigned long)objcAuth.count];
    [report appendFormat:@"    • Swift: %lu\n", (unsigned long)swiftAuth.count];
    [report appendFormat:@"  - Certificate/Trust APIs: %lu\n", (unsigned long)totalCertAPIs];
    [report appendFormat:@"  - Credential Strings: %lu\n\n", (unsigned long)credentials.count];

    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[KeychainAnalyzer] SUMMARY"];
    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Total Findings: %lu", (unsigned long)totalFindings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Keychain APIs: %lu (SecItem:%lu Legacy:%lu Attrs:%lu)", (unsigned long)totalKeychainAPIs, (unsigned long)secItemAPIs.count, (unsigned long)legacyAPIs.count, (unsigned long)attributeAPIs.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Crypto APIs: %lu (CC:%lu SecKey:%lu Enclave:%lu)", (unsigned long)totalCryptoAPIs, (unsigned long)commonCrypto.count, (unsigned long)secKeyAPIs.count, (unsigned long)enclaveAPIs.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] LocalAuth: %lu (ObjC:%lu Swift:%lu)", (unsigned long)totalAuthAPIs, (unsigned long)objcAuth.count, (unsigned long)swiftAuth.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Certificate/Trust: %lu", (unsigned long)totalCertAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[KeychainAnalyzer] Credential Strings: %lu", (unsigned long)credentials.count]];

    BOOL usesKeychain = (totalKeychainAPIs > 0);
    BOOL usesCrypto = (totalCryptoAPIs > 0);
    BOOL usesAuth = (totalAuthAPIs > 0);
    BOOL usesCerts = (totalCertAPIs > 0);

    if (usesKeychain) {
        [report appendString:@"✓ Binary uses Keychain for secure storage\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ✓ Binary uses Keychain for secure storage"];
    }
    if (usesCrypto) {
        [report appendString:@"✓ Binary implements cryptographic operations\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ✓ Binary implements cryptographic operations"];
    }
    if (usesAuth) {
        [report appendString:@"✓ Binary uses LocalAuthentication (TouchID/FaceID)\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ✓ Binary uses LocalAuthentication (TouchID/FaceID)"];
    }
    if (usesCerts) {
        [report appendString:@"✓ Binary handles certificates/identities\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ✓ Binary handles certificates/identities"];
    }
    [report appendString:@"\n"];

    if (usesKeychain || usesCrypto || usesAuth || usesCerts) {
        [report appendString:@"SECURITY ANALYSIS RECOMMENDATIONS:\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] SECURITY ANALYSIS RECOMMENDATIONS:"];
        [report appendString:@"1. Verify proper keychain access control (kSecAttrAccessible*)\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] 1. Verify proper keychain access control (kSecAttrAccessible*)"];
        [report appendString:@"2. Check for hardcoded credentials or weak encryption keys\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] 2. Check for hardcoded credentials or weak encryption keys"];
        [report appendString:@"3. Ensure proper use of secure enclave for sensitive keys\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] 3. Ensure proper use of secure enclave for sensitive keys"];
        [report appendString:@"4. Review biometric authentication implementation\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] 4. Review biometric authentication implementation"];
        [report appendString:@"5. Validate certificate pinning and TLS configuration\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] 5. Validate certificate pinning and TLS configuration"];
    } else {
        [report appendString:@"ℹ️  No keychain or credential operations detected\n\n"];
        [document logInfoMessage:@"[KeychainAnalyzer] ℹ️  No keychain or credential operations detected"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[KeychainAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[KeychainAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"Keychain_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    // Show summary popup
    NSString *summary = [NSString stringWithFormat:
        @"Keychain & Credential Analysis Complete\n\n"
        @"Total Findings: %lu\n"
        @"  • Keychain APIs: %lu\n"
        @"  • Cryptographic APIs: %lu\n"
        @"  • LocalAuthentication: %lu\n"
        @"  • Certificate/Trust: %lu\n"
        @"  • Credential Strings: %lu\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalFindings,
        (unsigned long)totalKeychainAPIs,
        (unsigned long)totalCryptoAPIs,
        (unsigned long)totalAuthAPIs,
        (unsigned long)totalCertAPIs,
        (unsigned long)credentials.count,
        tmpPath];

    [document displayAlertWithMessageText:@"Keychain & Credential Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)analyzeKeychainAPIs:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *secItemAPIs = [NSMutableArray array];
    NSMutableArray *legacyAPIs = [NSMutableArray array];
    NSMutableArray *attributeAPIs = [NSMutableArray array];

    // Modern SecItem C APIs
    NSArray *secItemPatterns = @[
        @"SecItemAdd", @"SecItemCopyMatching", @"SecItemUpdate", @"SecItemDelete",
        @"SecItemUpdateTokenItems", @"SecItemExport", @"SecItemImport"
    ];

    // Legacy Keychain C APIs
    NSArray *legacyPatterns = @[
        @"SecKeychainCreate", @"SecKeychainOpen", @"SecKeychainDelete",
        @"SecKeychainAddGenericPassword", @"SecKeychainAddInternetPassword",
        @"SecKeychainFindGenericPassword", @"SecKeychainFindInternetPassword",
        @"SecKeychainItemCopyContent", @"SecKeychainItemModifyContent",
        @"SecKeychainItemDelete", @"SecKeychainItemFreeContent",
        @"SecKeychainGetDefault", @"SecKeychainSetDefault",
        @"SecKeychainCopyDefault", @"SecKeychainSetPreferenceDomain",
        @"SecKeychainItemCopyAttributesAndData", @"SecKeychainItemModifyAttributesAndData"
    ];

    // Keychain attributes and constants
    NSArray *attributePatterns = @[
        @"kSecClass", @"kSecClassGenericPassword", @"kSecClassInternetPassword",
        @"kSecClassCertificate", @"kSecClassKey", @"kSecClassIdentity",
        @"kSecAttrAccessible", @"kSecAttrAccessibleWhenUnlocked",
        @"kSecAttrAccessibleAfterFirstUnlock", @"kSecAttrAccessibleAlways",
        @"kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        @"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        @"kSecAttrAccessibleAlwaysThisDeviceOnly",
        @"kSecAttrAccount", @"kSecAttrService", @"kSecAttrGeneric",
        @"kSecAttrLabel", @"kSecAttrComment", @"kSecAttrDescription",
        @"kSecValueData", @"kSecReturnData", @"kSecReturnAttributes",
        @"kSecMatchLimit", @"kSecMatchLimitOne", @"kSecMatchLimitAll"
    ];

    [self scanStringsForPatterns:secItemPatterns inFile:file results:secItemAPIs maxResults:100];
    [self scanStringsForPatterns:legacyPatterns inFile:file results:legacyAPIs maxResults:100];
    [self scanStringsForPatterns:attributePatterns inFile:file results:attributeAPIs maxResults:150];

    return @{
        @"secitem": [secItemAPIs copy],
        @"legacy": [legacyAPIs copy],
        @"attributes": [attributeAPIs copy]
    };
}

- (NSDictionary *)analyzeCryptographicAPIs:(NSObject<HPDisassembledFile> *)file
                                  document:(NSObject<HPDocument> *)document {
    NSMutableArray *commonCrypto = [NSMutableArray array];
    NSMutableArray *secKeyAPIs = [NSMutableArray array];
    NSMutableArray *enclaveAPIs = [NSMutableArray array];

    // CommonCrypto C APIs
    NSArray *ccPatterns = @[
        // Encryption/Decryption
        @"CCCrypt", @"CCCryptorCreate", @"CCCryptorCreateFromData",
        @"CCCryptorUpdate", @"CCCryptorFinal", @"CCCryptorRelease", @"CCCryptorReset",
        @"CCCryptorGetOutputLength",
        // Hashing
        @"CC_MD2", @"CC_MD4", @"CC_MD5", @"CC_SHA1", @"CC_SHA224",
        @"CC_SHA256", @"CC_SHA384", @"CC_SHA512",
        @"CC_MD5_Init", @"CC_MD5_Update", @"CC_MD5_Final",
        @"CC_SHA1_Init", @"CC_SHA1_Update", @"CC_SHA1_Final",
        @"CC_SHA256_Init", @"CC_SHA256_Update", @"CC_SHA256_Final",
        @"CC_SHA512_Init", @"CC_SHA512_Update", @"CC_SHA512_Final",
        // HMAC
        @"CCHmac", @"CCHmacInit", @"CCHmacUpdate", @"CCHmacFinal",
        // Key Derivation
        @"CCKeyDerivationPBKDF", @"CCCalibratePBKDF",
        @"CCDeriveKey", @"PBKDF2",
        // Random
        @"CCRandomGenerateBytes", @"CCRandomCopyBytes"
    ];

    // SecKey modern cryptography APIs
    NSArray *secKeyPatterns = @[
        @"SecKeyCreateRandomKey", @"SecKeyCreateWithData",
        @"SecKeyCreateSignature", @"SecKeyVerifySignature",
        @"SecKeyCreateEncryptedData", @"SecKeyCreateDecryptedData",
        @"SecKeyCopyExternalRepresentation", @"SecKeyCopyAttributes",
        @"SecKeyCopyPublicKey", @"SecKeyIsAlgorithmSupported",
        @"SecKeyGeneratePair", @"SecKeyRawSign", @"SecKeyRawVerify",
        @"SecKeyEncrypt", @"SecKeyDecrypt"
    ];

    // Secure Enclave APIs
    NSArray *enclavePatterns = @[
        @"kSecAttrTokenIDSecureEnclave", @"kSecAttrTokenID",
        @"SecAccessControlCreateWithFlags",
        @"kSecAccessControlPrivateKeyUsage", @"kSecAccessControlUserPresence",
        @"kSecAccessControlBiometryAny", @"kSecAccessControlBiometryCurrentSet",
        @"kSecAccessControlDevicePasscode", @"kSecAccessControlApplicationPassword",
        @"SecRandomCopyBytes"
    ];

    [self scanStringsForPatterns:ccPatterns inFile:file results:commonCrypto maxResults:150];
    [self scanStringsForPatterns:secKeyPatterns inFile:file results:secKeyAPIs maxResults:100];
    [self scanStringsForPatterns:enclavePatterns inFile:file results:enclaveAPIs maxResults:50];

    return @{
        @"commoncrypto": [commonCrypto copy],
        @"seckey": [secKeyAPIs copy],
        @"enclave": [enclaveAPIs copy]
    };
}

- (NSDictionary *)analyzeLocalAuthentication:(NSObject<HPDisassembledFile> *)file
                                    document:(NSObject<HPDocument> *)document {
    NSMutableArray *objcAuth = [NSMutableArray array];
    NSMutableArray *swiftAuth = [NSMutableArray array];

    // Objective-C LocalAuthentication APIs
    NSArray *objcPatterns = @[
        @"LAContext", @"canEvaluatePolicy", @"evaluatePolicy",
        @"evaluateAccessControl", @"invalidate",
        @"setCredential", @"isCredentialSet", @"biometryType",
        @"localizedReason", @"localizedFallbackTitle",
        @"LAPolicyDeviceOwnerAuthentication",
        @"LAPolicyDeviceOwnerAuthenticationWithBiometrics",
        @"LAPolicyDeviceOwnerAuthenticationWithWatch",
        @"LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch",
        @"LABiometryNone", @"LABiometryTypeTouchID", @"LABiometryTypeFaceID",
        @"LAError", @"LAErrorAuthenticationFailed", @"LAErrorUserCancel",
        @"LAErrorUserFallback", @"LAErrorBiometryNotAvailable",
        @"LAErrorBiometryNotEnrolled", @"LAErrorBiometryLockout"
    ];

    // Swift LocalAuthentication (mangled names and Swift-specific)
    NSArray *swiftPatterns = @[
        @"LocalAuthentication.LAContext",
        @"$s20LocalAuthentication", // Swift module prefix
        @"LAContext", @"LAPolicy", @"LABiometryType",
        @"Swift.LAContext", @"Swift.LAPolicy"
    ];

    [self scanStringsForPatterns:objcPatterns inFile:file results:objcAuth maxResults:100];
    [self scanStringsForPatterns:swiftPatterns inFile:file results:swiftAuth maxResults:50];

    return @{
        @"objc": [objcAuth copy],
        @"swift": [swiftAuth copy]
    };
}

- (NSDictionary *)analyzeCertificateAPIs:(NSObject<HPDisassembledFile> *)file
                                document:(NSObject<HPDocument> *)document {
    NSMutableArray *certOps = [NSMutableArray array];
    NSMutableArray *trustOps = [NSMutableArray array];
    NSMutableArray *identityOps = [NSMutableArray array];

    // Certificate C APIs
    NSArray *certPatterns = @[
        @"SecCertificateCreateWithData", @"SecCertificateCopyData",
        @"SecCertificateCopySubjectSummary", @"SecCertificateCopyCommonName",
        @"SecCertificateCopyEmailAddresses", @"SecCertificateCopySerialNumber",
        @"SecCertificateCopyNormalizedIssuerSequence",
        @"SecCertificateCopyNormalizedSubjectSequence",
        @"SecCertificateCopyKey", @"SecCertificateCopyPublicKey"
    ];

    // Trust evaluation APIs
    NSArray *trustPatterns = @[
        @"SecTrustCreateWithCertificates", @"SecTrustEvaluate",
        @"SecTrustEvaluateAsync", @"SecTrustEvaluateAsyncWithError",
        @"SecTrustEvaluateWithError",
        @"SecTrustGetCertificateCount", @"SecTrustGetCertificateAtIndex",
        @"SecTrustCopyResult", @"SecTrustCopyPublicKey",
        @"SecTrustSetPolicies", @"SecTrustSetAnchorCertificates",
        @"SecTrustSetAnchorCertificatesOnly", @"SecTrustSetNetworkFetchAllowed",
        @"SecPolicyCreateSSL", @"SecPolicyCreateBasicX509",
        @"SecPolicyCreateRevocation", @"SecPolicyCreateWithProperties"
    ];

    // Identity APIs
    NSArray *identityPatterns = @[
        @"SecIdentityCreate", @"SecIdentityCopyCertificate",
        @"SecIdentityCopyPrivateKey", @"SecPKCS12Import",
        @"SecIdentityCopyPreference", @"SecIdentitySetPreference"
    ];

    [self scanStringsForPatterns:certPatterns inFile:file results:certOps maxResults:80];
    [self scanStringsForPatterns:trustPatterns inFile:file results:trustOps maxResults:80];
    [self scanStringsForPatterns:identityPatterns inFile:file results:identityOps maxResults:40];

    return @{
        @"certificate": [certOps copy],
        @"trust": [trustOps copy],
        @"identity": [identityOps copy]
    };
}

- (NSArray *)extractCredentialStrings:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Credential keywords (case-insensitive)
    NSArray *keywords = @[
        @"password", @"passwd", @"pwd", @"pass",
        @"credential", @"creds", @"secret", @"token",
        @"apikey", @"api_key", @"api-key", @"api key",
        @"private_key", @"privatekey", @"priv_key", @"private key",
        @"keychain", @"authorization", @"bearer",
        @"oauth", @"jwt", @"session", @"auth"
    ];

    // Scan string sections
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"] &&
            ![segment.segmentName isEqualToString:@"__DATA"]) continue;

        for (NSObject<HPSection> *section in segment.sections) {
            NSString *sectionName = section.sectionName;

            if ([sectionName containsString:@"string"] ||
                [sectionName containsString:@"cstring"]) {

                Address addr = section.startAddress;
                Address end = section.endAddress;

                while (addr < end && addr < end - 4) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:512];

                    if (str && str.length >= 4) {
                        NSString *lowerStr = [str lowercaseString];
                        for (NSString *keyword in keywords) {
                            if ([lowerStr containsString:keyword]) {
                                [results addObject:@{
                                    @"type": keyword,
                                    @"string": str,
                                    @"address": @(addr)
                                }];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 200) break;
                }
            }
        }
        if (results.count > 200) break;
    }

    return [results copy];
}

#pragma mark - Helper Methods

- (void)scanStringsForPatterns:(NSArray *)patterns
                        inFile:(NSObject<HPDisassembledFile> *)file
                       results:(NSMutableArray *)results
                    maxResults:(NSUInteger)maxResults {
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"] &&
            ![segment.segmentName isEqualToString:@"__DATA"]) continue;

        for (NSObject<HPSection> *section in segment.sections) {
            NSString *sectionName = section.sectionName;

            if ([sectionName containsString:@"string"] ||
                [sectionName containsString:@"cstring"] ||
                [sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address end = section.endAddress;

                while (addr < end && addr < end - 4) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:256];

                    if (str && str.length >= 3) {
                        for (NSString *pattern in patterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count >= maxResults) break;
                }
                if (results.count >= maxResults) break;
            }
        }
        if (results.count >= maxResults) break;
    }
}

- (NSString *)readStringAtAddress:(Address)address
                             file:(NSObject<HPDisassembledFile> *)file
                        maxLength:(NSUInteger)maxLength {
    NSMutableString *result = [NSMutableString string];

    for (NSUInteger i = 0; i < maxLength; i++) {
        uint8_t byte = [file readUInt8AtVirtualAddress:address + i];
        if (byte == 0) break;
        if (byte < 32 || byte > 126) return nil; // Not printable ASCII
        [result appendFormat:@"%c", byte];
    }

    return result.length > 0 ? [result copy] : nil;
}

@end

#pragma clang diagnostic pop
