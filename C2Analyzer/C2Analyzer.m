/*
 C2Analyzer.m
 Command & Control (C2) Communication Analyzer Plugin for Hopper Disassembler

 Comprehensive detection of C2 communication patterns across:
 - Network Communication (HTTP/HTTPS, DNS, raw sockets)
 - Domain Generation Algorithms (DGA)
 - Encryption & Encoding techniques
 - Known C2 Framework signatures
 - Data Exfiltration methods
 - Beaconing & Timing patterns

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

#import "C2Analyzer.h"

@implementation C2Analyzer

#pragma mark - HopperTool Protocol Methods

- (instancetype)initWithHopperServices:(NSObject <HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

+ (int)sdkVersion {
    return 6;
}

- (NSString *)pluginIdentifier {
    return @"com.zeyadazima.hopper.C2Analyzer";
}

- (NSString *)pluginUUID {
    return @"9A4D6F8C-7E2B-11EF-C345-0800200C9A99";
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"C2 Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive Command & Control (C2) communication analyzer detecting network patterns, DGA, encryption, C2 frameworks, exfiltration, and beaconing techniques";
}

- (NSString *)pluginAuthor {
    return @"Zeyad Azima";
}

- (NSString *)pluginCopyright {
    return @"Copyright (c) 2025 Zeyad Azima. All rights reserved.";
}

- (NSString *)pluginVersion {
    return @"1.0.0";
}

- (nonnull NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"c2analyzer"];
}

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"C2 Communication Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeC2:))
        }
    ];
}

#pragma mark - Main Analysis Entry Point

- (void)analyzeC2:(nullable id)sender {
    NSObject<HPDocument> *document = [self.services currentDocument];
    if (!document) {
        [self.services logMessage:@"[C2Analyzer] No document open"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[C2Analyzer] No disassembled file available"];
        return;
    }

    [document logInfoMessage:@"[C2Analyzer] Starting comprehensive C2 communication analysis..."];

    NSMutableString *report = [NSMutableString string];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"       COMMAND & CONTROL (C2) COMMUNICATION ANALYSIS\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    NSUInteger totalDetections = 0;

    // Phase 1: Network Communication Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 1: Analyzing network communication APIs..."];
    NSDictionary *networkResults = [self detectNetworkCommunication:file document:document];
    NSUInteger networkCount = [self addNetworkResultsToReport:report results:networkResults];
    totalDetections += networkCount;

    // Phase 2: Domain Generation Algorithm (DGA) Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 2: Analyzing DGA patterns..."];
    NSDictionary *dgaResults = [self detectDGAPatterns:file document:document];
    NSUInteger dgaCount = [self addDGAResultsToReport:report results:dgaResults];
    totalDetections += dgaCount;

    // Phase 3: Encryption & Encoding Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 3: Analyzing encryption and encoding..."];
    NSDictionary *cryptoResults = [self detectEncryptionEncoding:file document:document];
    NSUInteger cryptoCount = [self addCryptoResultsToReport:report results:cryptoResults];
    totalDetections += cryptoCount;

    // Phase 4: C2 Framework Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 4: Analyzing C2 framework signatures..."];
    NSDictionary *frameworkResults = [self detectC2Frameworks:file document:document];
    NSUInteger frameworkCount = [self addFrameworkResultsToReport:report results:frameworkResults];
    totalDetections += frameworkCount;

    // Phase 5: Data Exfiltration Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 5: Analyzing data exfiltration methods..."];
    NSDictionary *exfilResults = [self detectDataExfiltration:file document:document];
    NSUInteger exfilCount = [self addExfilResultsToReport:report results:exfilResults];
    totalDetections += exfilCount;

    // Phase 6: Beaconing & Timing Detection
    [document logInfoMessage:@"[C2Analyzer] Phase 6: Analyzing beaconing and timing patterns..."];
    NSDictionary *beaconResults = [self detectBeaconing:file document:document];
    NSUInteger beaconCount = [self addBeaconResultsToReport:report results:beaconResults];
    totalDetections += beaconCount;

    // Summary
    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                         SUMMARY\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total C2 Communication Indicators: %lu\n\n", (unsigned long)totalDetections];

    if (totalDetections > 0) {
        [report appendString:@"⚠️  C2 COMMUNICATION PATTERNS DETECTED\n\n"];
        [report appendString:@"Security Recommendations:\n"];
        [report appendString:@"1. Network Activity: Monitor network connections and DNS queries\n"];
        [report appendString:@"2. Traffic Analysis: Inspect encrypted traffic patterns\n"];
        [report appendString:@"3. Domain Analysis: Check domains against threat intelligence\n"];
        [report appendString:@"4. Behavior Monitoring: Watch for periodic beaconing patterns\n"];
        [report appendString:@"5. Sandbox Analysis: Run in controlled network environment\n"];
        [report appendString:@"6. IDS/IPS: Deploy network-based detection systems\n"];
        [report appendString:@"7. Endpoint Protection: Enable EDR solutions\n"];
        [report appendString:@"8. Forensics: Capture network traffic for analysis\n"];
    } else {
        [report appendString:@"✓ No obvious C2 communication patterns detected\n"];
        [report appendString:@"Note: Advanced C2 may use custom protocols or obfuscation\n"];
    }

    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];

    // Save report to file
    NSString *reportPath = [NSString stringWithFormat:@"/tmp/c2_analysis_%@.txt",
                           [[NSDate date] descriptionWithLocale:nil]];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@":" withString:@"-"];

    NSError *error = nil;
    [report writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (!error) {
        [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Report saved to: %@", reportPath]];
    }

    // Display summary in console
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[C2Analyzer] Analysis Complete"];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Total Indicators: %lu", (unsigned long)totalDetections]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Network APIs: %lu", (unsigned long)networkCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] DGA Patterns: %lu", (unsigned long)dgaCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Crypto/Encoding: %lu", (unsigned long)cryptoCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] C2 Frameworks: %lu", (unsigned long)frameworkCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Exfiltration: %lu", (unsigned long)exfilCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Beaconing: %lu", (unsigned long)beaconCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[C2Analyzer] Report saved to: %@", reportPath]];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
}

#pragma mark - Phase 1: Network Communication Detection

- (NSDictionary *)detectNetworkCommunication:(NSObject<HPDisassembledFile> *)file
                                    document:(NSObject<HPDocument> *)document {
    NSMutableArray *socketAPIs = [NSMutableArray array];
    NSMutableArray *httpAPIs = [NSMutableArray array];
    NSMutableArray *dnsAPIs = [NSMutableArray array];
    NSMutableArray *urlAPIs = [NSMutableArray array];
    NSMutableArray *sslAPIs = [NSMutableArray array];

    // BSD Socket APIs (15 patterns)
    NSArray *socketPatterns = @[
        @"socket", @"connect", @"bind", @"listen", @"accept",
        @"send", @"recv", @"sendto", @"recvfrom",
        @"setsockopt", @"getsockopt",
        @"getaddrinfo", @"gethostbyname", @"inet_addr", @"inet_ntoa"
    ];

    // HTTP/HTTPS APIs - C and Objective-C (20 patterns)
    NSArray *httpPatterns = @[
        // Objective-C
        @"NSURLSession", @"NSURLConnection", @"NSURLRequest", @"NSMutableURLRequest",
        @"NSURLSessionTask", @"NSURLSessionDataTask", @"NSURLSessionDownloadTask",
        @"dataTaskWithURL", @"dataTaskWithRequest",
        // Swift
        @"URLSession", @"URLRequest", @"dataTask",
        // C APIs
        @"curl_easy_init", @"curl_easy_perform", @"curl_easy_setopt",
        @"CFHTTPMessage", @"CFReadStream", @"CFWriteStream",
        // HTTP strings
        @"http://", @"https://"
    ];

    // DNS Query APIs (12 patterns)
    NSArray *dnsPatterns = @[
        @"res_query", @"res_search", @"res_init", @"dn_expand",
        @"DNSServiceQueryRecord", @"DNSServiceBrowse", @"DNSServiceResolve",
        @"kDNSServiceType", @"kDNSServiceClass",
        @"dns_", @"__dns_", @"dnssd"
    ];

    // URL Loading APIs (15 patterns)
    NSArray *urlPatterns = @[
        @"NSURL", @"URLWithString", @"initWithURL",
        @"CFURLCreate", @"CFURLCreateWithString",
        @"NSURLComponents", @"URLComponents",
        @"NSURLQueryItem", @"queryItems",
        @"percentEncoding", @"addingPercentEncoding",
        @"URLByAppendingPathComponent",
        @"absoluteString", @"absoluteURL", @"baseURL"
    ];

    // SSL/TLS APIs (18 patterns)
    NSArray *sslPatterns = @[
        @"SSLCreateContext", @"SSLSetConnection", @"SSLHandshake",
        @"SSLWrite", @"SSLRead", @"SSLClose",
        @"SecTrustEvaluate", @"SecTrustSetAnchorCertificates",
        @"kSecTrustResult",
        @"SSL_", @"TLS_", @"tls_",
        @"NSURLAuthenticationChallenge",
        @"didReceiveAuthenticationChallenge",
        @"SecureTransport",
        @"kSSLProtocol", @"SSLProtocol", @"TLSv1"
    ];

    [self scanStringsForPatterns:socketPatterns inFile:file results:socketAPIs maxResults:100];
    [self scanStringsForPatterns:httpPatterns inFile:file results:httpAPIs maxResults:100];
    [self scanStringsForPatterns:dnsPatterns inFile:file results:dnsAPIs maxResults:100];
    [self scanStringsForPatterns:urlPatterns inFile:file results:urlAPIs maxResults:100];
    [self scanStringsForPatterns:sslPatterns inFile:file results:sslAPIs maxResults:100];

    return @{
        @"socket": [socketAPIs copy],
        @"http": [httpAPIs copy],
        @"dns": [dnsAPIs copy],
        @"url": [urlAPIs copy],
        @"ssl": [sslAPIs copy]
    };
}

- (NSUInteger)addNetworkResultsToReport:(NSMutableString *)report
                                results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 1: NETWORK COMMUNICATION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *socketAPIs = results[@"socket"];
    NSArray *httpAPIs = results[@"http"];
    NSArray *dnsAPIs = results[@"dns"];
    NSArray *urlAPIs = results[@"url"];
    NSArray *sslAPIs = results[@"ssl"];

    [report appendFormat:@"BSD Socket APIs: %lu\n", (unsigned long)socketAPIs.count];
    if (socketAPIs.count > 0) {
        [report appendString:@"  Raw socket communication detected - potential custom protocol\n"];
        for (NSDictionary *match in [socketAPIs subarrayWithRange:NSMakeRange(0, MIN(5, socketAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (socketAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(socketAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += socketAPIs.count;

    [report appendFormat:@"HTTP/HTTPS APIs: %lu\n", (unsigned long)httpAPIs.count];
    if (httpAPIs.count > 0) {
        [report appendString:@"  HTTP(S) communication detected - typical C2 channel\n"];
        for (NSDictionary *match in [httpAPIs subarrayWithRange:NSMakeRange(0, MIN(5, httpAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (httpAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(httpAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += httpAPIs.count;

    [report appendFormat:@"DNS Query APIs: %lu\n", (unsigned long)dnsAPIs.count];
    if (dnsAPIs.count > 0) {
        [report appendString:@"  DNS queries detected - potential DNS tunneling or DGA\n"];
        for (NSDictionary *match in [dnsAPIs subarrayWithRange:NSMakeRange(0, MIN(5, dnsAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (dnsAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(dnsAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += dnsAPIs.count;

    [report appendFormat:@"URL Loading APIs: %lu\n", (unsigned long)urlAPIs.count];
    if (urlAPIs.count > 0) {
        [report appendString:@"  URL construction/loading detected\n"];
        for (NSDictionary *match in [urlAPIs subarrayWithRange:NSMakeRange(0, MIN(3, urlAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (urlAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(urlAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += urlAPIs.count;

    [report appendFormat:@"SSL/TLS APIs: %lu\n", (unsigned long)sslAPIs.count];
    if (sslAPIs.count > 0) {
        [report appendString:@"  Encrypted communication detected - C2 traffic likely encrypted\n"];
        for (NSDictionary *match in [sslAPIs subarrayWithRange:NSMakeRange(0, MIN(5, sslAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (sslAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(sslAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += sslAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No network communication APIs detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 2: Domain Generation Algorithm (DGA) Detection

- (NSDictionary *)detectDGAPatterns:(NSObject<HPDisassembledFile> *)file
                           document:(NSObject<HPDocument> *)document {
    NSMutableArray *cryptoFuncs = [NSMutableArray array];
    NSMutableArray *randomAPIs = [NSMutableArray array];
    NSMutableArray *timeAPIs = [NSMutableArray array];
    NSMutableArray *stringOps = [NSMutableArray array];

    // Cryptographic functions used in DGA (15 patterns)
    NSArray *cryptoPatterns = @[
        @"MD5", @"SHA1", @"SHA256", @"SHA512",
        @"CC_MD5", @"CC_SHA1", @"CC_SHA256",
        @"CCDigest", @"CCHmac",
        @"crc32", @"CRC32",
        @"hash", @"Hash",
        @"digest", @"Digest"
    ];

    // Random/Seed APIs for DGA (12 patterns)
    NSArray *randomPatterns = @[
        @"random", @"rand", @"srand", @"srandom",
        @"arc4random", @"CCRandomGenerateBytes",
        @"SecRandomCopyBytes",
        @"seed", @"Seed",
        @"entropy", @"Entropy",
        @"nonce"
    ];

    // Time-based seed APIs (10 patterns)
    NSArray *timePatterns = @[
        @"time", @"gettimeofday", @"clock_gettime",
        @"NSDate", @"CFAbsoluteTimeGetCurrent",
        @"mach_absolute_time",
        @"date", @"Date",
        @"timestamp", @"Timestamp"
    ];

    // String manipulation for domain generation (15 patterns)
    NSArray *stringPatterns = @[
        @"sprintf", @"snprintf", @"asprintf",
        @"strcat", @"strncat", @"strcpy", @"strncpy",
        @"stringWithFormat", @"appendString", @"appendFormat",
        @".com", @".net", @".org", @".info", @".biz"
    ];

    [self scanStringsForPatterns:cryptoPatterns inFile:file results:cryptoFuncs maxResults:100];
    [self scanStringsForPatterns:randomPatterns inFile:file results:randomAPIs maxResults:100];
    [self scanStringsForPatterns:timePatterns inFile:file results:timeAPIs maxResults:100];
    [self scanStringsForPatterns:stringPatterns inFile:file results:stringOps maxResults:100];

    return @{
        @"crypto": [cryptoFuncs copy],
        @"random": [randomAPIs copy],
        @"time": [timeAPIs copy],
        @"string": [stringOps copy]
    };
}

- (NSUInteger)addDGAResultsToReport:(NSMutableString *)report
                            results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 2: DOMAIN GENERATION ALGORITHM (DGA) DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *cryptoFuncs = results[@"crypto"];
    NSArray *randomAPIs = results[@"random"];
    NSArray *timeAPIs = results[@"time"];
    NSArray *stringOps = results[@"string"];

    [report appendFormat:@"Cryptographic Functions: %lu\n", (unsigned long)cryptoFuncs.count];
    if (cryptoFuncs.count > 0) {
        [report appendString:@"  Hash functions detected - commonly used for DGA\n"];
        for (NSDictionary *match in [cryptoFuncs subarrayWithRange:NSMakeRange(0, MIN(5, cryptoFuncs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (cryptoFuncs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(cryptoFuncs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += cryptoFuncs.count;

    [report appendFormat:@"Random/Seed APIs: %lu\n", (unsigned long)randomAPIs.count];
    if (randomAPIs.count > 0) {
        [report appendString:@"  Randomization detected - potential seed for domain generation\n"];
        for (NSDictionary *match in [randomAPIs subarrayWithRange:NSMakeRange(0, MIN(3, randomAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (randomAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(randomAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += randomAPIs.count;

    [report appendFormat:@"Time-Based Seed APIs: %lu\n", (unsigned long)timeAPIs.count];
    if (timeAPIs.count > 0) {
        [report appendString:@"  Time-based operations - DGAs often use date as seed\n"];
        for (NSDictionary *match in [timeAPIs subarrayWithRange:NSMakeRange(0, MIN(3, timeAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (timeAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(timeAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += timeAPIs.count;

    [report appendFormat:@"String Manipulation: %lu\n", (unsigned long)stringOps.count];
    if (stringOps.count > 0) {
        [report appendString:@"  String operations with TLDs - potential domain construction\n"];
        for (NSDictionary *match in [stringOps subarrayWithRange:NSMakeRange(0, MIN(5, stringOps.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (stringOps.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(stringOps.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += stringOps.count;

    if (total == 0) {
        [report appendString:@"✓ No DGA patterns detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 3: Encryption & Encoding Detection

- (NSDictionary *)detectEncryptionEncoding:(NSObject<HPDisassembledFile> *)file
                                  document:(NSObject<HPDocument> *)document {
    NSMutableArray *symmetricAPIs = [NSMutableArray array];
    NSMutableArray *asymmetricAPIs = [NSMutableArray array];
    NSMutableArray *encodingAPIs = [NSMutableArray array];
    NSMutableArray *customCrypto = [NSMutableArray array];

    // Symmetric encryption (18 patterns)
    NSArray *symmetricPatterns = @[
        @"AES", @"CCCrypt", @"CCCryptorCreate",
        @"kCCAlgorithmAES", @"kCCAlgorithmDES", @"kCCAlgorithm3DES",
        @"kCCEncrypt", @"kCCDecrypt",
        @"CCCryptorUpdate", @"CCCryptorFinal",
        @"ChaCha", @"Salsa20",
        @"RC4", @"Blowfish",
        @"cipher", @"Cipher",
        @"encrypt", @"decrypt"
    ];

    // Asymmetric encryption (15 patterns)
    NSArray *asymmetricPatterns = @[
        @"RSA", @"SecKeyCreateEncryptedData", @"SecKeyCreateDecryptedData",
        @"SecKeyEncrypt", @"SecKeyDecrypt",
        @"kSecKeyAlgorithmRSA",
        @"SecKeyGeneratePair", @"SecKeyCreateRandomKey",
        @"ECC", @"ECDH", @"ECDSA",
        @"SecKeyCreateSignature", @"SecKeyVerifySignature",
        @"public_key", @"private_key"
    ];

    // Encoding schemes (20 patterns)
    NSArray *encodingPatterns = @[
        @"Base64", @"base64", @"BASE64",
        @"base64Encoded", @"dataUsingEncoding",
        @"initWithBase64EncodedString",
        @"hex", @"Hex", @"HEX",
        @"hexadecimal",
        @"XOR", @"xor",
        @"percent", @"percentEncoding", @"URLEncoding",
        @"stringByAddingPercentEncoding",
        @"UTF8String", @"ASCII",
        @"encode", @"decode"
    ];

    // Custom crypto indicators (12 patterns)
    NSArray *customPatterns = @[
        @"sbox", @"s_box", @"SBox",
        @"permutation", @"substitution",
        @"key_schedule", @"round_key",
        @"obfuscate", @"deobfuscate",
        @"scramble", @"unscramble",
        @"mangle", @"unmangle"
    ];

    [self scanStringsForPatterns:symmetricPatterns inFile:file results:symmetricAPIs maxResults:100];
    [self scanStringsForPatterns:asymmetricPatterns inFile:file results:asymmetricAPIs maxResults:100];
    [self scanStringsForPatterns:encodingPatterns inFile:file results:encodingAPIs maxResults:100];
    [self scanStringsForPatterns:customPatterns inFile:file results:customCrypto maxResults:100];

    return @{
        @"symmetric": [symmetricAPIs copy],
        @"asymmetric": [asymmetricAPIs copy],
        @"encoding": [encodingAPIs copy],
        @"custom": [customCrypto copy]
    };
}

- (NSUInteger)addCryptoResultsToReport:(NSMutableString *)report
                               results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 3: ENCRYPTION & ENCODING DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *symmetricAPIs = results[@"symmetric"];
    NSArray *asymmetricAPIs = results[@"asymmetric"];
    NSArray *encodingAPIs = results[@"encoding"];
    NSArray *customCrypto = results[@"custom"];

    [report appendFormat:@"Symmetric Encryption: %lu\n", (unsigned long)symmetricAPIs.count];
    if (symmetricAPIs.count > 0) {
        [report appendString:@"  Symmetric crypto detected - likely C2 traffic encryption\n"];
        for (NSDictionary *match in [symmetricAPIs subarrayWithRange:NSMakeRange(0, MIN(5, symmetricAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (symmetricAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(symmetricAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += symmetricAPIs.count;

    [report appendFormat:@"Asymmetric Encryption: %lu\n", (unsigned long)asymmetricAPIs.count];
    if (asymmetricAPIs.count > 0) {
        [report appendString:@"  Public-key crypto detected - potential key exchange\n"];
        for (NSDictionary *match in [asymmetricAPIs subarrayWithRange:NSMakeRange(0, MIN(5, asymmetricAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (asymmetricAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(asymmetricAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += asymmetricAPIs.count;

    [report appendFormat:@"Encoding Schemes: %lu\n", (unsigned long)encodingAPIs.count];
    if (encodingAPIs.count > 0) {
        [report appendString:@"  Data encoding detected - Base64, hex, or custom encoding\n"];
        for (NSDictionary *match in [encodingAPIs subarrayWithRange:NSMakeRange(0, MIN(5, encodingAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (encodingAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(encodingAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += encodingAPIs.count;

    [report appendFormat:@"Custom Cryptography: %lu\n", (unsigned long)customCrypto.count];
    if (customCrypto.count > 0) {
        [report appendString:@"  Custom crypto implementation - avoid detection signature\n"];
        for (NSDictionary *match in [customCrypto subarrayWithRange:NSMakeRange(0, MIN(5, customCrypto.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (customCrypto.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(customCrypto.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += customCrypto.count;

    if (total == 0) {
        [report appendString:@"✓ No encryption or encoding detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 4: C2 Framework Detection

- (NSDictionary *)detectC2Frameworks:(NSObject<HPDisassembledFile> *)file
                            document:(NSObject<HPDocument> *)document {
    NSMutableArray *frameworkSigs = [NSMutableArray array];

    // Known C2 framework signatures (45 patterns)
    NSArray *frameworkPatterns = @[
        // Cobalt Strike
        @"beacon", @"Beacon", @"BEACON",
        @"teamserver", @"cobaltstrike",
        @"/.cobaltstrike", @"beacon.dll",
        @"stager", @"staged",
        @"malleable",

        // Metasploit
        @"meterpreter", @"Meterpreter", @"METERPRETER",
        @"metasploit", @"Metasploit",
        @"msf", @"msfvenom",
        @"reverse_tcp", @"reverse_http", @"reverse_https",
        @"bind_tcp",

        // Empire/PowerShell Empire
        @"empire", @"Empire",
        @"powershell empire",
        @"Invoke-Empire",
        @"PSEmpire",

        // Sliver
        @"sliver", @"Sliver", @"SLIVER",
        @"sliverpkg",
        @"implant", @"Implant",

        // Mythic
        @"mythic", @"Mythic",
        @"apfell",

        // Covenant
        @"covenant", @"Covenant",
        @"Grunt",

        // Havoc
        @"havoc", @"Havoc",
        @"demon", @"Demon",

        // Other frameworks
        @"brute_ratel", @"BruteRatel",
        @"nighthawk", @"Nighthawk",
        @"posh_c2", @"PoshC2"
    ];

    [self scanForC2Frameworks:file results:frameworkSigs frameworkPatterns:frameworkPatterns];

    return @{
        @"frameworks": [frameworkSigs copy]
    };
}

- (void)scanForC2Frameworks:(NSObject<HPDisassembledFile> *)file
                    results:(NSMutableArray *)results
         frameworkPatterns:(NSArray *)frameworkPatterns {
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"] &&
            ![segment.segmentName isEqualToString:@"__DATA"]) {
            continue;
        }

        for (NSObject<HPSection> *section in segment.sections) {
            NSString *sectionName = section.sectionName;

            if ([sectionName containsString:@"string"] ||
                [sectionName containsString:@"cstring"] ||
                [sectionName isEqualToString:@"__const"] ||
                [sectionName isEqualToString:@"__data"]) {

                Address addr = section.startAddress;
                Address end = section.endAddress;

                while (addr < end && addr < end - 4) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:256];

                    if (str && str.length >= 3) {
                        for (NSString *pattern in frameworkPatterns) {
                            if ([str containsString:pattern]) {
                                // Determine framework type
                                NSString *type = @"Unknown";
                                if ([str containsString:@"beacon"] || [str containsString:@"Beacon"] ||
                                    [str containsString:@"cobaltstrike"] || [str containsString:@"malleable"]) {
                                    type = @"Cobalt Strike";
                                } else if ([str containsString:@"meterpreter"] || [str containsString:@"Meterpreter"] ||
                                          [str containsString:@"metasploit"] || [str containsString:@"msf"]) {
                                    type = @"Metasploit";
                                } else if ([str containsString:@"empire"] || [str containsString:@"Empire"]) {
                                    type = @"Empire";
                                } else if ([str containsString:@"sliver"] || [str containsString:@"Sliver"]) {
                                    type = @"Sliver";
                                } else if ([str containsString:@"mythic"] || [str containsString:@"Mythic"]) {
                                    type = @"Mythic";
                                } else if ([str containsString:@"covenant"] || [str containsString:@"Covenant"]) {
                                    type = @"Covenant";
                                } else if ([str containsString:@"havoc"] || [str containsString:@"Havoc"] ||
                                          [str containsString:@"demon"] || [str containsString:@"Demon"]) {
                                    type = @"Havoc";
                                } else if ([str containsString:@"brute_ratel"] || [str containsString:@"BruteRatel"]) {
                                    type = @"Brute Ratel";
                                }

                                [results addObject:@{
                                    @"address": @(addr),
                                    @"string": str,
                                    @"type": type
                                }];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count >= 100) break;
                }
            }
            if (results.count >= 100) break;
        }
        if (results.count >= 100) break;
    }
}

- (NSUInteger)addFrameworkResultsToReport:(NSMutableString *)report
                                  results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 4: C2 FRAMEWORK DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSArray *frameworkSigs = results[@"frameworks"];

    [report appendFormat:@"C2 Framework Signatures: %lu\n", (unsigned long)frameworkSigs.count];

    if (frameworkSigs.count > 0) {
        [report appendString:@"\n⚠️  WARNING: Known C2 framework signatures detected!\n\n"];

        // Group by framework type
        NSMutableDictionary *grouped = [NSMutableDictionary dictionary];
        for (NSDictionary *sig in frameworkSigs) {
            NSString *type = sig[@"type"];
            if (!grouped[type]) {
                grouped[type] = [NSMutableArray array];
            }
            [grouped[type] addObject:sig];
        }

        for (NSString *type in [grouped.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            NSArray *sigs = grouped[type];
            [report appendFormat:@"  %@ Framework: %lu detections\n", type, (unsigned long)sigs.count];
            for (NSDictionary *sig in [sigs subarrayWithRange:NSMakeRange(0, MIN(3, sigs.count))]) {
                [report appendFormat:@"    • 0x%llx: %@\n",
                 [sig[@"address"] unsignedLongLongValue],
                 sig[@"string"]];
            }
            if (sigs.count > 3) {
                [report appendFormat:@"    ... and %lu more\n", (unsigned long)(sigs.count - 3)];
            }
            [report appendString:@"\n"];
        }
    } else {
        [report appendString:@"✓ No known C2 framework signatures detected\n\n"];
    }

    return frameworkSigs.count;
}

#pragma mark - Phase 5: Data Exfiltration Detection

- (NSDictionary *)detectDataExfiltration:(NSObject<HPDisassembledFile> *)file
                                document:(NSObject<HPDocument> *)document {
    NSMutableArray *compressionAPIs = [NSMutableArray array];
    NSMutableArray *archiveAPIs = [NSMutableArray array];
    NSMutableArray *chunkingAPIs = [NSMutableArray array];
    NSMutableArray *stegoAPIs = [NSMutableArray array];

    // Compression APIs (15 patterns)
    NSArray *compressionPatterns = @[
        @"compress", @"decompress", @"compression",
        @"zlib", @"gzip", @"deflate",
        @"NSDataCompression", @"compression_encode", @"compression_decode",
        @"COMPRESSION_", @"COMPRESSION_ZLIB", @"COMPRESSION_LZMA",
        @"bz2", @"lzma", @"lz4"
    ];

    // Archive APIs (12 patterns)
    NSArray *archivePatterns = @[
        @"zip", @"unzip", @"archive",
        @"tar", @"gzip",
        @"NSFileWrapper", @"fileWrapper",
        @"ZipArchive", @"SSZipArchive",
        @".zip", @".tar", @".gz"
    ];

    // Chunking/Splitting (10 patterns)
    NSArray *chunkingPatterns = @[
        @"chunk", @"Chunk", @"CHUNK",
        @"split", @"Split",
        @"segment", @"Segment",
        @"fragment", @"Fragment",
        @"part"
    ];

    // Steganography indicators (10 patterns)
    NSArray *stegoPatterns = @[
        @"steg", @"Steg", @"steganography",
        @"LSB", @"least_significant_bit",
        @"embed", @"embedded",
        @"hide", @"hidden",
        @"covert"
    ];

    [self scanStringsForPatterns:compressionPatterns inFile:file results:compressionAPIs maxResults:100];
    [self scanStringsForPatterns:archivePatterns inFile:file results:archiveAPIs maxResults:100];
    [self scanStringsForPatterns:chunkingPatterns inFile:file results:chunkingAPIs maxResults:100];
    [self scanStringsForPatterns:stegoPatterns inFile:file results:stegoAPIs maxResults:100];

    return @{
        @"compression": [compressionAPIs copy],
        @"archive": [archiveAPIs copy],
        @"chunking": [chunkingAPIs copy],
        @"steganography": [stegoAPIs copy]
    };
}

- (NSUInteger)addExfilResultsToReport:(NSMutableString *)report
                              results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 5: DATA EXFILTRATION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *compressionAPIs = results[@"compression"];
    NSArray *archiveAPIs = results[@"archive"];
    NSArray *chunkingAPIs = results[@"chunking"];
    NSArray *stegoAPIs = results[@"steganography"];

    [report appendFormat:@"Compression APIs: %lu\n", (unsigned long)compressionAPIs.count];
    if (compressionAPIs.count > 0) {
        [report appendString:@"  Data compression detected - reduce exfiltration bandwidth\n"];
        for (NSDictionary *match in [compressionAPIs subarrayWithRange:NSMakeRange(0, MIN(5, compressionAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (compressionAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(compressionAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += compressionAPIs.count;

    [report appendFormat:@"Archive APIs: %lu\n", (unsigned long)archiveAPIs.count];
    if (archiveAPIs.count > 0) {
        [report appendString:@"  Archive operations detected - bundle data for exfiltration\n"];
        for (NSDictionary *match in [archiveAPIs subarrayWithRange:NSMakeRange(0, MIN(3, archiveAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (archiveAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(archiveAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += archiveAPIs.count;

    [report appendFormat:@"Chunking/Splitting: %lu\n", (unsigned long)chunkingAPIs.count];
    if (chunkingAPIs.count > 0) {
        [report appendString:@"  Data chunking detected - split large files for transfer\n"];
        for (NSDictionary *match in [chunkingAPIs subarrayWithRange:NSMakeRange(0, MIN(3, chunkingAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (chunkingAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(chunkingAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += chunkingAPIs.count;

    [report appendFormat:@"Steganography: %lu\n", (unsigned long)stegoAPIs.count];
    if (stegoAPIs.count > 0) {
        [report appendString:@"  Steganography indicators - covert data hiding\n"];
        for (NSDictionary *match in [stegoAPIs subarrayWithRange:NSMakeRange(0, MIN(3, stegoAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (stegoAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(stegoAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += stegoAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No data exfiltration techniques detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 6: Beaconing & Timing Detection

- (NSDictionary *)detectBeaconing:(NSObject<HPDisassembledFile> *)file
                         document:(NSObject<HPDocument> *)document {
    NSMutableArray *sleepAPIs = [NSMutableArray array];
    NSMutableArray *timerAPIs = [NSMutableArray array];
    NSMutableArray *intervalAPIs = [NSMutableArray array];

    // Sleep/Delay APIs (15 patterns)
    NSArray *sleepPatterns = @[
        @"sleep", @"usleep", @"nanosleep",
        @"NSThread", @"sleepForTimeInterval",
        @"dispatch_after", @"dispatch_time",
        @"CFRunLoopRun",
        @"delay", @"Delay",
        @"wait", @"Wait",
        @"pause", @"Pause"
    ];

    // Timer APIs (12 patterns)
    NSArray *timerPatterns = @[
        @"NSTimer", @"timerWithTimeInterval", @"scheduledTimerWithTimeInterval",
        @"dispatch_source_create", @"DISPATCH_SOURCE_TYPE_TIMER",
        @"dispatch_source_set_timer",
        @"CFRunLoopTimer", @"CFRunLoopTimerCreate",
        @"timer", @"Timer",
        @"repeats", @"repeating"
    ];

    // Interval/Periodic (10 patterns)
    NSArray *intervalPatterns = @[
        @"interval", @"Interval",
        @"periodic", @"Periodic",
        @"frequency", @"Frequency",
        @"heartbeat", @"Heartbeat",
        @"callback", @"Callback"
    ];

    [self scanStringsForPatterns:sleepPatterns inFile:file results:sleepAPIs maxResults:100];
    [self scanStringsForPatterns:timerPatterns inFile:file results:timerAPIs maxResults:100];
    [self scanStringsForPatterns:intervalPatterns inFile:file results:intervalAPIs maxResults:100];

    return @{
        @"sleep": [sleepAPIs copy],
        @"timer": [timerAPIs copy],
        @"interval": [intervalAPIs copy]
    };
}

- (NSUInteger)addBeaconResultsToReport:(NSMutableString *)report
                               results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 6: BEACONING & TIMING DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *sleepAPIs = results[@"sleep"];
    NSArray *timerAPIs = results[@"timer"];
    NSArray *intervalAPIs = results[@"interval"];

    [report appendFormat:@"Sleep/Delay APIs: %lu\n", (unsigned long)sleepAPIs.count];
    if (sleepAPIs.count > 0) {
        [report appendString:@"  Sleep operations detected - potential jitter or rate limiting\n"];
        for (NSDictionary *match in [sleepAPIs subarrayWithRange:NSMakeRange(0, MIN(5, sleepAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (sleepAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(sleepAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += sleepAPIs.count;

    [report appendFormat:@"Timer APIs: %lu\n", (unsigned long)timerAPIs.count];
    if (timerAPIs.count > 0) {
        [report appendString:@"  Timer operations detected - periodic C2 callbacks\n"];
        for (NSDictionary *match in [timerAPIs subarrayWithRange:NSMakeRange(0, MIN(5, timerAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (timerAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(timerAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += timerAPIs.count;

    [report appendFormat:@"Interval/Periodic: %lu\n", (unsigned long)intervalAPIs.count];
    if (intervalAPIs.count > 0) {
        [report appendString:@"  Periodic operations detected - beaconing behavior\n"];
        for (NSDictionary *match in [intervalAPIs subarrayWithRange:NSMakeRange(0, MIN(5, intervalAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (intervalAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(intervalAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += intervalAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No beaconing or timing patterns detected\n\n"];
    }

    return total;
}

#pragma mark - Helper Methods

- (void)scanStringsForPatterns:(NSArray *)patterns
                        inFile:(NSObject<HPDisassembledFile> *)file
                       results:(NSMutableArray *)results
                    maxResults:(NSUInteger)maxResults {
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"] &&
            ![segment.segmentName isEqualToString:@"__DATA"]) {
            continue;
        }

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
                                [results addObject:@{
                                    @"address": @(addr),
                                    @"string": str
                                }];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count >= maxResults) break;
                }
            }
            if (results.count >= maxResults) break;
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

        if (byte == 0) {
            break;
        }

        if (byte >= 32 && byte <= 126) {
            [result appendFormat:@"%c", byte];
        } else {
            break;
        }
    }

    return result.length > 0 ? result : nil;
}

@end
