/*
 NetworkAnalyzer.m
 Network Operations Analyzer Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "NetworkAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation NetworkAnalyzer

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
    return [self.services UUIDWithString:@"B8F9A0E3-5D4C-12EF-C975-0800200C9A77"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Network Operations Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive network operation detection: C socket APIs, Objective-C, Swift, and network string extraction";
}

- (NSString *)pluginAuthor {
    return @"Zeyad Azima";
}

- (NSString *)pluginCopyright {
    return @"©2025 Zeyad Azima";
}

- (NSString *)pluginVersion {
    return @"1.0.0";
}

- (NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"network-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Network Operations Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeNetwork:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeNetwork:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[NetworkAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[NetworkAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing Network Operations..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[NetworkAnalyzer]           NETWORK OPERATIONS ANALYSIS REPORT"];
    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[NetworkAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"            NETWORK OPERATIONS ANALYSIS REPORT                        \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n", [NSDate date]];
    [report appendString:@"\n"];

    // Phase 1: C Socket API Detection
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[NetworkAnalyzer] Phase 1: Detecting C socket APIs..."];
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *cAPIs = [self findCSocketAPIs:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] C SOCKET API DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:cAPIs[@"socket_ops"] title:@"Socket Operations" report:report document:document];
    [self logAndReportArray:cAPIs[@"dns_ops"] title:@"DNS Operations" report:report document:document];
    [self logAndReportArray:cAPIs[@"ssl_ops"] title:@"SSL/TLS Operations" report:report document:document];

    // Phase 2: Objective-C Network API Detection
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[NetworkAnalyzer] Phase 2: Detecting Objective-C network APIs..."];
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *objcAPIs = [self findObjCNetworkAPIs:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] OBJECTIVE-C NETWORK API DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:objcAPIs[@"nsurlsession"] title:@"NSURLSession APIs" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsurlconnection"] title:@"NSURLConnection APIs" report:report document:document];
    [self logAndReportArray:objcAPIs[@"cfnetwork"] title:@"CFNetwork APIs" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsstream"] title:@"NSStream APIs" report:report document:document];

    // Phase 3: Swift Network API Detection
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[NetworkAnalyzer] Phase 3: Detecting Swift network APIs..."];
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *swiftAPIs = [self findSwiftNetworkAPIs:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] SWIFT NETWORK API DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:swiftAPIs title:@"Swift Network APIs" report:report document:document];

    // Phase 4: Network String Extraction
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[NetworkAnalyzer] Phase 4: Extracting network strings..."];
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *networkStrings = [self findNetworkStrings:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] NETWORK STRING EXTRACTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:networkStrings[@"urls"] title:@"URLs Found" report:report document:document];
    [self logAndReportArray:networkStrings[@"ips"] title:@"IP Addresses" report:report document:document];
    [self logAndReportArray:networkStrings[@"domains"] title:@"Domain Names" report:report document:document];
    [self logAndReportArray:networkStrings[@"ports"] title:@"Port Numbers" report:report document:document];

    // Summary
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[NetworkAnalyzer] [5] ANALYSIS SUMMARY"];
    [document logInfoMessage:@"[NetworkAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] ANALYSIS SUMMARY\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSUInteger totalCAPIs = [cAPIs[@"socket_ops"] count] + [cAPIs[@"dns_ops"] count] + [cAPIs[@"ssl_ops"] count];
    NSUInteger totalObjCAPIs = [objcAPIs[@"nsurlsession"] count] + [objcAPIs[@"nsurlconnection"] count] +
                               [objcAPIs[@"cfnetwork"] count] + [objcAPIs[@"nsstream"] count];
    NSUInteger totalSwiftAPIs = [swiftAPIs count];
    NSUInteger totalStrings = [networkStrings[@"urls"] count] + [networkStrings[@"ips"] count] +
                              [networkStrings[@"domains"] count] + [networkStrings[@"ports"] count];

    [report appendFormat:@"C Socket APIs Found:         %lu\n", (unsigned long)totalCAPIs];
    [report appendFormat:@"  • Socket Operations:       %lu\n", (unsigned long)[cAPIs[@"socket_ops"] count]];
    [report appendFormat:@"  • DNS Operations:          %lu\n", (unsigned long)[cAPIs[@"dns_ops"] count]];
    [report appendFormat:@"  • SSL/TLS Operations:      %lu\n", (unsigned long)[cAPIs[@"ssl_ops"] count]];
    [report appendFormat:@"Objective-C APIs Found:      %lu\n", (unsigned long)totalObjCAPIs];
    [report appendFormat:@"  • NSURLSession:            %lu\n", (unsigned long)[objcAPIs[@"nsurlsession"] count]];
    [report appendFormat:@"  • NSURLConnection:         %lu\n", (unsigned long)[objcAPIs[@"nsurlconnection"] count]];
    [report appendFormat:@"  • CFNetwork:               %lu\n", (unsigned long)[objcAPIs[@"cfnetwork"] count]];
    [report appendFormat:@"  • NSStream:                %lu\n", (unsigned long)[objcAPIs[@"nsstream"] count]];
    [report appendFormat:@"Swift Network APIs Found:    %lu\n", (unsigned long)totalSwiftAPIs];
    [report appendFormat:@"Network Strings Found:       %lu\n", (unsigned long)totalStrings];
    [report appendFormat:@"  • URLs:                    %lu\n", (unsigned long)[networkStrings[@"urls"] count]];
    [report appendFormat:@"  • IP Addresses:            %lu\n", (unsigned long)[networkStrings[@"ips"] count]];
    [report appendFormat:@"  • Domain Names:            %lu\n", (unsigned long)[networkStrings[@"domains"] count]];
    [report appendFormat:@"  • Port Numbers:            %lu\n\n", (unsigned long)[networkStrings[@"ports"] count]];

    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] C Socket APIs Found:         %lu", (unsigned long)totalCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • Socket Operations:       %lu", (unsigned long)[cAPIs[@"socket_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • DNS Operations:          %lu", (unsigned long)[cAPIs[@"dns_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • SSL/TLS Operations:      %lu", (unsigned long)[cAPIs[@"ssl_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Objective-C APIs Found:      %lu", (unsigned long)totalObjCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • NSURLSession:            %lu", (unsigned long)[objcAPIs[@"nsurlsession"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • NSURLConnection:         %lu", (unsigned long)[objcAPIs[@"nsurlconnection"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • CFNetwork:               %lu", (unsigned long)[objcAPIs[@"cfnetwork"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • NSStream:                %lu", (unsigned long)[objcAPIs[@"nsstream"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Swift Network APIs Found:    %lu", (unsigned long)totalSwiftAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Network Strings Found:       %lu", (unsigned long)totalStrings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • URLs:                    %lu", (unsigned long)[networkStrings[@"urls"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • IP Addresses:            %lu", (unsigned long)[networkStrings[@"ips"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • Domain Names:            %lu", (unsigned long)[networkStrings[@"domains"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   • Port Numbers:            %lu", (unsigned long)[networkStrings[@"ports"] count]]];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[NetworkAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"Network_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    NSString *summary = [NSString stringWithFormat:
        @"Network Operations Analysis Complete\n\n"
        @"C APIs: %lu\n"
        @"Objective-C APIs: %lu\n"
        @"Swift APIs: %lu\n"
        @"Network Strings: %lu\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalCAPIs,
        (unsigned long)totalObjCAPIs,
        (unsigned long)totalSwiftAPIs,
        (unsigned long)totalStrings,
        tmpPath
    ];

    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[NetworkAnalyzer] Analysis Complete!"];
    [document logInfoMessage:@"[NetworkAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] C APIs: %lu", (unsigned long)totalCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Objective-C APIs: %lu", (unsigned long)totalObjCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Swift APIs: %lu", (unsigned long)totalSwiftAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Network Strings: %lu", (unsigned long)totalStrings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] Full report saved to: %@", tmpPath]];

    [document displayAlertWithMessageText:@"Network Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)findCSocketAPIs:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *socketOps = [NSMutableArray array];
    NSMutableArray *dnsOps = [NSMutableArray array];
    NSMutableArray *sslOps = [NSMutableArray array];

    NSArray *socketFunctions = @[
        @"socket", @"connect", @"bind", @"listen", @"accept", @"send", @"recv",
        @"sendto", @"recvfrom", @"sendmsg", @"recvmsg", @"shutdown", @"close",
        @"setsockopt", @"getsockopt", @"getpeername", @"getsockname",
        @"select", @"poll", @"epoll", @"kqueue", @"read", @"write"
    ];

    NSArray *dnsFunctions = @[
        @"getaddrinfo", @"freeaddrinfo", @"getnameinfo", @"gethostbyname",
        @"gethostbyaddr", @"getservbyname", @"getservbyport", @"inet_pton",
        @"inet_ntop", @"inet_addr", @"inet_ntoa", @"res_query", @"dns_"
    ];

    NSArray *sslFunctions = @[
        @"SSL_", @"SSLContext", @"SSLHandshake", @"SSLRead", @"SSLWrite",
        @"SSLClose", @"SSLSetConnection", @"TLS_", @"OpenSSL", @"BIO_",
        @"EVP_", @"X509_", @"PEM_", @"RSA_", @"SecureTransport"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check socket operations
                    for (NSString *func in socketFunctions) {
                        if ([name containsString:func]) {
                            [socketOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check DNS operations
                    for (NSString *func in dnsFunctions) {
                        if ([name containsString:func]) {
                            [dnsOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check SSL/TLS operations
                    for (NSString *func in sslFunctions) {
                        if ([name containsString:func]) {
                            [sslOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"socket_ops": socketOps,
        @"dns_ops": dnsOps,
        @"ssl_ops": sslOps
    };
}

- (NSDictionary *)findObjCNetworkAPIs:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *nsurlsession = [NSMutableArray array];
    NSMutableArray *nsurlconnection = [NSMutableArray array];
    NSMutableArray *cfnetwork = [NSMutableArray array];
    NSMutableArray *nsstream = [NSMutableArray array];

    NSArray *urlSessionMethods = @[
        @"NSURLSession", @"dataTaskWithURL", @"dataTaskWithRequest",
        @"uploadTask", @"downloadTask", @"streamTask", @"webSocketTask",
        @"sessionWithConfiguration", @"sharedSession", @"URLSession"
    ];

    NSArray *urlConnectionMethods = @[
        @"NSURLConnection", @"sendSynchronousRequest", @"sendAsynchronousRequest",
        @"connectionWithRequest", @"initWithRequest"
    ];

    NSArray *cfNetworkAPIs = @[
        @"CFNetwork", @"CFHTTPMessage", @"CFHTTPStream", @"CFHost",
        @"CFNetService", @"CFSocketStream", @"CFReadStream", @"CFWriteStream",
        @"CFStream"
    ];

    NSArray *streamMethods = @[
        @"NSInputStream", @"NSOutputStream", @"NSStream",
        @"inputStreamWithURL", @"outputStreamToFileAtPath",
        @"getStreamsToHost"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check NSURLSession
                    for (NSString *method in urlSessionMethods) {
                        if ([name containsString:method]) {
                            [nsurlsession addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check NSURLConnection
                    for (NSString *method in urlConnectionMethods) {
                        if ([name containsString:method]) {
                            [nsurlconnection addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check CFNetwork
                    for (NSString *api in cfNetworkAPIs) {
                        if ([name containsString:api]) {
                            [cfnetwork addObject:@{@"address": @(addr), @"api": name}];
                            break;
                        }
                    }

                    // Check NSStream
                    for (NSString *method in streamMethods) {
                        if ([name containsString:method]) {
                            [nsstream addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"nsurlsession": nsurlsession,
        @"nsurlconnection": nsurlconnection,
        @"cfnetwork": cfnetwork,
        @"nsstream": nsstream
    };
}

- (NSArray *)findSwiftNetworkAPIs:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *swiftOps = [NSMutableArray array];

    NSArray *swiftPatterns = @[
        @"URLSession", @"URLRequest", @"URLResponse", @"URLSessionTask",
        @"Network.NWConnection", @"Network.NWListener", @"Network.NWParameters",
        @"WebSocket", @"HTTPURLResponse", @"URLSessionConfiguration"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Skip non-Swift symbols
                    if ([name containsString:@"objc_"] || [name containsString:@"cfstring"] ||
                        [name hasPrefix:@"-["] || [name hasPrefix:@"+["] ||
                        [name containsString:@"_ptr"] || [name containsString:@"_data"]) {
                        addr += 4;
                        continue;
                    }

                    // Match Swift mangled names or explicit Swift types
                    BOOL isSwiftSymbol = [name hasPrefix:@"_$s"] || [name containsString:@"Swift"];

                    if (isSwiftSymbol) {
                        for (NSString *pattern in swiftPatterns) {
                            if ([name containsString:pattern]) {
                                [swiftOps addObject:@{@"address": @(addr), @"symbol": name}];
                                break;
                            }
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return swiftOps;
}

- (NSDictionary *)findNetworkStrings:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *urls = [NSMutableArray array];
    NSMutableArray *ips = [NSMutableArray array];
    NSMutableArray *domains = [NSMutableArray array];
    NSMutableArray *ports = [NSMutableArray array];

    // Scan all string sections
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            if ([section.sectionName containsString:@"string"] ||
                [section.sectionName containsString:@"cstring"] ||
                [section.sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address endAddr = section.endAddress;

                while (addr < endAddr) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:512];

                    if (str && str.length > 3) {
                        // URLs (http://, https://, ws://, wss://, ftp://)
                        if ([str hasPrefix:@"http://"] || [str hasPrefix:@"https://"] ||
                            [str hasPrefix:@"ws://"] || [str hasPrefix:@"wss://"] ||
                            [str hasPrefix:@"ftp://"] || [str hasPrefix:@"ftps://"]) {
                            [urls addObject:@{@"address": @(addr), @"url": str}];
                        }

                        // IP addresses (simple pattern: X.X.X.X)
                        NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:
                            @"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b" options:0 error:nil];
                        NSArray *ipMatches = [ipRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
                        if (ipMatches.count > 0) {
                            for (NSTextCheckingResult *match in ipMatches) {
                                NSString *ip = [str substringWithRange:match.range];
                                [ips addObject:@{@"address": @(addr), @"ip": ip}];
                            }
                        }

                        // Domain names (contains .com, .net, .org, etc.)
                        NSArray *tlds = @[@".com", @".net", @".org", @".edu", @".gov", @".mil",
                                         @".io", @".co", @".us", @".uk", @".de", @".fr", @".cn", @".ru"];
                        for (NSString *tld in tlds) {
                            if ([str containsString:tld] && ![str hasPrefix:@"http"]) {
                                // Extract potential domain
                                NSRegularExpression *domainRegex = [NSRegularExpression regularExpressionWithPattern:
                                    @"[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\\.[a-zA-Z]{2,}" options:0 error:nil];
                                NSArray *domainMatches = [domainRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
                                if (domainMatches.count > 0) {
                                    for (NSTextCheckingResult *match in domainMatches) {
                                        NSString *domain = [str substringWithRange:match.range];
                                        [domains addObject:@{@"address": @(addr), @"domain": domain}];
                                    }
                                }
                                break;
                            }
                        }

                        // Port numbers (common ports as strings: ":80", ":443", ":8080", etc.)
                        NSRegularExpression *portRegex = [NSRegularExpression regularExpressionWithPattern:
                            @":[0-9]{2,5}\\b" options:0 error:nil];
                        NSArray *portMatches = [portRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
                        if (portMatches.count > 0) {
                            for (NSTextCheckingResult *match in portMatches) {
                                NSString *port = [str substringWithRange:match.range];
                                [ports addObject:@{@"address": @(addr), @"port": port, @"context": str}];
                            }
                        }
                    }

                    addr++;
                }
            }
        }
    }

    return @{
        @"urls": urls,
        @"ips": ips,
        @"domains": domains,
        @"ports": ports
    };
}

#pragma mark - Helper Methods

- (void)logAndReportArray:(NSArray *)items title:(NSString *)title report:(NSMutableString *)report document:(NSObject<HPDocument> *)document {
    if (items.count > 0) {
        [report appendFormat:@"%@: %lu\n\n", title, (unsigned long)items.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer] %@: %lu", title, (unsigned long)items.count]];

        for (NSDictionary *item in items) {
            NSString *value = item[@"function"] ?: item[@"method"] ?: item[@"api"] ?: item[@"symbol"] ?:
                             item[@"url"] ?: item[@"ip"] ?: item[@"domain"] ?: item[@"port"];
            [report appendFormat:@"  [0x%llx] %@\n", [item[@"address"] unsignedLongLongValue], value];
            [document logInfoMessage:[NSString stringWithFormat:@"[NetworkAnalyzer]   [0x%llx] %@",
                [item[@"address"] unsignedLongLongValue], value]];
        }
        [report appendString:@"\n"];
    }
}

- (NSString *)readStringAtAddress:(Address)addr file:(NSObject<HPDisassembledFile> *)file maxLength:(NSUInteger)maxLength {
    NSMutableString *result = [NSMutableString string];

    for (NSUInteger i = 0; i < maxLength; i++) {
        uint8_t byte = [file readUInt8AtVirtualAddress:addr + i];

        if (byte == 0) {
            break;
        }

        if (byte >= 32 && byte < 127) {
            [result appendFormat:@"%c", (char)byte];
        } else if (byte == 9 || byte == 10 || byte == 13) {
            continue;
        } else {
            break;
        }
    }

    return result.length >= 4 ? result : nil;
}

@end

#pragma clang diagnostic pop
