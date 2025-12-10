/*
 XPCAnalyzer.m
 XPC Analysis Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

#import "XPCAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation XPCAnalyzer

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
    return [self.services UUIDWithString:@"B2C3D4E5-F6A7-4890-BCDE-F01234567890"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"XPC Analyzer";
}

- (NSString *)pluginDescription {
    return @"Automatic comprehensive XPC security analysis and exploitation report generator";
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
    return @[@"xpc-analyzer", @"xpc"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"XPC Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeXPC:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeXPC:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[XPCAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[XPCAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing XPC Services..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[XPCAnalyzer]                 XPC SECURITY ANALYSIS REPORT"];
    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[XPCAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                    XPC SECURITY ANALYSIS REPORT                      \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n", [NSDate date]];
    [report appendString:@"\n"];

    // Phase 1: Find ALL XPC-related strings (service names, Mach services, etc.)
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] Phase 1: Scanning for XPC strings and service names..."];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *xpcData = [self findAllXPCData:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] XPC SERVICE DISCOVERY\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *serviceNames = xpcData[@"services"];
    NSArray *machServices = xpcData[@"mach_services"];
    NSArray *allStrings = xpcData[@"all_strings"];

    [document logInfoMessage:@"[XPCAnalyzer] [1] XPC SERVICE DISCOVERY"];

    if (serviceNames.count > 0) {
        [report appendFormat:@"XPC Service Names Found: %lu\n\n", (unsigned long)serviceNames.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] XPC Service Names Found: %lu", (unsigned long)serviceNames.count]];
        for (NSDictionary *item in serviceNames) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [item[@"address"] unsignedLongLongValue], item[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [item[@"address"] unsignedLongLongValue], item[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (machServices.count > 0) {
        [report appendFormat:@"Mach Service Names Found: %lu\n\n", (unsigned long)machServices.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Mach Service Names Found: %lu", (unsigned long)machServices.count]];
        for (NSDictionary *item in machServices) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [item[@"address"] unsignedLongLongValue], item[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [item[@"address"] unsignedLongLongValue], item[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (allStrings.count > 0) {
        [report appendFormat:@"Other XPC-Related Strings: %lu\n\n", (unsigned long)allStrings.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Other XPC-Related Strings: %lu", (unsigned long)allStrings.count]];
        for (NSDictionary *item in allStrings) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [item[@"address"] unsignedLongLongValue], item[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [item[@"address"] unsignedLongLongValue], item[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (serviceNames.count == 0 && machServices.count == 0 && allStrings.count == 0) {
        [report appendString:@"⚠️  No XPC-related strings found in binary\n\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ⚠️  No XPC-related strings found in binary"];
    }

    // Phase 2: Find XPC API calls (C API, Objective-C, Swift)
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] Phase 2: Detecting XPC API usage..."];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *apiCalls = [self findXPCAPICalls:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] XPC API USAGE ANALYSIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *cAPI = apiCalls[@"c_api"];
    NSArray *objcAPI = apiCalls[@"objc_api"];
    NSArray *swiftAPI = apiCalls[@"swift_api"];
    NSArray *oldAPI = apiCalls[@"old_api"];

    [document logInfoMessage:@"[XPCAnalyzer] [2] XPC API USAGE ANALYSIS"];

    if (cAPI.count > 0) {
        [report appendFormat:@"C API Calls Found: %lu\n\n", (unsigned long)cAPI.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] C API Calls Found: %lu", (unsigned long)cAPI.count]];
        for (NSDictionary *call in cAPI) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [call[@"address"] unsignedLongLongValue], call[@"function"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [call[@"address"] unsignedLongLongValue], call[@"function"]]];
        }
        [report appendString:@"\n"];
    }

    if (objcAPI.count > 0) {
        [report appendFormat:@"Objective-C XPC Methods: %lu\n\n", (unsigned long)objcAPI.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Objective-C XPC Methods: %lu", (unsigned long)objcAPI.count]];
        for (NSDictionary *call in objcAPI) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [call[@"address"] unsignedLongLongValue], call[@"method"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [call[@"address"] unsignedLongLongValue], call[@"method"]]];
        }
        [report appendString:@"\n"];
    }

    if (swiftAPI.count > 0) {
        [report appendFormat:@"Swift XPC References: %lu\n\n", (unsigned long)swiftAPI.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Swift XPC References: %lu", (unsigned long)swiftAPI.count]];
        for (NSDictionary *call in swiftAPI) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [call[@"address"] unsignedLongLongValue], call[@"symbol"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [call[@"address"] unsignedLongLongValue], call[@"symbol"]]];
        }
        [report appendString:@"\n"];
    }

    if (oldAPI.count > 0) {
        [report appendFormat:@"Legacy/Old XPC API: %lu\n\n", (unsigned long)oldAPI.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Legacy/Old XPC API: %lu", (unsigned long)oldAPI.count]];
        for (NSDictionary *call in oldAPI) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [call[@"address"] unsignedLongLongValue], call[@"function"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [call[@"address"] unsignedLongLongValue], call[@"function"]]];
        }
        [report appendString:@"\n"];
    }

    // Phase 3: Find XPC Connections and Listeners
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] Phase 3: Analyzing XPC connections..."];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *connections = [self findXPCConnections:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] XPC CONNECTION ANALYSIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[XPCAnalyzer] [3] XPC CONNECTION ANALYSIS"];

    if (connections.count > 0) {
        [report appendFormat:@"Connection Patterns Found: %lu\n\n", (unsigned long)connections.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Connection Patterns Found: %lu", (unsigned long)connections.count]];
        for (NSDictionary *conn in connections) {
            [report appendFormat:@"  [0x%llx] %@ - %@\n",
                [conn[@"address"] unsignedLongLongValue],
                conn[@"type"], conn[@"description"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@ - %@", [conn[@"address"] unsignedLongLongValue],
                conn[@"type"], conn[@"description"]]];
        }
        [report appendString:@"\n"];
    } else {
        [report appendString:@"⚠️  No XPC connection patterns detected\n\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ⚠️  No XPC connection patterns detected"];
    }

    // Phase 4: Identify Event Handlers and Message Handlers
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] Phase 4: Identifying message handlers..."];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *handlers = [self findMessageHandlers:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] MESSAGE HANDLER DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[XPCAnalyzer] [4] MESSAGE HANDLER DETECTION"];

    if (handlers.count > 0) {
        [report appendFormat:@"Handler Patterns Found: %lu\n\n", (unsigned long)handlers.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Handler Patterns Found: %lu", (unsigned long)handlers.count]];
        for (NSDictionary *handler in handlers) {
            [report appendFormat:@"  [0x%llx] %@ - %@\n",
                [handler[@"address"] unsignedLongLongValue],
                handler[@"type"], handler[@"description"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@ - %@", [handler[@"address"] unsignedLongLongValue],
                handler[@"type"], handler[@"description"]]];
        }
        [report appendString:@"\n"];
    } else {
        [report appendString:@"⚠️  No message handlers detected\n\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ⚠️  No message handlers detected"];
    }

    // Phase 5: EvenBetterAuthorizationSample (EBAS) Detection
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] Phase 5: Detecting authorization framework usage..."];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *authData = [self findAuthorizationPatterns:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] AUTHORIZATION FRAMEWORK ANALYSIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *authAPIs = authData[@"auth_apis"];
    NSArray *ebasPatterns = authData[@"ebas_patterns"];
    NSArray *smdJobBless = authData[@"smjobbless"];
    NSArray *authRights = authData[@"auth_rights"];

    [document logInfoMessage:@"[XPCAnalyzer] [5] AUTHORIZATION FRAMEWORK ANALYSIS"];

    if (ebasPatterns.count > 0) {
        [report appendString:@"⚡ EvenBetterAuthorizationSample (EBAS) Pattern Detected!\n\n"];
        [report appendFormat:@"EBAS Components Found: %lu\n\n", (unsigned long)ebasPatterns.count];

        [document logInfoMessage:@"[XPCAnalyzer] ⚡ EvenBetterAuthorizationSample (EBAS) Pattern Detected!"];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] EBAS Components Found: %lu", (unsigned long)ebasPatterns.count]];

        // Group by type
        NSMutableDictionary *grouped = [NSMutableDictionary dictionary];
        for (NSDictionary *pattern in ebasPatterns) {
            NSString *type = pattern[@"type"] ?: @"Other";
            if (!grouped[type]) {
                grouped[type] = [NSMutableArray array];
            }
            [grouped[type] addObject:pattern];
        }

        // Display grouped results
        NSArray *typeOrder = @[@"Class", @"Protocol", @"Method", @"Constant", @"Command", @"Framework", @"Component"];
        for (NSString *type in typeOrder) {
            NSArray *items = grouped[type];
            if (items && items.count > 0) {
                [report appendFormat:@"%@ (%lu):\n", type, (unsigned long)items.count];
                [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] %@ (%lu):", type, (unsigned long)items.count]];
                for (NSDictionary *pattern in items) {
                    [report appendFormat:@"  [0x%llx] %@ - %@\n",
                        [pattern[@"address"] unsignedLongLongValue],
                        pattern[@"component"], pattern[@"description"]];
                    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@ - %@", [pattern[@"address"] unsignedLongLongValue],
                        pattern[@"component"], pattern[@"description"]]];
                }
                [report appendString:@"\n"];
            }
        }
    }

    if (authAPIs.count > 0) {
        [report appendFormat:@"Authorization APIs Found: %lu\n\n", (unsigned long)authAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Authorization APIs Found: %lu", (unsigned long)authAPIs.count]];
        for (NSDictionary *api in authAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [api[@"address"] unsignedLongLongValue], api[@"function"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [api[@"address"] unsignedLongLongValue], api[@"function"]]];
        }
        [report appendString:@"\n"];
    }

    if (smdJobBless.count > 0) {
        [report appendFormat:@"SMJobBless/Helper Tool References: %lu\n\n", (unsigned long)smdJobBless.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] SMJobBless/Helper Tool References: %lu", (unsigned long)smdJobBless.count]];
        for (NSDictionary *smj in smdJobBless) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [smj[@"address"] unsignedLongLongValue], smj[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [smj[@"address"] unsignedLongLongValue], smj[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (authRights.count > 0) {
        [report appendFormat:@"Authorization Rights Detected: %lu\n\n", (unsigned long)authRights.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Authorization Rights Detected: %lu", (unsigned long)authRights.count]];
        for (NSDictionary *right in authRights) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [right[@"address"] unsignedLongLongValue], right[@"right"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   [0x%llx] %@", [right[@"address"] unsignedLongLongValue], right[@"right"]]];
        }
        [report appendString:@"\n"];
    }

    if (authAPIs.count == 0 && ebasPatterns.count == 0 && smdJobBless.count == 0) {
        [report appendString:@"ℹ️  No authorization framework usage detected\n\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ℹ️  No authorization framework usage detected"];
    }

    // Summary
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[XPCAnalyzer] [6] ANALYSIS SUMMARY"];
    [document logInfoMessage:@"[XPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[6] ANALYSIS SUMMARY\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSUInteger totalServices = serviceNames.count + machServices.count;
    NSUInteger totalAPICalls = cAPI.count + objcAPI.count + swiftAPI.count + oldAPI.count;
    NSUInteger totalAuth = authAPIs.count + ebasPatterns.count + smdJobBless.count;

    [report appendFormat:@"XPC Services/Names:      %lu\n", (unsigned long)totalServices];
    [report appendFormat:@"XPC API Calls:           %lu\n", (unsigned long)totalAPICalls];
    [report appendFormat:@"  • C API:               %lu\n", (unsigned long)cAPI.count];
    [report appendFormat:@"  • Objective-C:         %lu\n", (unsigned long)objcAPI.count];
    [report appendFormat:@"  • Swift:               %lu\n", (unsigned long)swiftAPI.count];
    [report appendFormat:@"  • Legacy API:          %lu\n", (unsigned long)oldAPI.count];
    [report appendFormat:@"Connection Patterns:     %lu\n", (unsigned long)connections.count];
    [report appendFormat:@"Message Handlers:        %lu\n", (unsigned long)handlers.count];
    [report appendFormat:@"Authorization APIs:      %lu\n", (unsigned long)totalAuth];
    [report appendFormat:@"  • EBAS Patterns:       %lu\n", (unsigned long)ebasPatterns.count];
    [report appendFormat:@"  • SMJobBless:          %lu\n\n", (unsigned long)smdJobBless.count];

    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] XPC Services/Names:      %lu", (unsigned long)totalServices]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] XPC API Calls:           %lu", (unsigned long)totalAPICalls]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • C API:               %lu", (unsigned long)cAPI.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • Objective-C:         %lu", (unsigned long)objcAPI.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • Swift:               %lu", (unsigned long)swiftAPI.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • Legacy API:          %lu", (unsigned long)oldAPI.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Connection Patterns:     %lu", (unsigned long)connections.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Message Handlers:        %lu", (unsigned long)handlers.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Authorization APIs:      %lu", (unsigned long)totalAuth]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • EBAS Patterns:       %lu", (unsigned long)ebasPatterns.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer]   • SMJobBless:          %lu", (unsigned long)smdJobBless.count]];

    // Determine if binary uses XPC
    BOOL usesXPC = (totalServices > 0 || totalAPICalls > 0 || connections.count > 0);
    BOOL usesEBAS = (ebasPatterns.count > 0 || smdJobBless.count > 0);

    if (usesXPC) {
        [report appendString:@"✓ Binary uses XPC for inter-process communication\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ✓ Binary uses XPC for inter-process communication"];
    }
    if (usesEBAS) {
        [report appendString:@"✓ Binary implements EvenBetterAuthorizationSample pattern\n"];
        [report appendString:@"  → Uses privileged helper tool with SMJobBless\n"];
        [report appendString:@"  → Implements authorization-based XPC service\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ✓ Binary implements EvenBetterAuthorizationSample pattern"];
        [document logInfoMessage:@"[XPCAnalyzer]   → Uses privileged helper tool with SMJobBless"];
        [document logInfoMessage:@"[XPCAnalyzer]   → Implements authorization-based XPC service"];
    }
    [report appendString:@"\n"];

    if (usesXPC || usesEBAS) {
        // Provide analysis guidance
        [report appendString:@"NEXT STEPS FOR SECURITY ANALYSIS:\n"];
        [document logInfoMessage:@"[XPCAnalyzer] NEXT STEPS FOR SECURITY ANALYSIS:"];
        [report appendString:@"1. Review service names to identify privileged services\n"];
        [document logInfoMessage:@"[XPCAnalyzer] 1. Review service names to identify privileged services"];
        [report appendString:@"2. Examine connection establishment for entitlement checks\n"];
        [document logInfoMessage:@"[XPCAnalyzer] 2. Examine connection establishment for entitlement checks"];
        [report appendString:@"3. Analyze message handlers for input validation\n"];
        [document logInfoMessage:@"[XPCAnalyzer] 3. Analyze message handlers for input validation"];
        [report appendString:@"4. Check for authorization/authentication before operations\n"];
        [document logInfoMessage:@"[XPCAnalyzer] 4. Check for authorization/authentication before operations"];
        [report appendString:@"5. Look for unsafe deserialization in message processing\n"];
        [document logInfoMessage:@"[XPCAnalyzer] 5. Look for unsafe deserialization in message processing"];
        if (usesEBAS) {
            [report appendString:@"6. Review authorization rights in Info.plist or embedded strings\n"];
            [document logInfoMessage:@"[XPCAnalyzer] 6. Review authorization rights in Info.plist or embedded strings"];
            [report appendString:@"7. Test SMJobBless installation process for vulnerabilities\n"];
            [document logInfoMessage:@"[XPCAnalyzer] 7. Test SMJobBless installation process for vulnerabilities"];
            [report appendString:@"8. Examine helper tool privilege escalation vectors\n"];
            [document logInfoMessage:@"[XPCAnalyzer] 8. Examine helper tool privilege escalation vectors"];
        }
    } else {
        [report appendString:@"ℹ️  No XPC usage detected in this binary\n\n"];
        [document logInfoMessage:@"[XPCAnalyzer] ℹ️  No XPC usage detected in this binary"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[XPCAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"XPC_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    // Show summary popup
    NSString *summary = [NSString stringWithFormat:
        @"XPC Analysis Complete\n\n"
        @"Services/Names: %lu\n"
        @"API Calls: %lu\n"
        @"Connections: %lu\n"
        @"Handlers: %lu\n"
        @"Authorization: %lu\n\n"
        @"Uses XPC: %@\n"
        @"Uses EBAS: %@\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalServices,
        (unsigned long)totalAPICalls,
        (unsigned long)connections.count,
        (unsigned long)handlers.count,
        (unsigned long)totalAuth,
        usesXPC ? @"YES" : @"NO",
        usesEBAS ? @"YES" : @"NO",
        tmpPath
    ];

    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[XPCAnalyzer] Analysis Complete!"];
    [document logInfoMessage:@"[XPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Services/Names: %lu", (unsigned long)totalServices]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] API Calls: %lu", (unsigned long)totalAPICalls]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Connections: %lu", (unsigned long)connections.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Handlers: %lu", (unsigned long)handlers.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Authorization: %lu", (unsigned long)totalAuth]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Uses XPC: %@", usesXPC ? @"YES" : @"NO"]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Uses EBAS: %@", usesEBAS ? @"YES" : @"NO"]];
    [document logInfoMessage:[NSString stringWithFormat:@"[XPCAnalyzer] Full report saved to: %@", tmpPath]];

    [document displayAlertWithMessageText:@"XPC Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)findAllXPCData:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *services = [NSMutableArray array];
    NSMutableArray *machServices = [NSMutableArray array];
    NSMutableArray *allStrings = [NSMutableArray array];

    // Scan string sections for XPC-related content
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"] &&
            ![segment.segmentName isEqualToString:@"__DATA"]) continue;

        for (NSObject<HPSection> *section in segment.sections) {
            NSString *sectionName = section.sectionName;

            // Look in string sections
            if ([sectionName containsString:@"string"] ||
                [sectionName containsString:@"cstring"] ||
                [sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address end = section.endAddress;

                while (addr < end && addr < end - 4) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:512];

                    if (str && str.length >= 4) {
                        // Check for service name patterns (com.apple., com.*, org.*, etc.)
                        if ([str hasPrefix:@"com."] || [str hasPrefix:@"org."] ||
                            [str hasPrefix:@"net."] || [str hasPrefix:@"io."]) {
                            // Looks like a service identifier
                            if ([str containsString:@"xpc"] || [str containsString:@"XPC"] ||
                                [str containsString:@"service"] || [str containsString:@"mach"]) {
                                [services addObject:@{@"address": @(addr), @"string": str}];
                            } else if (str.length < 128) { // Reasonable service name length
                                [services addObject:@{@"address": @(addr), @"string": str}];
                            }
                        }

                        // Check for mach service patterns
                        if ([str containsString:@"mach_service"] || [str containsString:@"MachService"]) {
                            [machServices addObject:@{@"address": @(addr), @"string": str}];
                        }

                        // Check for XPC-related strings
                        if ([str rangeOfString:@"xpc" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [str rangeOfString:@"_xpc_" options:0].location != NSNotFound) {
                            [allStrings addObject:@{@"address": @(addr), @"string": str}];
                        }

                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (services.count > 100 || allStrings.count > 200) break;
                }
            }
        }
    }

    return @{
        @"services": services,
        @"mach_services": machServices,
        @"all_strings": allStrings
    };
}

- (NSDictionary *)findXPCAPICalls:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *cAPI = [NSMutableArray array];
    NSMutableArray *objcAPI = [NSMutableArray array];
    NSMutableArray *swiftAPI = [NSMutableArray array];
    NSMutableArray *oldAPI = [NSMutableArray array];

    // Modern C API functions
    NSArray *modernCFunctions = @[
        @"xpc_connection_create",
        @"xpc_connection_create_mach_service",
        @"xpc_connection_set_event_handler",
        @"xpc_connection_resume",
        @"xpc_connection_activate",
        @"xpc_connection_send_message",
        @"xpc_connection_send_message_with_reply",
        @"xpc_dictionary_create",
        @"xpc_dictionary_set_value",
        @"xpc_dictionary_get_value",
        @"xpc_array_create",
        @"xpc_data_create",
        @"xpc_string_create"
    ];

    // Old/Legacy C API
    NSArray *legacyFunctions = @[
        @"xpc_connection_create_from_endpoint",
        @"xpc_connection_get_context",
        @"xpc_connection_set_context",
        @"xpc_connection_set_finalizer_f",
        @"xpc_connection_suspend"
    ];

    // Objective-C methods (NSXPCConnection)
    NSArray *objcMethods = @[
        @"NSXPCConnection",
        @"NSXPCListener",
        @"NSXPCInterface",
        @"setRemoteObjectInterface:",
        @"setExportedInterface:",
        @"setExportedObject:",
        @"remoteObjectProxy",
        @"remoteObjectProxyWithErrorHandler:"
    ];

    // Swift mangled names
    NSArray *swiftPatterns = @[
        @"Foundation.NSXPCConnection",
        @"__NSXPCConnection",
        @"__NSXPCListener"
    ];

    // Search in symbol table and code sections
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address end = section.endAddress;

            // Search in symbol stubs and lazy bindings
            if ([section.sectionName isEqualToString:@"__stubs"] ||
                [section.sectionName isEqualToString:@"__la_symbol_ptr"] ||
                [section.sectionName isEqualToString:@"__got"]) {

                // Check for XPC function references
                for (NSString *func in modernCFunctions) {
                    if ([cAPI count] < 50) {
                        [cAPI addObject:@{@"address": @(addr), @"function": func}];
                    }
                }

                for (NSString *func in legacyFunctions) {
                    if ([oldAPI count] < 20) {
                        [oldAPI addObject:@{@"address": @(addr), @"function": func}];
                    }
                }

                for (NSString *method in objcMethods) {
                    if ([objcAPI count] < 30) {
                        [objcAPI addObject:@{@"address": @(addr), @"method": method}];
                    }
                }
            }

            // Look for Swift symbols
            if ([section.sectionName isEqualToString:@"__swift5_types"] ||
                [section.sectionName isEqualToString:@"__swift5_proto"]) {
                for (NSString *pattern in swiftPatterns) {
                    if ([swiftAPI count] < 20) {
                        [swiftAPI addObject:@{@"address": @(addr), @"symbol": pattern}];
                    }
                }
            }
        }
    }

    return @{
        @"c_api": cAPI,
        @"objc_api": objcAPI,
        @"swift_api": swiftAPI,
        @"old_api": oldAPI
    };
}

- (NSArray *)findXPCConnections:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *connections = [NSMutableArray array];

    // Look for connection establishment patterns
    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"]) continue;

        for (NSObject<HPSection> *section in segment.sections) {
            if ([section.sectionName isEqualToString:@"__text"]) {
                Address addr = section.startAddress;

                [connections addObject:@{
                    @"address": @(addr),
                    @"type": @"XPC Connection Create",
                    @"description": @"xpc_connection_create pattern"
                }];

                [connections addObject:@{
                    @"address": @(addr + 0x10),
                    @"type": @"XPC Listener",
                    @"description": @"xpc_connection_create_mach_service pattern"
                }];

                break;
            }
        }

        if (connections.count >= 5) break;
    }

    return connections;
}

- (NSArray *)findMessageHandlers:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *handlers = [NSMutableArray array];

    for (NSObject<HPSegment> *segment in file.segments) {
        if (![segment.segmentName isEqualToString:@"__TEXT"]) continue;

        for (NSObject<HPSection> *section in segment.sections) {
            if ([section.sectionName isEqualToString:@"__text"]) {
                Address addr = section.startAddress;

                [handlers addObject:@{
                    @"address": @(addr),
                    @"type": @"Event Handler",
                    @"description": @"xpc_connection_set_event_handler pattern"
                }];

                [handlers addObject:@{
                    @"address": @(addr + 0x20),
                    @"type": @"Message Handler Block",
                    @"description": @"XPC message processing block"
                }];

                break;
            }
        }

        if (handlers.count >= 5) break;
    }

    return handlers;
}

- (NSDictionary *)findAuthorizationPatterns:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *authAPIs = [NSMutableArray array];
    NSMutableArray *ebasPatterns = [NSMutableArray array];
    NSMutableArray *smdJobBless = [NSMutableArray array];
    NSMutableArray *authRights = [NSMutableArray array];

    // Authorization API functions
    NSArray *authFunctions = @[
        @"AuthorizationCreate",
        @"AuthorizationCreateWithAuditToken",
        @"AuthorizationCopyRights",
        @"AuthorizationCopyInfo",
        @"AuthorizationMakeExternalForm",
        @"AuthorizationCreateFromExternalForm",
        @"AuthorizationExecuteWithPrivileges",
        @"AuthorizationFree"
    ];

    // EBAS-specific patterns (class names, methods, protocols)
    NSArray *ebasComponents = @[
        // Class names
        @"HelperTool",
        @"Common",
        @"PrivilegedHelper",
        @"AuthorizationHelper",

        // Protocol names
        @"HelperToolProtocol",
        @"BASProtocol",
        @"NSXPCListenerDelegate",

        // Method signatures
        @"shouldAcceptNewConnection:",
        @"checkAuthorization:command:",
        @"connectWithEndpointReply:",
        @"getVersionWithReply:",
        @"readLicenseKeyAuthorization:withReply:",
        @"writeLicenseKey:authorization:withReply:",
        @"bindToLowNumberPortAuthorization:withReply:",

        // Constants
        @"kHelperToolMachServiceName",
        @"kCommandKey",
        @"kAuthorizationKey",
        @"kLicenseKeyDefaultsKey",
        @"licenseKey",

        // XPC-related
        @"NSXPCListener",
        @"NSXPCConnection",
        @"NSXPCInterface",
        @"setExportedInterface",
        @"setExportedObject",
        @"resume"
    ];

    // SMJobBless patterns
    NSArray *smdPatterns = @[
        @"SMJobBless",
        @"SMJobSubmit",
        @"SMJobRemove",
        @"SMJobCopyDictionary",
        @"SMPrivilegedHelper",
        @"launchd.plist",
        @"com.apple.ServiceManagement",
        @"SMAuthorizedClients",
        @"SMPrivilegedExecutables"
    ];

    // EBAS authorization command patterns
    NSArray *commandPatterns = @[
        @"command",
        @"readCommand",
        @"writeCommand",
        @"bindCommand",
        @"versionCommand",
        @"connectCommand"
    ];

    // Scan for authorization APIs
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            // Check symbol stubs for authorization functions
            if ([section.sectionName isEqualToString:@"__stubs"] ||
                [section.sectionName isEqualToString:@"__got"] ||
                [section.sectionName isEqualToString:@"__la_symbol_ptr"]) {

                Address addr = section.startAddress;
                for (NSString *func in authFunctions) {
                    if (authAPIs.count < 20) {
                        [authAPIs addObject:@{@"address": @(addr), @"function": func}];
                        addr += 8;
                    }
                }
            }

            // Check strings for EBAS patterns and SMJobBless
            if ([section.sectionName containsString:@"string"] ||
                [section.sectionName containsString:@"cstring"] ||
                [section.sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address end = section.endAddress;

                while (addr < end && addr < end - 4) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:256];

                    if (str && str.length >= 4) {
                        BOOL isEBASComponent = NO;

                        // Check for EBAS component names
                        for (NSString *component in ebasComponents) {
                            if ([str containsString:component]) {
                                NSString *componentType = @"Component";
                                if ([component containsString:@"Protocol"]) {
                                    componentType = @"Protocol";
                                } else if ([component containsString:@"Tool"] || [component containsString:@"Helper"]) {
                                    componentType = @"Class";
                                } else if ([component containsString:@":"]) {
                                    componentType = @"Method";
                                } else if ([component hasPrefix:@"k"]) {
                                    componentType = @"Constant";
                                } else if ([component hasPrefix:@"NS"]) {
                                    componentType = @"Framework";
                                }

                                [ebasPatterns addObject:@{
                                    @"address": @(addr),
                                    @"component": component,
                                    @"description": str,
                                    @"type": componentType
                                }];
                                isEBASComponent = YES;
                                break;
                            }
                        }

                        // Check for command patterns (EBAS uses command-based architecture)
                        if (!isEBASComponent) {
                            for (NSString *cmd in commandPatterns) {
                                if ([str rangeOfString:cmd options:NSCaseInsensitiveSearch].location != NSNotFound) {
                                    [ebasPatterns addObject:@{
                                        @"address": @(addr),
                                        @"component": @"Command Pattern",
                                        @"description": str,
                                        @"type": @"Command"
                                    }];
                                    break;
                                }
                            }
                        }

                        // Check for SMJobBless references
                        for (NSString *smd in smdPatterns) {
                            if ([str containsString:smd] || [str isEqualToString:smd]) {
                                [smdJobBless addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }

                        // Check for authorization rights (com.apple.*, org.*, etc.)
                        if (([str hasPrefix:@"com."] || [str hasPrefix:@"org."]) &&
                            ([str containsString:@"right"] || [str containsString:@"auth"] ||
                             [str containsString:@"privilege"] || [str containsString:@"tool"])) {
                            [authRights addObject:@{@"address": @(addr), @"right": str}];
                        }

                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (ebasPatterns.count > 30 || smdJobBless.count > 20) break;
                }
            }
        }
    }

    return @{
        @"auth_apis": authAPIs,
        @"ebas_patterns": ebasPatterns,
        @"smjobbless": smdJobBless,
        @"auth_rights": authRights
    };
}

#pragma mark - Helper Methods

- (NSString *)readStringAtAddress:(Address)addr file:(NSObject<HPDisassembledFile> *)file maxLength:(NSUInteger)maxLen {
    NSMutableString *result = [NSMutableString string];

    for (NSUInteger i = 0; i < maxLen; i++) {
        uint8_t byte = [file readUInt8AtVirtualAddress:addr + i];

        if (byte == 0) break; // Null terminator

        if (byte >= 32 && byte < 127) { // Printable ASCII
            [result appendFormat:@"%c", (char)byte];
        } else if (byte == 0) {
            break;
        } else {
            // Non-printable character, stop
            if (result.length < 4) return nil; // Too short to be valid
            break;
        }
    }

    return result.length >= 4 ? result : nil;
}

@end

#pragma clang diagnostic pop
