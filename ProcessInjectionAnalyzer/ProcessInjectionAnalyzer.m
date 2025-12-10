/*
 ProcessInjectionAnalyzer.m
 Process & Code Injection Analyzer Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "ProcessInjectionAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation ProcessInjectionAnalyzer

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
    return [self.services UUIDWithString:@"7A3B9F2E-4D8C-11EF-9876-0800200C9A66"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Process & Code Injection Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive process and code injection detection: process creation, dynamic loading, Mach injection, and privilege escalation";
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
    return @[@"process-injection-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Process & Code Injection Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeProcessInjection:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeProcessInjection:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[ProcessInjectionAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[ProcessInjectionAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing Process & Code Injection..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer]      PROCESS & CODE INJECTION ANALYSIS REPORT"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"          PROCESS & CODE INJECTION ANALYSIS REPORT                    \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    // Phase 1: Process Creation APIs
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] Phase 1: Analyzing Process Creation..."];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *processCreation = [self analyzeProcessCreation:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] PROCESS CREATION APIS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (processCreation.count > 0) {
        [report appendFormat:@"Found %lu process creation operation(s)\n\n", (unsigned long)processCreation.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Found %lu process creation operation(s)", (unsigned long)processCreation.count]];
        for (NSDictionary *op in processCreation) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"⚠️  No process creation operations detected\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  No process creation operations detected"];
    }
    [report appendString:@"\n"];

    // Phase 2: Dynamic Library Loading
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] Phase 2: Analyzing Dynamic Library Loading..."];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *dynamicLoading = [self analyzeDynamicLoading:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] DYNAMIC LIBRARY LOADING\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (dynamicLoading.count > 0) {
        [report appendFormat:@"Found %lu dynamic loading operation(s)\n\n", (unsigned long)dynamicLoading.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Found %lu dynamic loading operation(s)", (unsigned long)dynamicLoading.count]];
        for (NSDictionary *op in dynamicLoading) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"⚠️  No dynamic loading operations detected\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  No dynamic loading operations detected"];
    }
    [report appendString:@"\n"];

    // Phase 3: Mach Injection Vectors
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] Phase 3: Analyzing Mach Injection Vectors..."];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *machInjection = [self analyzeMachInjection:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] MACH INJECTION VECTORS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (machInjection.count > 0) {
        [report appendFormat:@"Found %lu Mach injection vector(s)\n\n", (unsigned long)machInjection.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Found %lu Mach injection vector(s)", (unsigned long)machInjection.count]];
        for (NSDictionary *op in machInjection) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"⚠️  No Mach injection vectors detected\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  No Mach injection vectors detected"];
    }
    [report appendString:@"\n"];

    // Phase 4: Ptrace & Debugging
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] Phase 4: Analyzing Ptrace & Debugging..."];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *debugging = [self analyzeDebugging:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] PTRACE & DEBUGGING\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (debugging.count > 0) {
        [report appendFormat:@"Found %lu debugging/ptrace operation(s)\n\n", (unsigned long)debugging.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Found %lu debugging/ptrace operation(s)", (unsigned long)debugging.count]];
        for (NSDictionary *op in debugging) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"⚠️  No ptrace/debugging operations detected\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  No ptrace/debugging operations detected"];
    }
    [report appendString:@"\n"];

    // Phase 5: Privilege Escalation
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] Phase 5: Analyzing Privilege Escalation..."];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *privEsc = [self analyzePrivilegeEscalation:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] PRIVILEGE ESCALATION PATTERNS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (privEsc.count > 0) {
        [report appendFormat:@"Found %lu privilege escalation pattern(s)\n\n", (unsigned long)privEsc.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Found %lu privilege escalation pattern(s)", (unsigned long)privEsc.count]];
        for (NSDictionary *op in privEsc) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"⚠️  No privilege escalation patterns detected\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  No privilege escalation patterns detected"];
    }
    [report appendString:@"\n"];

    // Summary
    NSUInteger totalFindings = processCreation.count + dynamicLoading.count + machInjection.count +
                               debugging.count + privEsc.count;

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"SUMMARY\n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Findings: %lu\n", (unsigned long)totalFindings];
    [report appendFormat:@"  - Process Creation: %lu\n", (unsigned long)processCreation.count];
    [report appendFormat:@"  - Dynamic Library Loading: %lu\n", (unsigned long)dynamicLoading.count];
    [report appendFormat:@"  - Mach Injection Vectors: %lu\n", (unsigned long)machInjection.count];
    [report appendFormat:@"  - Ptrace/Debugging: %lu\n", (unsigned long)debugging.count];
    [report appendFormat:@"  - Privilege Escalation: %lu\n\n", (unsigned long)privEsc.count];

    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] SUMMARY"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Total Findings:            %lu", (unsigned long)totalFindings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Process Creation:          %lu", (unsigned long)processCreation.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Dynamic Library Loading:   %lu", (unsigned long)dynamicLoading.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Mach Injection Vectors:    %lu", (unsigned long)machInjection.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Ptrace/Debugging:          %lu", (unsigned long)debugging.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[ProcessInjectionAnalyzer] Privilege Escalation:      %lu", (unsigned long)privEsc.count]];

    BOOL createsProcesses = (processCreation.count > 0);
    BOOL loadsDynamic = (dynamicLoading.count > 0);
    BOOL usesMachInjection = (machInjection.count > 0);
    BOOL usesDebugging = (debugging.count > 0);
    BOOL usesPrivEsc = (privEsc.count > 0);

    if (createsProcesses) {
        [report appendString:@"✓ Binary creates/spawns processes\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ✓ Binary creates/spawns processes"];
    }
    if (loadsDynamic) {
        [report appendString:@"✓ Binary dynamically loads libraries/code\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ✓ Binary dynamically loads libraries/code"];
    }
    if (usesMachInjection) {
        [report appendString:@"⚠️  Binary uses Mach-based injection techniques\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  Binary uses Mach-based injection techniques"];
    }
    if (usesDebugging) {
        [report appendString:@"⚠️  Binary uses ptrace/debugging APIs\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  Binary uses ptrace/debugging APIs"];
    }
    if (usesPrivEsc) {
        [report appendString:@"⚠️  Binary implements privilege escalation patterns\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ⚠️  Binary implements privilege escalation patterns"];
    }
    [report appendString:@"\n"];

    if (totalFindings > 0) {
        [report appendString:@"SECURITY ANALYSIS RECOMMENDATIONS:\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] SECURITY ANALYSIS RECOMMENDATIONS:"];
        [report appendString:@"1. Review all process creation for command injection vulnerabilities\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] 1. Review all process creation for command injection vulnerabilities"];
        [report appendString:@"2. Verify dynamic library loading paths are not user-controlled\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] 2. Verify dynamic library loading paths are not user-controlled"];
        [report appendString:@"3. Analyze Mach injection usage for malicious intent\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] 3. Analyze Mach injection usage for malicious intent"];
        [report appendString:@"4. Check ptrace usage (anti-debugging or process manipulation)\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] 4. Check ptrace usage (anti-debugging or process manipulation)"];
        [report appendString:@"5. Examine privilege escalation for proper authorization checks\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] 5. Examine privilege escalation for proper authorization checks"];
    } else {
        [report appendString:@"ℹ️  No process injection or manipulation detected\n\n"];
        [document logInfoMessage:@"[ProcessInjectionAnalyzer] ℹ️  No process injection or manipulation detected"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[ProcessInjectionAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"ProcessInjection_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    // Show summary popup
    NSString *summary = [NSString stringWithFormat:
        @"Process & Code Injection Analysis Complete\n\n"
        @"Total Findings: %lu\n"
        @"  • Process Creation: %lu\n"
        @"  • Dynamic Library Loading: %lu\n"
        @"  • Mach Injection Vectors: %lu\n"
        @"  • Ptrace/Debugging: %lu\n"
        @"  • Privilege Escalation: %lu\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalFindings,
        (unsigned long)processCreation.count,
        (unsigned long)dynamicLoading.count,
        (unsigned long)machInjection.count,
        (unsigned long)debugging.count,
        (unsigned long)privEsc.count,
        tmpPath];

    [document displayAlertWithMessageText:@"Process & Code Injection Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSArray *)analyzeProcessCreation:(NSObject<HPDisassembledFile> *)file
                           document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Process creation API patterns
    NSArray *processPatterns = @[
        // C APIs
        @"fork", @"vfork", @"execl", @"execle", @"execlp", @"execv", @"execve",
        @"execvp", @"execvP", @"posix_spawn", @"posix_spawnp",
        @"system", @"popen",
        // Objective-C
        @"NSTask", @"NSTaskDidTerminateNotification",
        @"launchPath", @"setLaunchPath", @"arguments", @"setArguments",
        @"launch", @"waitUntilExit",
        // Process info
        @"NSProcessInfo", @"processIdentifier", @"globallyUniqueString"
    ];

    // Scan string sections
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

                    if (str && str.length >= 4) {
                        for (NSString *pattern in processPatterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 100) break;
                }
            }
        }
        if (results.count > 100) break;
    }

    return [results copy];
}

- (NSArray *)analyzeDynamicLoading:(NSObject<HPDisassembledFile> *)file
                          document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Dynamic loading patterns
    NSArray *dynamicPatterns = @[
        // dlopen/dlsym
        @"dlopen", @"dlsym", @"dlclose", @"dlerror", @"dladdr",
        // Dyld
        @"dyld", @"_dyld_register_func_for_add_image",
        @"_dyld_register_func_for_remove_image",
        @"dyld_get_image_name", @"dyld_image_count",
        // NSBundle
        @"NSBundle", @"bundleWithPath", @"loadBundle", @"principalClass",
        @"classNamed", @"pathForResource",
        // CFBundle
        @"CFBundleCreate", @"CFBundleGetFunctionPointerForName",
        @"CFBundleLoadExecutable"
    ];

    // Scan string sections
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

                    if (str && str.length >= 4) {
                        for (NSString *pattern in dynamicPatterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 100) break;
                }
            }
        }
        if (results.count > 100) break;
    }

    return [results copy];
}

- (NSArray *)analyzeMachInjection:(NSObject<HPDisassembledFile> *)file
                         document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Mach injection patterns
    NSArray *machPatterns = @[
        // Task operations
        @"task_for_pid", @"pid_for_task", @"task_threads",
        @"task_suspend", @"task_resume", @"task_info",
        // Thread operations
        @"thread_create", @"thread_create_running",
        @"thread_suspend", @"thread_resume", @"thread_terminate",
        @"thread_set_state", @"thread_get_state",
        // VM operations
        @"vm_allocate", @"vm_deallocate", @"vm_write", @"vm_read",
        @"vm_protect", @"vm_region", @"vm_remap",
        @"mach_vm_allocate", @"mach_vm_write", @"mach_vm_read",
        // Mach ports
        @"mach_port_allocate", @"mach_port_insert_right"
    ];

    // Scan string sections
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

                    if (str && str.length >= 4) {
                        for (NSString *pattern in machPatterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 100) break;
                }
            }
        }
        if (results.count > 100) break;
    }

    return [results copy];
}

- (NSArray *)analyzeDebugging:(NSObject<HPDisassembledFile> *)file
                     document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Ptrace and debugging patterns
    NSArray *debugPatterns = @[
        // Ptrace
        @"ptrace", @"PT_TRACE_ME", @"PT_DENY_ATTACH",
        @"PT_ATTACH", @"PT_DETACH", @"PT_CONTINUE",
        // Debugging detection
        @"sysctl", @"P_TRACED", @"kinfo_proc",
        @"isatty", @"ioctl", @"TIOCGWINSZ",
        // Anti-debugging
        @"AmIBeingDebugged", @"IsDebuggerPresent"
    ];

    // Scan string sections
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

                    if (str && str.length >= 4) {
                        for (NSString *pattern in debugPatterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 50) break;
                }
            }
        }
        if (results.count > 50) break;
    }

    return [results copy];
}

- (NSArray *)analyzePrivilegeEscalation:(NSObject<HPDisassembledFile> *)file
                               document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Privilege escalation patterns
    NSArray *privEscPatterns = @[
        // UID/GID manipulation
        @"setuid", @"seteuid", @"setreuid", @"setresuid",
        @"setgid", @"setegid", @"setregid", @"setresgid",
        @"setgroups", @"initgroups",
        // Authorization
        @"AuthorizationCreate", @"AuthorizationExecuteWithPrivileges",
        @"AuthorizationCopyRights", @"AuthorizationFree",
        // Elevated execution
        @"SMJobBless", @"SMJobSubmit", @"SMJobRemove",
        // Sudo/su
        @"sudo", @"/usr/bin/sudo", @"su", @"/bin/su"
    ];

    // Scan string sections
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

                    if (str && str.length >= 4) {
                        for (NSString *pattern in privEscPatterns) {
                            if ([str containsString:pattern]) {
                                [results addObject:@{@"address": @(addr), @"string": str}];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count > 50) break;
                }
            }
        }
        if (results.count > 50) break;
    }

    return [results copy];
}

#pragma mark - Helper Methods

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
