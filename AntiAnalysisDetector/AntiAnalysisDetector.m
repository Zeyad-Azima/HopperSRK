/*
 AntiAnalysisDetector.m
 Anti-Analysis Detection Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "AntiAnalysisDetector.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation AntiAnalysisDetector

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
    return [self.services UUIDWithString:@"9D2E8F7A-5C4B-11EF-A123-0800200C9A77"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Anti-Analysis Detector";
}

- (NSString *)pluginDescription {
    return @"Comprehensive anti-analysis technique detection: anti-debugging, anti-VM, code integrity checks, and environment detection";
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
    return @[@"anti-analysis-detector"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Anti-Analysis Detector",
            HPM_SELECTOR: NSStringFromSelector(@selector(detectAntiAnalysis:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)detectAntiAnalysis:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[AntiAnalysisDetector] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[AntiAnalysisDetector] No disassembled file"];
        return;
    }

    [document beginToWait:@"Detecting Anti-Analysis Techniques..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[AntiAnalysisDetector]           ANTI-ANALYSIS TECHNIQUE DETECTION REPORT"];
    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[AntiAnalysisDetector] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"           ANTI-ANALYSIS TECHNIQUE DETECTION REPORT                   \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    // Phase 1: Anti-Debugging Detection
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[AntiAnalysisDetector] Phase 1: Detecting Anti-Debugging Techniques..."];
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *antiDebug = [self detectAntiDebugging:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] ANTI-DEBUGGING TECHNIQUES\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *ptraceAPIs = antiDebug[@"ptrace"];
    NSArray *sysctlChecks = antiDebug[@"sysctl"];
    NSArray *timingChecks = antiDebug[@"timing"];
    NSArray *exceptionAPIs = antiDebug[@"exception"];

    if (ptraceAPIs.count > 0) {
        [report appendFormat:@"Ptrace Anti-Debug: %lu\n\n", (unsigned long)ptraceAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Ptrace Anti-Debug: %lu", (unsigned long)ptraceAPIs.count]];
        for (NSDictionary *op in ptraceAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (sysctlChecks.count > 0) {
        [report appendFormat:@"Sysctl Debugger Checks: %lu\n\n", (unsigned long)sysctlChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Sysctl Checks: %lu", (unsigned long)sysctlChecks.count]];
        for (NSDictionary *op in sysctlChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (timingChecks.count > 0) {
        [report appendFormat:@"Timing-Based Detection: %lu\n\n", (unsigned long)timingChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Timing Checks: %lu", (unsigned long)timingChecks.count]];
        for (NSDictionary *op in timingChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    if (exceptionAPIs.count > 0) {
        [report appendFormat:@"Exception Port Checks: %lu\n\n", (unsigned long)exceptionAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Exception APIs: %lu", (unsigned long)exceptionAPIs.count]];
        for (NSDictionary *op in exceptionAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalAntiDebug = ptraceAPIs.count + sysctlChecks.count + timingChecks.count + exceptionAPIs.count;
    if (totalAntiDebug == 0) {
        [report appendString:@"✓ No anti-debugging techniques detected\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No anti-debugging detected"];
    }

    // Phase 2: Anti-VM/Sandbox Detection
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[AntiAnalysisDetector] Phase 2: Detecting Anti-VM/Sandbox Techniques..."];
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *antiVM = [self detectAntiVM:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] ANTI-VM / SANDBOX DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *hardwareChecks = antiVM[@"hardware"];
    NSArray *vmArtifacts = antiVM[@"artifacts"];
    NSArray *sandboxChecks = antiVM[@"sandbox"];

    if (hardwareChecks.count > 0) {
        [report appendFormat:@"Hardware Enumeration: %lu\n\n", (unsigned long)hardwareChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Hardware Checks: %lu", (unsigned long)hardwareChecks.count]];
        for (NSDictionary *op in hardwareChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (vmArtifacts.count > 0) {
        [report appendFormat:@"VM Artifact Checks: %lu\n\n", (unsigned long)vmArtifacts.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  VM Artifacts: %lu", (unsigned long)vmArtifacts.count]];
        for (NSDictionary *op in vmArtifacts) {
            [report appendFormat:@"  [0x%llx] [%@] \"%@\"\n",
                [op[@"address"] unsignedLongLongValue], op[@"type"], op[@"string"]];
            NSString *displayStr = [op[@"string"] length] > 50 ?
                [[op[@"string"] substringToIndex:50] stringByAppendingString:@"..."] : op[@"string"];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@",
                [op[@"address"] unsignedLongLongValue], displayStr]];
        }
        [report appendString:@"\n"];
    }

    if (sandboxChecks.count > 0) {
        [report appendFormat:@"Sandbox Detection: %lu\n\n", (unsigned long)sandboxChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Sandbox Checks: %lu", (unsigned long)sandboxChecks.count]];
        for (NSDictionary *op in sandboxChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalAntiVM = hardwareChecks.count + vmArtifacts.count + sandboxChecks.count;
    if (totalAntiVM == 0) {
        [report appendString:@"✓ No anti-VM/sandbox techniques detected\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No anti-VM/sandbox detected"];
    }

    // Phase 3: Code Integrity Checks
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[AntiAnalysisDetector] Phase 3: Detecting Code Integrity Checks..."];
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *integrityChecks = [self detectCodeIntegrity:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] CODE INTEGRITY CHECKS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *signatureChecks = integrityChecks[@"signature"];
    NSArray *checksumming = integrityChecks[@"checksum"];
    NSArray *memoryChecks = integrityChecks[@"memory"];

    if (signatureChecks.count > 0) {
        [report appendFormat:@"Code Signature Validation: %lu\n\n", (unsigned long)signatureChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Signature Checks: %lu", (unsigned long)signatureChecks.count]];
        for (NSDictionary *op in signatureChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (checksumming.count > 0) {
        [report appendFormat:@"Self-Checksumming: %lu\n\n", (unsigned long)checksumming.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Checksumming: %lu", (unsigned long)checksumming.count]];
        for (NSDictionary *op in checksumming) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    if (memoryChecks.count > 0) {
        [report appendFormat:@"Memory Integrity Checks: %lu\n\n", (unsigned long)memoryChecks.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Memory Checks: %lu", (unsigned long)memoryChecks.count]];
        for (NSDictionary *op in memoryChecks) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalIntegrity = signatureChecks.count + checksumming.count + memoryChecks.count;
    if (totalIntegrity == 0) {
        [report appendString:@"✓ No code integrity checks detected\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No code integrity checks detected"];
    }

    // Phase 4: Environment & Tool Detection
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[AntiAnalysisDetector] Phase 4: Detecting Environment & Tool Checks..."];
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *envChecks = [self detectEnvironment:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] ENVIRONMENT & TOOL DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *toolStrings = envChecks[@"tools"];
    NSArray *processEnum = envChecks[@"processes"];

    if (toolStrings.count > 0) {
        [report appendFormat:@"Analysis Tool Strings: %lu\n\n", (unsigned long)toolStrings.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Tool Strings: %lu", (unsigned long)toolStrings.count]];
        for (NSDictionary *op in toolStrings) {
            [report appendFormat:@"  [0x%llx] [%@] \"%@\"\n",
                [op[@"address"] unsignedLongLongValue], op[@"type"], op[@"string"]];
            NSString *displayStr = [op[@"string"] length] > 50 ?
                [[op[@"string"] substringToIndex:50] stringByAppendingString:@"..."] : op[@"string"];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] [%@] \"%@\"",
                [op[@"address"] unsignedLongLongValue], op[@"type"], displayStr]];
        }
        [report appendString:@"\n"];
    }

    if (processEnum.count > 0) {
        [report appendFormat:@"Process Enumeration: %lu\n\n", (unsigned long)processEnum.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Process Enum: %lu", (unsigned long)processEnum.count]];
        for (NSDictionary *op in processEnum) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalEnv = toolStrings.count + processEnum.count;
    if (totalEnv == 0) {
        [report appendString:@"✓ No environment detection found\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No environment detection"];
    }

    // Phase 5: Dynamic API Resolution
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[AntiAnalysisDetector] Phase 5: Detecting Dynamic API Resolution..."];
    [document logInfoMessage:@"[AntiAnalysisDetector] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *dynamicAPIs = [self detectDynamicResolution:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] DYNAMIC API RESOLUTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (dynamicAPIs.count > 0) {
        [report appendFormat:@"Dynamic Symbol Resolution: %lu\n\n", (unsigned long)dynamicAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] ⚠️  Dynamic Resolution: %lu", (unsigned long)dynamicAPIs.count]];
        for (NSDictionary *op in dynamicAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
    } else {
        [report appendString:@"✓ No dynamic API resolution detected\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No dynamic API resolution"];
    }
    [report appendString:@"\n"];

    // Summary
    NSUInteger totalFindings = totalAntiDebug + totalAntiVM + totalIntegrity + totalEnv + dynamicAPIs.count;

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"SUMMARY\n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Anti-Analysis Techniques: %lu\n\n", (unsigned long)totalFindings];
    [report appendFormat:@"  - Anti-Debugging: %lu\n", (unsigned long)totalAntiDebug];
    [report appendFormat:@"    • Ptrace: %lu\n", (unsigned long)ptraceAPIs.count];
    [report appendFormat:@"    • Sysctl: %lu\n", (unsigned long)sysctlChecks.count];
    [report appendFormat:@"    • Timing: %lu\n", (unsigned long)timingChecks.count];
    [report appendFormat:@"    • Exception: %lu\n", (unsigned long)exceptionAPIs.count];
    [report appendFormat:@"  - Anti-VM/Sandbox: %lu\n", (unsigned long)totalAntiVM];
    [report appendFormat:@"    • Hardware: %lu\n", (unsigned long)hardwareChecks.count];
    [report appendFormat:@"    • Artifacts: %lu\n", (unsigned long)vmArtifacts.count];
    [report appendFormat:@"    • Sandbox: %lu\n", (unsigned long)sandboxChecks.count];
    [report appendFormat:@"  - Code Integrity: %lu\n", (unsigned long)totalIntegrity];
    [report appendFormat:@"    • Signature: %lu\n", (unsigned long)signatureChecks.count];
    [report appendFormat:@"    • Checksum: %lu\n", (unsigned long)checksumming.count];
    [report appendFormat:@"    • Memory: %lu\n", (unsigned long)memoryChecks.count];
    [report appendFormat:@"  - Environment Detection: %lu\n", (unsigned long)totalEnv];
    [report appendFormat:@"  - Dynamic API Resolution: %lu\n\n", (unsigned long)dynamicAPIs.count];

    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[AntiAnalysisDetector] SUMMARY"];
    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Total Techniques: %lu", (unsigned long)totalFindings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Anti-Debug: %lu (Ptrace:%lu Sysctl:%lu Timing:%lu Exception:%lu)",
        (unsigned long)totalAntiDebug, (unsigned long)ptraceAPIs.count, (unsigned long)sysctlChecks.count,
        (unsigned long)timingChecks.count, (unsigned long)exceptionAPIs.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Anti-VM: %lu (HW:%lu Artifacts:%lu Sandbox:%lu)",
        (unsigned long)totalAntiVM, (unsigned long)hardwareChecks.count, (unsigned long)vmArtifacts.count, (unsigned long)sandboxChecks.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Integrity: %lu (Sig:%lu Checksum:%lu Mem:%lu)",
        (unsigned long)totalIntegrity, (unsigned long)signatureChecks.count, (unsigned long)checksumming.count, (unsigned long)memoryChecks.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Environment: %lu", (unsigned long)totalEnv]];
    [document logInfoMessage:[NSString stringWithFormat:@"[AntiAnalysisDetector] Dynamic APIs: %lu", (unsigned long)dynamicAPIs.count]];

    if (totalFindings > 0) {
        [report appendString:@"⚠️  ANALYSIS EVASION DETECTED\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ⚠️  ANALYSIS EVASION DETECTED"];

        [report appendString:@"ANALYST RECOMMENDATIONS:\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ANALYST RECOMMENDATIONS:"];

        if (totalAntiDebug > 0) {
            [report appendString:@"1. Patch anti-debugging checks before dynamic analysis\n"];
            [document logInfoMessage:@"[AntiAnalysisDetector] 1. Patch anti-debugging checks before dynamic analysis"];
        }
        if (totalAntiVM > 0) {
            [report appendString:@"2. Modify VM artifacts or use bare-metal analysis environment\n"];
            [document logInfoMessage:@"[AntiAnalysisDetector] 2. Modify VM artifacts or use bare-metal environment"];
        }
        if (totalIntegrity > 0) {
            [report appendString:@"3. Disable code signature validation before patching\n"];
            [document logInfoMessage:@"[AntiAnalysisDetector] 3. Disable code signature validation"];
        }
        if (totalEnv > 0) {
            [report appendString:@"4. Rename/hide analysis tools or use stealthy techniques\n"];
            [document logInfoMessage:@"[AntiAnalysisDetector] 4. Hide analysis tools"];
        }
        if (dynamicAPIs.count > 0) {
            [report appendString:@"5. Monitor runtime API resolution for hidden functionality\n"];
            [document logInfoMessage:@"[AntiAnalysisDetector] 5. Monitor runtime API resolution"];
        }
    } else {
        [report appendString:@"✓ No anti-analysis techniques detected\n"];
        [report appendString:@"  Binary appears safe for standard analysis procedures\n\n"];
        [document logInfoMessage:@"[AntiAnalysisDetector] ✓ No anti-analysis techniques detected"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[AntiAnalysisDetector]                       END OF REPORT"];
    [document logInfoMessage:@"[AntiAnalysisDetector] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"AntiAnalysis_Detection_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    // Show summary popup
    NSString *summary = [NSString stringWithFormat:
        @"Anti-Analysis Detection Complete\n\n"
        @"Total Techniques: %lu\n"
        @"  • Anti-Debugging: %lu\n"
        @"  • Anti-VM/Sandbox: %lu\n"
        @"  • Code Integrity: %lu\n"
        @"  • Environment Detection: %lu\n"
        @"  • Dynamic APIs: %lu\n\n"
        @"%@\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalFindings,
        (unsigned long)totalAntiDebug,
        (unsigned long)totalAntiVM,
        (unsigned long)totalIntegrity,
        (unsigned long)totalEnv,
        (unsigned long)dynamicAPIs.count,
        totalFindings > 0 ? @"⚠️  Evasion techniques detected!" : @"✓ No evasion detected",
        tmpPath];

    [document displayAlertWithMessageText:@"Anti-Analysis Detection Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)detectAntiDebugging:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *ptraceAPIs = [NSMutableArray array];
    NSMutableArray *sysctlChecks = [NSMutableArray array];
    NSMutableArray *timingChecks = [NSMutableArray array];
    NSMutableArray *exceptionAPIs = [NSMutableArray array];

    // Ptrace anti-debugging
    NSArray *ptracePatterns = @[
        @"ptrace", @"PT_DENY_ATTACH", @"PT_TRACE_ME", @"PT_ATTACH", @"PT_DETACH"
    ];

    // Sysctl debugger detection
    NSArray *sysctlPatterns = @[
        @"sysctl", @"CTL_KERN", @"KERN_PROC", @"KERN_PROC_PID",
        @"kinfo_proc", @"P_TRACED", @"p_flag"
    ];

    // Timing-based detection
    NSArray *timingPatterns = @[
        @"gettimeofday", @"clock_gettime", @"mach_absolute_time",
        @"CFAbsoluteTimeGetCurrent", @"CACurrentMediaTime",
        @"clock", @"times", @"getrusage"
    ];

    // Exception port checks
    NSArray *exceptionPatterns = @[
        @"task_get_exception_ports", @"task_set_exception_ports",
        @"exception_raise", @"catch_exception_raise",
        @"mach_exc_server"
    ];

    [self scanStringsForPatterns:ptracePatterns inFile:file results:ptraceAPIs maxResults:50];
    [self scanStringsForPatterns:sysctlPatterns inFile:file results:sysctlChecks maxResults:50];
    [self scanStringsForPatterns:timingPatterns inFile:file results:timingChecks maxResults:80];
    [self scanStringsForPatterns:exceptionPatterns inFile:file results:exceptionAPIs maxResults:50];

    return @{
        @"ptrace": [ptraceAPIs copy],
        @"sysctl": [sysctlChecks copy],
        @"timing": [timingChecks copy],
        @"exception": [exceptionAPIs copy]
    };
}

- (NSDictionary *)detectAntiVM:(NSObject<HPDisassembledFile> *)file
                      document:(NSObject<HPDocument> *)document {
    NSMutableArray *hardwareChecks = [NSMutableArray array];
    NSMutableArray *vmArtifacts = [NSMutableArray array];
    NSMutableArray *sandboxChecks = [NSMutableArray array];

    // Hardware enumeration
    NSArray *hwPatterns = @[
        @"sysctl", @"hw.model", @"hw.machine", @"hw.cpufrequency",
        @"IOServiceMatching", @"IOServiceGetMatchingServices",
        @"sysctlbyname", @"machdep.cpu"
    ];

    // VM artifact strings
    NSArray *vmStrings = @[
        @"VMware", @"vmware", @"VMWARE",
        @"Parallels", @"parallels", @"prl",
        @"VirtualBox", @"virtualbox", @"vbox", @"VBOX",
        @"QEMU", @"qemu",
        @"VMware Tools", @"Parallels Tools",
        @"/.dockerenv", @"/.containerenv",
        @"/Applications/VMware", @"/Library/Parallels"
    ];

    // Sandbox detection
    NSArray *sandboxPatterns = @[
        @"sandbox_init", @"sandbox_free_error", @"sandbox_check",
        @"APP_SANDBOX_READ", @"container", @"Containers"
    ];

    [self scanStringsForPatterns:hwPatterns inFile:file results:hardwareChecks maxResults:80];

    // Special handling for VM artifact strings
    [self scanForVMArtifacts:file results:vmArtifacts vmStrings:vmStrings];

    [self scanStringsForPatterns:sandboxPatterns inFile:file results:sandboxChecks maxResults:50];

    return @{
        @"hardware": [hardwareChecks copy],
        @"artifacts": [vmArtifacts copy],
        @"sandbox": [sandboxChecks copy]
    };
}

- (NSDictionary *)detectCodeIntegrity:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *signatureChecks = [NSMutableArray array];
    NSMutableArray *checksumming = [NSMutableArray array];
    NSMutableArray *memoryChecks = [NSMutableArray array];

    // Code signature validation
    NSArray *sigPatterns = @[
        @"SecStaticCodeCreateWithPath", @"SecCodeCheckValidity",
        @"SecCodeCopySigningInformation", @"SecRequirementCreateWithString",
        @"SecCodeCopySelf", @"SecTaskCreateFromSelf",
        @"csops", @"CS_OPS_STATUS"
    ];

    // Checksumming (hash functions used on binary)
    NSArray *checksumPatterns = @[
        @"CC_MD5", @"CC_SHA1", @"CC_SHA256", @"CC_SHA512",
        @"CCDigest", @"CCCryptorCreate"
    ];

    // Memory integrity
    NSArray *memPatterns = @[
        @"vm_region", @"vm_read", @"vm_region_64",
        @"mach_vm_region", @"mach_vm_read",
        @"vm_protect", @"mach_vm_protect"
    ];

    [self scanStringsForPatterns:sigPatterns inFile:file results:signatureChecks maxResults:60];
    [self scanStringsForPatterns:checksumPatterns inFile:file results:checksumming maxResults:50];
    [self scanStringsForPatterns:memPatterns inFile:file results:memoryChecks maxResults:60];

    return @{
        @"signature": [signatureChecks copy],
        @"checksum": [checksumming copy],
        @"memory": [memoryChecks copy]
    };
}

- (NSDictionary *)detectEnvironment:(NSObject<HPDisassembledFile> *)file
                           document:(NSObject<HPDocument> *)document {
    NSMutableArray *toolStrings = [NSMutableArray array];
    NSMutableArray *processEnum = [NSMutableArray array];

    // Analysis tool strings
    NSArray *toolNames = @[
        @"lldb", @"LLDB", @"debugserver",
        @"gdb", @"GDB",
        @"Hopper", @"hopper",
        @"IDA", @"ida", @"ida64",
        @"radare", @"r2", @"rizin",
        @"dtrace", @"dtruss", @"dtrace",
        @"Instruments", @"instruments",
        @"sample", @"spindump",
        @"fs_usage", @"opensnoop",
        @"class-dump", @"otool", @"jtool",
        @"Ghidra", @"ghidra",
        @"Binary Ninja", @"binaryninja"
    ];

    // Process enumeration APIs
    NSArray *procPatterns = @[
        @"proc_listpids", @"proc_pidpath", @"proc_name",
        @"NSRunningApplication", @"runningApplications",
        @"kCGWindowListOptionAll", @"CGWindowListCopyWindowInfo"
    ];

    [self scanForToolStrings:file results:toolStrings toolNames:toolNames];
    [self scanStringsForPatterns:procPatterns inFile:file results:processEnum maxResults:50];

    return @{
        @"tools": [toolStrings copy],
        @"processes": [processEnum copy]
    };
}

- (NSArray *)detectDynamicResolution:(NSObject<HPDisassembledFile> *)file
                            document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Dynamic symbol resolution
    NSArray *dynPatterns = @[
        @"dlsym", @"dlopen", @"dladdr",
        @"NSClassFromString", @"NSSelectorFromString",
        @"class_getMethodImplementation", @"method_getImplementation",
        @"objc_getClass", @"objc_lookUpClass",
        @"CFBundleGetFunctionPointerForName"
    ];

    [self scanStringsForPatterns:dynPatterns inFile:file results:results maxResults:100];

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

- (void)scanForVMArtifacts:(NSObject<HPDisassembledFile> *)file
                   results:(NSMutableArray *)results
                 vmStrings:(NSArray *)vmStrings {
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

                    if (str && str.length >= 3) {
                        for (NSString *vmString in vmStrings) {
                            if ([str containsString:vmString]) {
                                NSString *type = @"VM";
                                if ([vmString containsString:@"VMware"]) type = @"VMware";
                                else if ([vmString containsString:@"Parallels"] || [vmString containsString:@"prl"]) type = @"Parallels";
                                else if ([vmString containsString:@"VirtualBox"] || [vmString containsString:@"vbox"]) type = @"VirtualBox";
                                else if ([vmString containsString:@"QEMU"]) type = @"QEMU";
                                else if ([vmString containsString:@"docker"] || [vmString containsString:@"container"]) type = @"Container";

                                [results addObject:@{
                                    @"address": @(addr),
                                    @"type": type,
                                    @"string": str
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
                if (results.count >= 100) break;
            }
        }
        if (results.count >= 100) break;
    }
}

- (void)scanForToolStrings:(NSObject<HPDisassembledFile> *)file
                   results:(NSMutableArray *)results
                 toolNames:(NSArray *)toolNames {
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

                    if (str && str.length >= 3) {
                        for (NSString *toolName in toolNames) {
                            if ([str containsString:toolName]) {
                                NSString *type = @"Tool";
                                if ([toolName containsString:@"lldb"] || [toolName containsString:@"gdb"]) type = @"Debugger";
                                else if ([toolName containsString:@"Hopper"] || [toolName containsString:@"IDA"] || [toolName containsString:@"Ghidra"]) type = @"Disassembler";
                                else if ([toolName containsString:@"dtrace"] || [toolName containsString:@"Instruments"]) type = @"Tracer";

                                [results addObject:@{
                                    @"address": @(addr),
                                    @"type": type,
                                    @"string": str
                                }];
                                break;
                            }
                        }
                        addr += str.length + 1;
                    } else {
                        addr += 1;
                    }

                    if (results.count >= 150) break;
                }
                if (results.count >= 150) break;
            }
        }
        if (results.count >= 150) break;
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
