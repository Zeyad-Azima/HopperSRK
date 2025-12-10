/*
 PersistenceAnalyzer.m
 Persistence Mechanism Analyzer Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "PersistenceAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation PersistenceAnalyzer

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
    return [self.services UUIDWithString:@"8F3C5E9B-6D7A-11EF-B234-0800200C9A88"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Persistence Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive persistence mechanism detection: Launch Agents/Daemons, Login Items, Cron Jobs, Kernel Extensions, Browser Extensions, and Dylib Injection";
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
    return @[@"persistence-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Persistence Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzePersistence:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzePersistence:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[PersistenceAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[PersistenceAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing Persistence Mechanisms..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[PersistenceAnalyzer]           PERSISTENCE MECHANISM ANALYSIS REPORT"];
    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[PersistenceAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"           PERSISTENCE MECHANISM ANALYSIS REPORT                       \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    // Phase 1: Launch Agents/Daemons
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 1: Detecting Launch Agents/Daemons..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *launchMechanisms = [self detectLaunchMechanisms:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] LAUNCH AGENTS / DAEMONS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *smJobAPIs = launchMechanisms[@"smjob"];
    NSArray *launchPaths = launchMechanisms[@"paths"];
    NSArray *plistAPIs = launchMechanisms[@"plist"];

    if (smJobAPIs.count > 0) {
        [report appendFormat:@"SMJob APIs (Privileged Helper): %lu\n\n", (unsigned long)smJobAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  SMJob APIs: %lu", (unsigned long)smJobAPIs.count]];
        for (NSDictionary *op in smJobAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (launchPaths.count > 0) {
        [report appendFormat:@"Launch Agent/Daemon Paths: %lu\n\n", (unsigned long)launchPaths.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Launch Paths: %lu", (unsigned long)launchPaths.count]];
        for (NSDictionary *op in launchPaths) {
            [report appendFormat:@"  [0x%llx] [%@] \"%@\"\n",
                [op[@"address"] unsignedLongLongValue], op[@"type"], op[@"string"]];
            NSString *displayStr = [op[@"string"] length] > 60 ?
                [[op[@"string"] substringToIndex:60] stringByAppendingString:@"..."] : op[@"string"];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@",
                [op[@"address"] unsignedLongLongValue], displayStr]];
        }
        [report appendString:@"\n"];
    }

    if (plistAPIs.count > 0) {
        [report appendFormat:@"Plist Manipulation APIs: %lu\n\n", (unsigned long)plistAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Plist APIs: %lu", (unsigned long)plistAPIs.count]];
        for (NSDictionary *op in plistAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalLaunch = smJobAPIs.count + launchPaths.count + plistAPIs.count;
    if (totalLaunch == 0) {
        [report appendString:@"✓ No Launch Agent/Daemon persistence detected\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Launch Agent/Daemon persistence"];
    }

    // Phase 2: Login Items
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 2: Detecting Login Items..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *loginItems = [self detectLoginItems:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] LOGIN ITEMS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *loginAPIs = loginItems[@"apis"];
    NSArray *loginPaths = loginItems[@"paths"];

    if (loginAPIs.count > 0) {
        [report appendFormat:@"Login Item APIs: %lu\n\n", (unsigned long)loginAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Login Item APIs: %lu", (unsigned long)loginAPIs.count]];
        for (NSDictionary *op in loginAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (loginPaths.count > 0) {
        [report appendFormat:@"Login Item Paths: %lu\n\n", (unsigned long)loginPaths.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Login Paths: %lu", (unsigned long)loginPaths.count]];
        for (NSDictionary *op in loginPaths) {
            [report appendFormat:@"  [0x%llx] \"%@\"\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalLogin = loginAPIs.count + loginPaths.count;
    if (totalLogin == 0) {
        [report appendString:@"✓ No Login Item persistence detected\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Login Item persistence"];
    }

    // Phase 3: Cron Jobs & Scheduled Tasks
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 3: Detecting Cron Jobs & Scheduled Tasks..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *cronJobs = [self detectCronJobs:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] CRON JOBS & SCHEDULED TASKS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *cronCommands = cronJobs[@"commands"];
    NSArray *cronPaths = cronJobs[@"paths"];

    if (cronCommands.count > 0) {
        [report appendFormat:@"Cron/At Commands: %lu\n\n", (unsigned long)cronCommands.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Cron Commands: %lu", (unsigned long)cronCommands.count]];
        for (NSDictionary *op in cronCommands) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (cronPaths.count > 0) {
        [report appendFormat:@"Cron/Periodic Paths: %lu\n\n", (unsigned long)cronPaths.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Cron Paths: %lu", (unsigned long)cronPaths.count]];
        for (NSDictionary *op in cronPaths) {
            [report appendFormat:@"  [0x%llx] \"%@\"\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalCron = cronCommands.count + cronPaths.count;
    if (totalCron == 0) {
        [report appendString:@"✓ No Cron/Scheduled Task persistence detected\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Cron persistence"];
    }

    // Phase 4: Kernel Extensions
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 4: Detecting Kernel Extensions..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *kextMechanisms = [self detectKernelExtensions:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] KERNEL EXTENSIONS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *kextAPIs = kextMechanisms[@"apis"];
    NSArray *kextPaths = kextMechanisms[@"paths"];

    if (kextAPIs.count > 0) {
        [report appendFormat:@"Kernel Extension APIs: %lu\n\n", (unsigned long)kextAPIs.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Kext APIs: %lu", (unsigned long)kextAPIs.count]];
        for (NSDictionary *op in kextAPIs) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (kextPaths.count > 0) {
        [report appendFormat:@"Kext Paths: %lu\n\n", (unsigned long)kextPaths.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Kext Paths: %lu", (unsigned long)kextPaths.count]];
        for (NSDictionary *op in kextPaths) {
            [report appendFormat:@"  [0x%llx] \"%@\"\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalKext = kextAPIs.count + kextPaths.count;
    if (totalKext == 0) {
        [report appendString:@"✓ No Kernel Extension persistence detected\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Kernel Extension persistence"];
    }

    // Phase 5: Browser Extensions
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 5: Detecting Browser Extensions..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *browserExt = [self detectBrowserExtensions:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] BROWSER EXTENSIONS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    if (browserExt.count > 0) {
        [report appendFormat:@"Browser Extension Paths: %lu\n\n", (unsigned long)browserExt.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Browser Extensions: %lu", (unsigned long)browserExt.count]];
        for (NSDictionary *op in browserExt) {
            [report appendFormat:@"  [0x%llx] [%@] \"%@\"\n",
                [op[@"address"] unsignedLongLongValue], op[@"type"], op[@"string"]];
            NSString *displayStr = [op[@"string"] length] > 60 ?
                [[op[@"string"] substringToIndex:60] stringByAppendingString:@"..."] : op[@"string"];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] [%@] %@",
                [op[@"address"] unsignedLongLongValue], op[@"type"], displayStr]];
        }
    } else {
        [report appendString:@"✓ No Browser Extension persistence detected\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Browser Extension persistence"];
    }
    [report appendString:@"\n"];

    // Phase 6: Dylib Injection
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[PersistenceAnalyzer] Phase 6: Detecting Dylib Injection..."];
    [document logInfoMessage:@"[PersistenceAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *dylibInjection = [self detectDylibInjection:file document:document];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[6] DYLIB INJECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSArray *dylibEnv = dylibInjection[@"environment"];
    NSArray *interposing = dylibInjection[@"interposing"];

    if (dylibEnv.count > 0) {
        [report appendFormat:@"DYLD Environment Variables: %lu\n\n", (unsigned long)dylibEnv.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  DYLD Environment: %lu", (unsigned long)dylibEnv.count]];
        for (NSDictionary *op in dylibEnv) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer]   [0x%llx] %@", [op[@"address"] unsignedLongLongValue], op[@"string"]]];
        }
        [report appendString:@"\n"];
    }

    if (interposing.count > 0) {
        [report appendFormat:@"Dylib Interposing: %lu\n\n", (unsigned long)interposing.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] ⚠️  Interposing: %lu", (unsigned long)interposing.count]];
        for (NSDictionary *op in interposing) {
            [report appendFormat:@"  [0x%llx] %@\n", [op[@"address"] unsignedLongLongValue], op[@"string"]];
        }
        [report appendString:@"\n"];
    }

    NSUInteger totalDylib = dylibEnv.count + interposing.count;
    if (totalDylib == 0) {
        [report appendString:@"✓ No Dylib Injection persistence detected\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No Dylib Injection persistence"];
    }

    // Summary
    NSUInteger totalFindings = totalLaunch + totalLogin + totalCron + totalKext + browserExt.count + totalDylib;

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"SUMMARY\n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Persistence Mechanisms: %lu\n\n", (unsigned long)totalFindings];
    [report appendFormat:@"  - Launch Agents/Daemons: %lu\n", (unsigned long)totalLaunch];
    [report appendFormat:@"    • SMJob APIs: %lu\n", (unsigned long)smJobAPIs.count];
    [report appendFormat:@"    • Launch Paths: %lu\n", (unsigned long)launchPaths.count];
    [report appendFormat:@"    • Plist APIs: %lu\n", (unsigned long)plistAPIs.count];
    [report appendFormat:@"  - Login Items: %lu\n", (unsigned long)totalLogin];
    [report appendFormat:@"    • APIs: %lu\n", (unsigned long)loginAPIs.count];
    [report appendFormat:@"    • Paths: %lu\n", (unsigned long)loginPaths.count];
    [report appendFormat:@"  - Cron/Scheduled Tasks: %lu\n", (unsigned long)totalCron];
    [report appendFormat:@"    • Commands: %lu\n", (unsigned long)cronCommands.count];
    [report appendFormat:@"    • Paths: %lu\n", (unsigned long)cronPaths.count];
    [report appendFormat:@"  - Kernel Extensions: %lu\n", (unsigned long)totalKext];
    [report appendFormat:@"    • APIs: %lu\n", (unsigned long)kextAPIs.count];
    [report appendFormat:@"    • Paths: %lu\n", (unsigned long)kextPaths.count];
    [report appendFormat:@"  - Browser Extensions: %lu\n", (unsigned long)browserExt.count];
    [report appendFormat:@"  - Dylib Injection: %lu\n", (unsigned long)totalDylib];
    [report appendFormat:@"    • Environment: %lu\n", (unsigned long)dylibEnv.count];
    [report appendFormat:@"    • Interposing: %lu\n\n", (unsigned long)interposing.count];

    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[PersistenceAnalyzer] SUMMARY"];
    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Total Mechanisms: %lu", (unsigned long)totalFindings]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Launch: %lu (SMJob:%lu Paths:%lu Plist:%lu)",
        (unsigned long)totalLaunch, (unsigned long)smJobAPIs.count, (unsigned long)launchPaths.count, (unsigned long)plistAPIs.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Login Items: %lu (APIs:%lu Paths:%lu)",
        (unsigned long)totalLogin, (unsigned long)loginAPIs.count, (unsigned long)loginPaths.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Cron: %lu (Cmds:%lu Paths:%lu)",
        (unsigned long)totalCron, (unsigned long)cronCommands.count, (unsigned long)cronPaths.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Kext: %lu (APIs:%lu Paths:%lu)",
        (unsigned long)totalKext, (unsigned long)kextAPIs.count, (unsigned long)kextPaths.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Browser: %lu", (unsigned long)browserExt.count]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PersistenceAnalyzer] Dylib: %lu (Env:%lu Interpose:%lu)",
        (unsigned long)totalDylib, (unsigned long)dylibEnv.count, (unsigned long)interposing.count]];

    if (totalFindings > 0) {
        [report appendString:@"⚠️  PERSISTENCE MECHANISMS DETECTED\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ⚠️  PERSISTENCE MECHANISMS DETECTED"];

        [report appendString:@"REMEDIATION RECOMMENDATIONS:\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] REMEDIATION RECOMMENDATIONS:"];

        if (totalLaunch > 0) {
            [report appendString:@"1. Check Launch Agents/Daemons in system directories\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 1. Check Launch Agents/Daemons"];
        }
        if (totalLogin > 0) {
            [report appendString:@"2. Review Login Items in System Preferences\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 2. Review Login Items"];
        }
        if (totalCron > 0) {
            [report appendString:@"3. Audit crontab and periodic scripts\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 3. Audit crontab entries"];
        }
        if (totalKext > 0) {
            [report appendString:@"4. Verify kernel extensions with kextstat\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 4. Verify kernel extensions"];
        }
        if (browserExt.count > 0) {
            [report appendString:@"5. Check browser extension directories\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 5. Check browser extensions"];
        }
        if (totalDylib > 0) {
            [report appendString:@"6. Search for DYLD_INSERT_LIBRARIES in plists\n"];
            [document logInfoMessage:@"[PersistenceAnalyzer] 6. Search for DYLD environment variables"];
        }
    } else {
        [report appendString:@"✓ No persistence mechanisms detected\n"];
        [report appendString:@"  Binary does not appear to establish persistence\n\n"];
        [document logInfoMessage:@"[PersistenceAnalyzer] ✓ No persistence mechanisms detected"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[PersistenceAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[PersistenceAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"Persistence_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    // Show summary popup
    NSString *summary = [NSString stringWithFormat:
        @"Persistence Analysis Complete\n\n"
        @"Total Mechanisms: %lu\n"
        @"  • Launch Agents/Daemons: %lu\n"
        @"  • Login Items: %lu\n"
        @"  • Cron/Scheduled: %lu\n"
        @"  • Kernel Extensions: %lu\n"
        @"  • Browser Extensions: %lu\n"
        @"  • Dylib Injection: %lu\n\n"
        @"%@\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalFindings,
        (unsigned long)totalLaunch,
        (unsigned long)totalLogin,
        (unsigned long)totalCron,
        (unsigned long)totalKext,
        (unsigned long)browserExt.count,
        (unsigned long)totalDylib,
        totalFindings > 0 ? @"⚠️  Persistence detected!" : @"✓ No persistence detected",
        tmpPath];

    [document displayAlertWithMessageText:@"Persistence Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)detectLaunchMechanisms:(NSObject<HPDisassembledFile> *)file
                                document:(NSObject<HPDocument> *)document {
    NSMutableArray *smJobAPIs = [NSMutableArray array];
    NSMutableArray *launchPaths = [NSMutableArray array];
    NSMutableArray *plistAPIs = [NSMutableArray array];

    // SMJob APIs for privileged helper tools
    NSArray *smJobPatterns = @[
        @"SMJobBless", @"SMJobSubmit", @"SMJobRemove",
        @"SMJobCopyDictionary", @"SMCopyAllJobDictionaries",
        @"SMLoginItemSetEnabled"
    ];

    // Launch Agent/Daemon paths
    NSArray *launchPathPatterns = @[
        @"/Library/LaunchAgents", @"/Library/LaunchDaemons",
        @"~/Library/LaunchAgents", @"/System/Library/LaunchAgents",
        @"/System/Library/LaunchDaemons",
        @"LaunchAgents/", @"LaunchDaemons/",
        @".plist"
    ];

    // Plist manipulation
    NSArray *plistPatterns = @[
        @"CFPropertyListCreateWithData", @"CFPropertyListCreateData",
        @"NSPropertyListSerialization", @"propertyListWithData",
        @"writeToFile", @"writeToURL"
    ];

    [self scanStringsForPatterns:smJobPatterns inFile:file results:smJobAPIs maxResults:50];
    [self scanForLaunchPaths:file results:launchPaths pathPatterns:launchPathPatterns];
    [self scanStringsForPatterns:plistPatterns inFile:file results:plistAPIs maxResults:80];

    return @{
        @"smjob": [smJobAPIs copy],
        @"paths": [launchPaths copy],
        @"plist": [plistAPIs copy]
    };
}

- (NSDictionary *)detectLoginItems:(NSObject<HPDisassembledFile> *)file
                          document:(NSObject<HPDocument> *)document {
    NSMutableArray *loginAPIs = [NSMutableArray array];
    NSMutableArray *loginPaths = [NSMutableArray array];

    // Login Item APIs
    NSArray *loginAPIPatterns = @[
        @"LSSharedFileListCreate", @"LSSharedFileListInsertItemURL",
        @"LSSharedFileListItemRemove", @"kLSSharedFileListSessionLoginItems",
        @"kLSSharedFileListGlobalLoginItems",
        @"SMLoginItemSetEnabled", @"SMLoginItemEnabled"
    ];

    // Login Item paths
    NSArray *loginPathPatterns = @[
        @"LoginItems", @"SessionItems",
        @"com.apple.loginitems.plist",
        @"backgrounditems.btm"
    ];

    [self scanStringsForPatterns:loginAPIPatterns inFile:file results:loginAPIs maxResults:50];
    [self scanStringsForPatterns:loginPathPatterns inFile:file results:loginPaths maxResults:30];

    return @{
        @"apis": [loginAPIs copy],
        @"paths": [loginPaths copy]
    };
}

- (NSDictionary *)detectCronJobs:(NSObject<HPDisassembledFile> *)file
                        document:(NSObject<HPDocument> *)document {
    NSMutableArray *cronCommands = [NSMutableArray array];
    NSMutableArray *cronPaths = [NSMutableArray array];

    // Cron/at commands
    NSArray *cronCmdPatterns = @[
        @"crontab", @"crontab -e", @"crontab -l",
        @"at", @"atq", @"atrm",
        @"/usr/bin/crontab", @"/usr/bin/at"
    ];

    // Cron/periodic paths
    NSArray *cronPathPatterns = @[
        @"/etc/crontab", @"/etc/cron.d",
        @"/var/at/tabs", @"/var/cron/tabs",
        @"/etc/periodic", @"periodic/daily", @"periodic/weekly", @"periodic/monthly",
        @"/etc/rc.common", @"/etc/rc.local"
    ];

    [self scanStringsForPatterns:cronCmdPatterns inFile:file results:cronCommands maxResults:40];
    [self scanStringsForPatterns:cronPathPatterns inFile:file results:cronPaths maxResults:60];

    return @{
        @"commands": [cronCommands copy],
        @"paths": [cronPaths copy]
    };
}

- (NSDictionary *)detectKernelExtensions:(NSObject<HPDisassembledFile> *)file
                                document:(NSObject<HPDocument> *)document {
    NSMutableArray *kextAPIs = [NSMutableArray array];
    NSMutableArray *kextPaths = [NSMutableArray array];

    // Kernel extension APIs
    NSArray *kextAPIPatterns = @[
        @"kextload", @"kextunload", @"kextstat", @"kextutil",
        @"IOServiceMatching", @"IOServiceGetMatchingService",
        @"IOServiceOpen", @"IOConnectCallMethod",
        @"IOConnectCallStructMethod", @"IOConnectCallScalarMethod",
        @"KUNCUserNotificationDisplayNotice"
    ];

    // Kext paths
    NSArray *kextPathPatterns = @[
        @"/Library/Extensions", @"/System/Library/Extensions",
        @".kext", @".kext/", @"Extensions/"
    ];

    [self scanStringsForPatterns:kextAPIPatterns inFile:file results:kextAPIs maxResults:80];
    [self scanStringsForPatterns:kextPathPatterns inFile:file results:kextPaths maxResults:40];

    return @{
        @"apis": [kextAPIs copy],
        @"paths": [kextPaths copy]
    };
}

- (NSArray *)detectBrowserExtensions:(NSObject<HPDisassembledFile> *)file
                            document:(NSObject<HPDocument> *)document {
    NSMutableArray *results = [NSMutableArray array];

    // Browser extension paths
    NSArray *browserPaths = @[
        // Safari
        @"Safari/Extensions", @"~/Library/Safari/Extensions",
        @"Safari.app/Contents/Extensions",
        // Chrome
        @"Google/Chrome/Default/Extensions",
        @"Application Support/Google/Chrome",
        @"Chrome/Default/Extensions",
        // Firefox
        @"Firefox/Profiles", @"firefox/extensions",
        @"Mozilla/Extensions",
        // Brave
        @"BraveSoftware/Brave-Browser",
        // Edge
        @"Microsoft Edge/Default/Extensions"
    ];

    [self scanForBrowserPaths:file results:results browserPaths:browserPaths];

    return [results copy];
}

- (NSDictionary *)detectDylibInjection:(NSObject<HPDisassembledFile> *)file
                              document:(NSObject<HPDocument> *)document {
    NSMutableArray *dylibEnv = [NSMutableArray array];
    NSMutableArray *interposing = [NSMutableArray array];

    // DYLD environment variables
    NSArray *dylibEnvPatterns = @[
        @"DYLD_INSERT_LIBRARIES", @"DYLD_FORCE_FLAT_NAMESPACE",
        @"DYLD_LIBRARY_PATH", @"DYLD_FRAMEWORK_PATH",
        @"DYLD_FALLBACK_LIBRARY_PATH", @"DYLD_FALLBACK_FRAMEWORK_PATH",
        @"LSEnvironment", @"EnvironmentVariables"
    ];

    // Dylib interposing
    NSArray *interposingPatterns = @[
        @"__interpose", @"DYLD_INTERPOSE",
        @"interpose_", @"dyld_interpose",
        @"__DATA,__interpose"
    ];

    [self scanStringsForPatterns:dylibEnvPatterns inFile:file results:dylibEnv maxResults:60];
    [self scanStringsForPatterns:interposingPatterns inFile:file results:interposing maxResults:40];

    return @{
        @"environment": [dylibEnv copy],
        @"interposing": [interposing copy]
    };
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

- (void)scanForLaunchPaths:(NSObject<HPDisassembledFile> *)file
                   results:(NSMutableArray *)results
              pathPatterns:(NSArray *)pathPatterns {
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

                    if (str && str.length >= 5) {
                        for (NSString *pathPattern in pathPatterns) {
                            if ([str containsString:pathPattern]) {
                                NSString *type = @"Path";
                                if ([str containsString:@"LaunchAgents"]) type = @"LaunchAgent";
                                else if ([str containsString:@"LaunchDaemons"]) type = @"LaunchDaemon";
                                else if ([str containsString:@".plist"]) type = @"Plist";

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

- (void)scanForBrowserPaths:(NSObject<HPDisassembledFile> *)file
                    results:(NSMutableArray *)results
               browserPaths:(NSArray *)browserPaths {
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

                    if (str && str.length >= 5) {
                        for (NSString *browserPath in browserPaths) {
                            if ([str containsString:browserPath]) {
                                NSString *type = @"Browser";
                                if ([browserPath containsString:@"Safari"]) type = @"Safari";
                                else if ([browserPath containsString:@"Chrome"]) type = @"Chrome";
                                else if ([browserPath containsString:@"Firefox"]) type = @"Firefox";
                                else if ([browserPath containsString:@"Brave"]) type = @"Brave";
                                else if ([browserPath containsString:@"Edge"]) type = @"Edge";

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

                    if (results.count >= 80) break;
                }
                if (results.count >= 80) break;
            }
        }
        if (results.count >= 80) break;
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
