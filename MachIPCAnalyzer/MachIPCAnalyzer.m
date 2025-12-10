/*
 MachIPCAnalyzer.m
 Mach IPC Analyzer Plugin for Hopper Disassembler

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;

#import "MachIPCAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation MachIPCAnalyzer

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
    return [self.services UUIDWithString:@"C9FADE4-6E5F-13EF-D086-0800200C9B88"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Mach IPC Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive Mach IPC detection: MIG subsystems, mach ports, bootstrap services, and message handlers";
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
    return @[@"machipc-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Mach IPC Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeMachIPC:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeMachIPC:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [self.services logMessage:@"[MachIPCAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[MachIPCAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing Mach IPC..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[MachIPCAnalyzer]              MACH IPC ANALYSIS REPORT"];
    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[MachIPCAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                 MACH IPC ANALYSIS REPORT                             \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n", [NSDate date]];
    [report appendString:@"\n"];

    // Phase 1: MIG Subsystem Detection
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[MachIPCAnalyzer] Phase 1: Detecting MIG subsystems..."];
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *migSubsystems = [self findMIGSubsystems:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] MIG SUBSYSTEM DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportSubsystems:migSubsystems[@"subsystems"] report:report document:document];

    // Phase 2: Mach Port API Detection
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[MachIPCAnalyzer] Phase 2: Detecting Mach port APIs..."];
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *machAPIs = [self findMachAPIs:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] MACH PORT API DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:machAPIs[@"port_ops"] title:@"Mach Port Operations" report:report document:document];
    [self logAndReportArray:machAPIs[@"msg_ops"] title:@"Mach Message Operations" report:report document:document];

    // Phase 3: Bootstrap Service Detection
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[MachIPCAnalyzer] Phase 3: Detecting bootstrap services..."];
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *bootstrapAPIs = [self findBootstrapAPIs:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] BOOTSTRAP SERVICE DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:bootstrapAPIs[@"bootstrap_ops"] title:@"Bootstrap Operations" report:report document:document];
    [self logAndReportArray:bootstrapAPIs[@"service_names"] title:@"Service Names Found" report:report document:document];

    // Phase 4: MIG Dispatcher and Handler Detection
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[MachIPCAnalyzer] Phase 4: Detecting MIG dispatchers and handlers..."];
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *migHandlers = [self findMIGHandlers:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] MIG DISPATCHER & HANDLER DETECTION\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [self logAndReportArray:migHandlers[@"dispatchers"] title:@"MIG Dispatcher Functions" report:report document:document];
    [self logAndReportArray:migHandlers[@"handlers"] title:@"MIG Message Handlers" report:report document:document];

    // Summary
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[MachIPCAnalyzer] [5] ANALYSIS SUMMARY"];
    [document logInfoMessage:@"[MachIPCAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] ANALYSIS SUMMARY\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSUInteger totalSubsystems = [migSubsystems[@"subsystems"] count];
    NSUInteger totalMachAPIs = [machAPIs[@"port_ops"] count] + [machAPIs[@"msg_ops"] count];
    NSUInteger totalBootstrap = [bootstrapAPIs[@"bootstrap_ops"] count];
    NSUInteger totalHandlers = [migHandlers[@"dispatchers"] count] + [migHandlers[@"handlers"] count];
    NSUInteger totalServiceNames = [bootstrapAPIs[@"service_names"] count];

    [report appendFormat:@"MIG Subsystems Found:        %lu\n", (unsigned long)totalSubsystems];
    [report appendFormat:@"Mach Port APIs Found:        %lu\n", (unsigned long)totalMachAPIs];
    [report appendFormat:@"  • Port Operations:         %lu\n", (unsigned long)[machAPIs[@"port_ops"] count]];
    [report appendFormat:@"  • Message Operations:      %lu\n", (unsigned long)[machAPIs[@"msg_ops"] count]];
    [report appendFormat:@"Bootstrap APIs Found:        %lu\n", (unsigned long)totalBootstrap];
    [report appendFormat:@"Service Names Found:         %lu\n", (unsigned long)totalServiceNames];
    [report appendFormat:@"MIG Handlers Found:          %lu\n", (unsigned long)totalHandlers];
    [report appendFormat:@"  • Dispatchers:             %lu\n", (unsigned long)[migHandlers[@"dispatchers"] count]];
    [report appendFormat:@"  • Message Handlers:        %lu\n\n", (unsigned long)[migHandlers[@"handlers"] count]];

    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] MIG Subsystems Found:        %lu", (unsigned long)totalSubsystems]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Mach Port APIs Found:        %lu", (unsigned long)totalMachAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   • Port Operations:         %lu", (unsigned long)[machAPIs[@"port_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   • Message Operations:      %lu", (unsigned long)[machAPIs[@"msg_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Bootstrap APIs Found:        %lu", (unsigned long)totalBootstrap]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Service Names Found:         %lu", (unsigned long)totalServiceNames]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] MIG Handlers Found:          %lu", (unsigned long)totalHandlers]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   • Dispatchers:             %lu", (unsigned long)[migHandlers[@"dispatchers"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   • Message Handlers:        %lu", (unsigned long)[migHandlers[@"handlers"] count]]];

    BOOL usesMachIPC = (totalSubsystems > 0 || totalMachAPIs > 0 || totalBootstrap > 0);
    if (usesMachIPC) {
        [report appendString:@"✓ Binary uses Mach IPC for inter-process communication\n\n"];
        [document logInfoMessage:@"[MachIPCAnalyzer] ✓ Binary uses Mach IPC for inter-process communication"];
    } else {
        [report appendString:@"ℹ️  No Mach IPC usage detected in this binary\n\n"];
        [document logInfoMessage:@"[MachIPCAnalyzer] ℹ️  No Mach IPC usage detected in this binary"];
    }

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[MachIPCAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"MachIPC_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    NSString *summary = [NSString stringWithFormat:
        @"Mach IPC Analysis Complete\n\n"
        @"MIG Subsystems: %lu\n"
        @"Mach APIs: %lu\n"
        @"Bootstrap APIs: %lu\n"
        @"Service Names: %lu\n"
        @"MIG Handlers: %lu\n\n"
        @"Full report saved to:\n%@",
        (unsigned long)totalSubsystems,
        (unsigned long)totalMachAPIs,
        (unsigned long)totalBootstrap,
        (unsigned long)totalServiceNames,
        (unsigned long)totalHandlers,
        tmpPath
    ];

    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[MachIPCAnalyzer] Analysis Complete!"];
    [document logInfoMessage:@"[MachIPCAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] MIG Subsystems: %lu", (unsigned long)totalSubsystems]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Mach APIs: %lu", (unsigned long)totalMachAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Bootstrap APIs: %lu", (unsigned long)totalBootstrap]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Service Names: %lu", (unsigned long)totalServiceNames]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] MIG Handlers: %lu", (unsigned long)totalHandlers]];
    [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] Full report saved to: %@", tmpPath]];

    [document displayAlertWithMessageText:@"Mach IPC Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)findMIGSubsystems:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *subsystems = [NSMutableArray array];

    // Look for MIG subsystem structures in __DATA.__const, __DATA_CONST.__const, etc.
    NSArray *targetSections = @[
        @[@"__DATA", @"__const"],
        @[@"__DATA_CONST", @"__const"],
        @[@"__CONST", @"__constdata"]
    ];

    for (NSArray *sectionInfo in targetSections) {
        NSString *segmentName = sectionInfo[0];
        NSString *sectionName = sectionInfo[1];

        for (NSObject<HPSegment> *segment in file.segments) {
            if (![segment.segmentName isEqualToString:segmentName]) continue;

            for (NSObject<HPSection> *section in segment.sections) {
                if (![section.sectionName isEqualToString:sectionName]) continue;

                Address addr = section.startAddress;
                Address endAddr = section.endAddress;

                while (addr < endAddr - 0x28) {  // Min size of MIG subsystem structure
                    // Try to read potential MIG subsystem structure
                    uint64_t server_routine = [file readUInt64AtVirtualAddress:addr];
                    uint32_t start_id = [file readUInt32AtVirtualAddress:addr + 0x8];
                    uint32_t end_id = [file readUInt32AtVirtualAddress:addr + 0xC];
                    uint32_t maxsize = [file readUInt32AtVirtualAddress:addr + 0x10];
                    uint64_t reserved = [file readUInt64AtVirtualAddress:addr + 0x18];

                    // Heuristic: MIG subsystem has reserved=0, valid start/end IDs
                    if (reserved == 0 && start_id > 0 && start_id < 1000000 && 
                        end_id > start_id && (end_id - start_id) < 1000 && (end_id - start_id) > 0) {
                        
                        uint32_t msgCount = end_id - start_id;
                        NSString *info = [NSString stringWithFormat:
                            @"Subsystem %u: %u messages (IDs %u-%u), maxsize: %u",
                            start_id, msgCount, start_id, end_id - 1, maxsize];
                        
                        [subsystems addObject:@{
                            @"address": @(addr),
                            @"start_id": @(start_id),
                            @"end_id": @(end_id),
                            @"msg_count": @(msgCount),
                            @"maxsize": @(maxsize),
                            @"info": info
                        }];
                    }

                    addr += 8;  // Move to next potential structure
                }
            }
        }
    }

    return @{@"subsystems": subsystems};
}

- (NSDictionary *)findMachAPIs:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *portOps = [NSMutableArray array];
    NSMutableArray *msgOps = [NSMutableArray array];

    NSArray *portFunctions = @[
        @"mach_port_allocate", @"mach_port_deallocate", @"mach_port_insert_right",
        @"mach_port_extract_right", @"mach_port_get_attributes", @"mach_port_set_attributes",
        @"mach_port_request_notification", @"mach_port_mod_refs", @"mach_port_names",
        @"mach_port_type", @"mach_port_rename", @"mach_port_construct", @"mach_port_destruct",
        @"mach_port_guard", @"mach_port_unguard", @"task_get_special_port", @"task_set_special_port",
        @"task_for_pid", @"pid_for_task"
    ];

    NSArray *msgFunctions = @[
        @"mach_msg", @"mach_msg_trap", @"mach_msg_send", @"mach_msg_receive",
        @"mach_msg_server", @"mach_msg_server_once", @"mach_msg_overwrite",
        @"dispatch_mach_mig_demux", @"dispatch_mach_send", @"dispatch_mach_msg_get_msg"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check port operations
                    for (NSString *func in portFunctions) {
                        if ([name containsString:func]) {
                            [portOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check message operations
                    for (NSString *func in msgFunctions) {
                        if ([name containsString:func]) {
                            [msgOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"port_ops": portOps,
        @"msg_ops": msgOps
    };
}

- (NSDictionary *)findBootstrapAPIs:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *bootstrapOps = [NSMutableArray array];
    NSMutableArray *serviceNames = [NSMutableArray array];

    NSArray *bootstrapFunctions = @[
        @"bootstrap_look_up", @"bootstrap_check_in", @"bootstrap_register",
        @"bootstrap_create_server", @"bootstrap_subset", @"bootstrap_parent",
        @"bootstrap_status", @"bootstrap_info"
    ];

    // Search through all segments for bootstrap functions
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    for (NSString *func in bootstrapFunctions) {
                        if ([name containsString:func]) {
                            [bootstrapOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    // Search for service name strings (com.apple.*, com.*, org.*, etc.)
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            if ([section.sectionName containsString:@"string"] ||
                [section.sectionName containsString:@"cstring"] ||
                [section.sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address endAddr = section.endAddress;

                while (addr < endAddr) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:256];

                    if (str && str.length > 5) {
                        // Look for service name patterns
                        if (([str hasPrefix:@"com."] || [str hasPrefix:@"org."] || 
                             [str hasPrefix:@"net."] || [str hasPrefix:@"io."]) &&
                            [str rangeOfString:@" "].location == NSNotFound) {
                            [serviceNames addObject:@{@"address": @(addr), @"service": str}];
                        }
                    }

                    addr++;
                }
            }
        }
    }

    return @{
        @"bootstrap_ops": bootstrapOps,
        @"service_names": serviceNames
    };
}

- (NSDictionary *)findMIGHandlers:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *dispatchers = [NSMutableArray array];
    NSMutableArray *handlers = [NSMutableArray array];

    NSArray *dispatcherPatterns = @[
        @"_server", @"_subsystem", @"_server_routine", @"_demux",
        @"dispatch_mach", @"mig_server", @"mig_demux"
    ];

    NSArray *handlerPatterns = @[
        @"__X", @"_stub", @"_handler", @"mig_routine"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check for dispatcher patterns
                    for (NSString *pattern in dispatcherPatterns) {
                        if ([name containsString:pattern]) {
                            [dispatchers addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check for handler patterns
                    for (NSString *pattern in handlerPatterns) {
                        if ([name containsString:pattern]) {
                            [handlers addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"dispatchers": dispatchers,
        @"handlers": handlers
    };
}

#pragma mark - Helper Methods

- (void)logAndReportSubsystems:(NSArray *)subsystems report:(NSMutableString *)report document:(NSObject<HPDocument> *)document {
    if (subsystems.count > 0) {
        [report appendFormat:@"MIG Subsystems Found: %lu\n\n", (unsigned long)subsystems.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] MIG Subsystems Found: %lu", (unsigned long)subsystems.count]];

        for (NSDictionary *sub in subsystems) {
            [report appendFormat:@"  [0x%llx] %@\n",
                [sub[@"address"] unsignedLongLongValue], sub[@"info"]];
            [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   [0x%llx] %@",
                [sub[@"address"] unsignedLongLongValue], sub[@"info"]]];
        }
        [report appendString:@"\n"];
    } else {
        [report appendString:@"⚠️  No MIG subsystems detected\n\n"];
        [document logInfoMessage:@"[MachIPCAnalyzer] ⚠️  No MIG subsystems detected"];
    }
}

- (void)logAndReportArray:(NSArray *)items title:(NSString *)title report:(NSMutableString *)report document:(NSObject<HPDocument> *)document {
    if (items.count > 0) {
        [report appendFormat:@"%@: %lu\n\n", title, (unsigned long)items.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer] %@: %lu", title, (unsigned long)items.count]];

        for (NSDictionary *item in items) {
            NSString *value = item[@"function"] ?: item[@"service"] ?: item[@"info"];
            [report appendFormat:@"  [0x%llx] %@\n", [item[@"address"] unsignedLongLongValue], value];
            [document logInfoMessage:[NSString stringWithFormat:@"[MachIPCAnalyzer]   [0x%llx] %@",
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
