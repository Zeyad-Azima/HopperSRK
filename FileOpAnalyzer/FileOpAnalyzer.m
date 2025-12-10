//
//  FileOpAnalyzer.m
//  File Operations Analyzer - Hopper Disassembler Plugin
//
//  Comprehensive file operation detection and analysis
//  - Detects C, Objective-C, and Swift file operations
//  - Extracts all file path strings and patterns
//  - Maps complete file I/O API usage
//
//  Copyright (c) 2025 Zeyad Azima. All rights reserved.
//

#import "FileOpAnalyzer.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

@implementation FileOpAnalyzer

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
    return [self.services UUIDWithString:@"A7E8F9D2-4C3B-11EF-B864-0800200C9A66"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"File Operations Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive file operation detection: C, Objective-C, Swift APIs and file path strings";
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
    return @[@"fileop-analyzer"];
}

#pragma mark - Menu Definition

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"File Operations Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeFileOps:))
        }
    ];
}

#pragma mark - Main Analysis Function

- (void)analyzeFileOps:(nullable id)sender {
    NSObject<HPDocument> *document = self.services.currentDocument;
    if (!document) {
        [document logInfoMessage:@"[FileOpAnalyzer] No document loaded"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [document logInfoMessage:@"[FileOpAnalyzer] No disassembled file"];
        return;
    }

    [document beginToWait:@"Analyzing File Operations..."];

    NSMutableString *report = [NSMutableString string];

    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[FileOpAnalyzer]           FILE OPERATIONS ANALYSIS REPORT"];
    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Architecture: %@ %@", file.cpuFamily, file.cpuSubFamily]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Analysis Date: %@", [NSDate date]]];
    [document logInfoMessage:@"[FileOpAnalyzer] "];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"          FILE OPERATIONS ANALYSIS REPORT                             \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"\n"];
    [report appendFormat:@"Architecture: %@ %@\n", file.cpuFamily, file.cpuSubFamily];
    [report appendFormat:@"Analysis Date: %@\n", [NSDate date]];
    [report appendString:@"\n"];

    // Phase 1: C File Operation APIs
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[FileOpAnalyzer] Phase 1: Detecting C File Operation APIs..."];
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *cAPIs = [self findCFileOperations:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[1] C FILE OPERATION APIs\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[FileOpAnalyzer] [1] C FILE OPERATION APIs"];

    [self logAndReportArray:cAPIs[@"basic_ops"] title:@"Basic File Operations (open, read, write, close, etc.)" report:report document:document];
    [self logAndReportArray:cAPIs[@"symlink_ops"] title:@"Symlink/Hardlink Operations" report:report document:document];
    [self logAndReportArray:cAPIs[@"stat_ops"] title:@"File Status Operations (stat, access, etc.)" report:report document:document];
    [self logAndReportArray:cAPIs[@"perm_ops"] title:@"Permission/Ownership Operations" report:report document:document];
    [self logAndReportArray:cAPIs[@"dir_ops"] title:@"Directory Operations" report:report document:document];
    [self logAndReportArray:cAPIs[@"temp_ops"] title:@"Temporary File Operations" report:report document:document];

    // Phase 2: Objective-C File Operation APIs
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[FileOpAnalyzer] Phase 2: Detecting Objective-C File APIs..."];
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *objcAPIs = [self findObjCFileOperations:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[2] OBJECTIVE-C FILE OPERATION APIs\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[FileOpAnalyzer] [2] OBJECTIVE-C FILE OPERATION APIs"];

    [self logAndReportArray:objcAPIs[@"nsfilemanager"] title:@"NSFileManager Operations" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsfilehandle"] title:@"NSFileHandle Operations" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsdata"] title:@"NSData File Operations" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsstring"] title:@"NSString File Operations" report:report document:document];
    [self logAndReportArray:objcAPIs[@"nsbundle"] title:@"NSBundle Resource Operations" report:report document:document];

    // Phase 3: Swift File Operation APIs
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[FileOpAnalyzer] Phase 3: Detecting Swift File APIs..."];
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSArray *swiftAPIs = [self findSwiftFileOperations:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[3] SWIFT FILE OPERATION APIs\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[FileOpAnalyzer] [3] SWIFT FILE OPERATION APIs"];

    [self logAndReportArray:swiftAPIs title:@"Swift FileManager/FileHandle References" report:report document:document];

    // Phase 4: File Path String Extraction
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[FileOpAnalyzer] Phase 4: Extracting file path strings..."];
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    NSDictionary *pathStrings = [self extractFilePathStrings:file];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[4] FILE PATH STRINGS\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    [document logInfoMessage:@"[FileOpAnalyzer] [4] FILE PATH STRINGS"];

    [self logAndReportArray:pathStrings[@"absolute_paths"] title:@"Absolute Paths" report:report document:document];
    [self logAndReportArray:pathStrings[@"relative_paths"] title:@"Relative Paths (../, ./)" report:report document:document];
    [self logAndReportArray:pathStrings[@"home_paths"] title:@"Home Directory Paths (~)" report:report document:document];
    [self logAndReportArray:pathStrings[@"tmp_paths"] title:@"Temporary Directory Paths" report:report document:document];
    [self logAndReportArray:pathStrings[@"extension_patterns"] title:@"File Extensions" report:report document:document];

    // Summary
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];
    [document logInfoMessage:@"[FileOpAnalyzer] [5] ANALYSIS SUMMARY"];
    [document logInfoMessage:@"[FileOpAnalyzer] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"];

    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"];
    [report appendString:@"[5] ANALYSIS SUMMARY\n"];
    [report appendString:@"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"];

    NSUInteger totalCAPIs = [cAPIs[@"basic_ops"] count] + [cAPIs[@"symlink_ops"] count] +
                            [cAPIs[@"stat_ops"] count] + [cAPIs[@"perm_ops"] count] +
                            [cAPIs[@"dir_ops"] count] + [cAPIs[@"temp_ops"] count];

    NSUInteger totalObjCAPIs = [objcAPIs[@"nsfilemanager"] count] + [objcAPIs[@"nsfilehandle"] count] +
                               [objcAPIs[@"nsdata"] count] + [objcAPIs[@"nsstring"] count] +
                               [objcAPIs[@"nsbundle"] count];

    NSUInteger totalSwiftAPIs = [swiftAPIs count];

    NSUInteger totalPaths = [pathStrings[@"absolute_paths"] count] + [pathStrings[@"relative_paths"] count] +
                            [pathStrings[@"home_paths"] count] + [pathStrings[@"tmp_paths"] count] +
                            [pathStrings[@"extension_patterns"] count];

    [report appendFormat:@"C File APIs Found:               %lu\n", (unsigned long)totalCAPIs];
    [report appendFormat:@"  • Basic Operations:            %lu\n", (unsigned long)[cAPIs[@"basic_ops"] count]];
    [report appendFormat:@"  • Symlink/Hardlink Ops:        %lu\n", (unsigned long)[cAPIs[@"symlink_ops"] count]];
    [report appendFormat:@"  • Status Operations:           %lu\n", (unsigned long)[cAPIs[@"stat_ops"] count]];
    [report appendFormat:@"  • Permission Operations:       %lu\n", (unsigned long)[cAPIs[@"perm_ops"] count]];
    [report appendFormat:@"  • Directory Operations:        %lu\n", (unsigned long)[cAPIs[@"dir_ops"] count]];
    [report appendFormat:@"  • Temporary File Ops:          %lu\n\n", (unsigned long)[cAPIs[@"temp_ops"] count]];

    [report appendFormat:@"Objective-C File APIs Found:     %lu\n", (unsigned long)totalObjCAPIs];
    [report appendFormat:@"  • NSFileManager:               %lu\n", (unsigned long)[objcAPIs[@"nsfilemanager"] count]];
    [report appendFormat:@"  • NSFileHandle:                %lu\n", (unsigned long)[objcAPIs[@"nsfilehandle"] count]];
    [report appendFormat:@"  • NSData:                      %lu\n", (unsigned long)[objcAPIs[@"nsdata"] count]];
    [report appendFormat:@"  • NSString:                    %lu\n", (unsigned long)[objcAPIs[@"nsstring"] count]];
    [report appendFormat:@"  • NSBundle:                    %lu\n\n", (unsigned long)[objcAPIs[@"nsbundle"] count]];

    [report appendFormat:@"Swift File APIs Found:           %lu\n\n", (unsigned long)totalSwiftAPIs];

    [report appendFormat:@"File Path Strings Found:         %lu\n", (unsigned long)totalPaths];
    [report appendFormat:@"  • Absolute Paths:              %lu\n", (unsigned long)[pathStrings[@"absolute_paths"] count]];
    [report appendFormat:@"  • Relative Paths:              %lu\n", (unsigned long)[pathStrings[@"relative_paths"] count]];
    [report appendFormat:@"  • Home Paths:                  %lu\n", (unsigned long)[pathStrings[@"home_paths"] count]];
    [report appendFormat:@"  • Temp Paths:                  %lu\n", (unsigned long)[pathStrings[@"tmp_paths"] count]];
    [report appendFormat:@"  • File Extensions:             %lu\n\n", (unsigned long)[pathStrings[@"extension_patterns"] count]];

    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] C File APIs Found:               %lu", (unsigned long)totalCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Basic Operations:            %lu", (unsigned long)[cAPIs[@"basic_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Symlink/Hardlink Ops:        %lu", (unsigned long)[cAPIs[@"symlink_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Status Operations:           %lu", (unsigned long)[cAPIs[@"stat_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Permission Operations:       %lu", (unsigned long)[cAPIs[@"perm_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Directory Operations:        %lu", (unsigned long)[cAPIs[@"dir_ops"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Temporary File Ops:          %lu", (unsigned long)[cAPIs[@"temp_ops"] count]]];

    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Objective-C File APIs Found:     %lu", (unsigned long)totalObjCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • NSFileManager:               %lu", (unsigned long)[objcAPIs[@"nsfilemanager"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • NSFileHandle:                %lu", (unsigned long)[objcAPIs[@"nsfilehandle"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • NSData:                      %lu", (unsigned long)[objcAPIs[@"nsdata"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • NSString:                    %lu", (unsigned long)[objcAPIs[@"nsstring"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • NSBundle:                    %lu", (unsigned long)[objcAPIs[@"nsbundle"] count]]];

    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Swift File APIs Found:           %lu", (unsigned long)totalSwiftAPIs]];

    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] File Path Strings Found:         %lu", (unsigned long)totalPaths]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Absolute Paths:              %lu", (unsigned long)[pathStrings[@"absolute_paths"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Relative Paths:              %lu", (unsigned long)[pathStrings[@"relative_paths"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Home Paths:                  %lu", (unsigned long)[pathStrings[@"home_paths"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • Temp Paths:                  %lu", (unsigned long)[pathStrings[@"tmp_paths"] count]]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   • File Extensions:             %lu", (unsigned long)[pathStrings[@"extension_patterns"] count]]];

    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                          END OF REPORT                               \n"];
    [report appendString:@"══════════════════════════════════════════════════════════════════════\n"];

    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[FileOpAnalyzer]                       END OF REPORT"];
    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];

    // Save report
    NSString *timestamp = [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]];
    NSString *filename = [NSString stringWithFormat:@"FileOp_Analysis_%@.txt", timestamp];
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
    NSError *error = nil;
    [report writeToFile:tmpPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    [document endWaiting];

    NSString *summary = [NSString stringWithFormat:
        @"File Operations Analysis Complete\n\n"
        "C APIs: %lu\n"
        "Objective-C APIs: %lu\n"
        "Swift APIs: %lu\n"
        "File Paths: %lu\n\n"
        "Full report saved to:\n%@",
        (unsigned long)totalCAPIs,
        (unsigned long)totalObjCAPIs,
        (unsigned long)totalSwiftAPIs,
        (unsigned long)totalPaths,
        tmpPath
    ];

    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[FileOpAnalyzer] Analysis Complete!"];
    [document logInfoMessage:@"[FileOpAnalyzer] ══════════════════════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] C APIs: %lu", (unsigned long)totalCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Objective-C APIs: %lu", (unsigned long)totalObjCAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Swift APIs: %lu", (unsigned long)totalSwiftAPIs]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] File Paths: %lu", (unsigned long)totalPaths]];
    [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] Full report saved to: %@", tmpPath]];

    [document displayAlertWithMessageText:@"File Operations Analysis Complete"
                            defaultButton:@"OK"
                          alternateButton:nil
                              otherButton:nil
                          informativeText:summary];
}

#pragma mark - Analysis Methods

- (NSDictionary *)findCFileOperations:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *basicOps = [NSMutableArray array];
    NSMutableArray *symlinkOps = [NSMutableArray array];
    NSMutableArray *statOps = [NSMutableArray array];
    NSMutableArray *permOps = [NSMutableArray array];
    NSMutableArray *dirOps = [NSMutableArray array];
    NSMutableArray *tempOps = [NSMutableArray array];

    // Comprehensive C file operation functions
    NSArray *basicFunctions = @[
        @"open", @"openat", @"creat", @"close",
        @"read", @"write", @"pread", @"pwrite", @"readv", @"writev",
        @"unlink", @"unlinkat", @"rename", @"renameat",
        @"remove", @"link", @"linkat",
        @"fopen", @"fclose", @"fread", @"fwrite", @"fseek", @"ftell", @"rewind",
        @"truncate", @"ftruncate", @"dup", @"dup2", @"fcntl",
        @"lseek", @"fsync", @"fdatasync", @"sync"
    ];

    NSArray *symlinkFunctions = @[
        @"symlink", @"symlinkat", @"readlink", @"readlinkat",
        @"lstat", @"lstat64", @"fstatat"
    ];

    NSArray *statFunctions = @[
        @"stat", @"stat64", @"fstat", @"fstat64",
        @"lstat", @"lstat64", @"fstatat",
        @"access", @"faccessat", @"eaccess"
    ];

    NSArray *permFunctions = @[
        @"chmod", @"fchmod", @"fchmodat",
        @"chown", @"fchown", @"lchown", @"fchownat",
        @"umask", @"chflags", @"fchflags"
    ];

    NSArray *dirFunctions = @[
        @"mkdir", @"mkdirat", @"rmdir",
        @"opendir", @"readdir", @"readdir_r", @"closedir", @"rewinddir",
        @"chdir", @"fchdir", @"getcwd", @"getwd"
    ];

    NSArray *tempFunctions = @[
        @"mktemp", @"mkstemp", @"mkostemp", @"mkstemps",
        @"mkdtemp", @"tmpnam", @"tempnam", @"tmpfile"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check basic operations
                    for (NSString *func in basicFunctions) {
                        if ([name containsString:func]) {
                            [basicOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check symlink operations
                    for (NSString *func in symlinkFunctions) {
                        if ([name containsString:func]) {
                            [symlinkOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check stat operations
                    for (NSString *func in statFunctions) {
                        if ([name containsString:func]) {
                            [statOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check permission operations
                    for (NSString *func in permFunctions) {
                        if ([name containsString:func]) {
                            [permOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check directory operations
                    for (NSString *func in dirFunctions) {
                        if ([name containsString:func]) {
                            [dirOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }

                    // Check temp file operations
                    for (NSString *func in tempFunctions) {
                        if ([name containsString:func]) {
                            [tempOps addObject:@{@"address": @(addr), @"function": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"basic_ops": basicOps,
        @"symlink_ops": symlinkOps,
        @"stat_ops": statOps,
        @"perm_ops": permOps,
        @"dir_ops": dirOps,
        @"temp_ops": tempOps
    };
}

- (NSDictionary *)findObjCFileOperations:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *nsfilemanager = [NSMutableArray array];
    NSMutableArray *nsfilehandle = [NSMutableArray array];
    NSMutableArray *nsdata = [NSMutableArray array];
    NSMutableArray *nsstring = [NSMutableArray array];
    NSMutableArray *nsbundle = [NSMutableArray array];

    // NSFileManager methods
    NSArray *fileManagerMethods = @[
        @"createFileAtPath:", @"createDirectoryAtPath:",
        @"removeItemAtPath:", @"removeItemAtURL:",
        @"copyItemAtPath:", @"copyItemAtURL:",
        @"moveItemAtPath:", @"moveItemAtURL:",
        @"fileExistsAtPath:", @"isReadableFileAtPath:", @"isWritableFileAtPath:",
        @"attributesOfItemAtPath:", @"setAttributes:ofItemAtPath:",
        @"contentsOfDirectoryAtPath:", @"subpathsOfDirectoryAtPath:",
        @"createSymbolicLinkAtPath:", @"linkItemAtPath:",
        @"destinationOfSymbolicLinkAtPath:"
    ];

    // NSFileHandle methods
    NSArray *fileHandleMethods = @[
        @"fileHandleForReadingAtPath:", @"fileHandleForWritingAtPath:",
        @"fileHandleForUpdatingAtPath:", @"readDataToEndOfFile",
        @"readDataOfLength:", @"writeData:", @"seekToFileOffset:",
        @"closeFile", @"synchronizeFile"
    ];

    // NSData file methods
    NSArray *nsDataMethods = @[
        @"dataWithContentsOfFile:", @"dataWithContentsOfURL:",
        @"writeToFile:", @"writeToURL:"
    ];

    // NSString file methods
    NSArray *nsStringMethods = @[
        @"stringWithContentsOfFile:", @"stringWithContentsOfURL:",
        @"writeToFile:", @"writeToURL:"
    ];

    // NSBundle methods
    NSArray *nsBundleMethods = @[
        @"pathForResource:", @"URLForResource:", @"bundlePath", @"resourcePath"
    ];

    // Search through all segments
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            Address addr = section.startAddress;
            Address endAddr = section.endAddress;

            while (addr < endAddr) {
                NSString *name = [file nameForVirtualAddress:addr];

                if (name && name.length > 0) {
                    // Check NSFileManager
                    for (NSString *method in fileManagerMethods) {
                        if ([name containsString:method] || [name containsString:@"NSFileManager"]) {
                            [nsfilemanager addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check NSFileHandle
                    for (NSString *method in fileHandleMethods) {
                        if ([name containsString:method] || [name containsString:@"NSFileHandle"]) {
                            [nsfilehandle addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check NSData
                    for (NSString *method in nsDataMethods) {
                        if ([name containsString:method] && [name containsString:@"File"]) {
                            [nsdata addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check NSString
                    for (NSString *method in nsStringMethods) {
                        if ([name containsString:method] && [name containsString:@"NSString"]) {
                            [nsstring addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }

                    // Check NSBundle
                    for (NSString *method in nsBundleMethods) {
                        if ([name containsString:method] || [name containsString:@"NSBundle"]) {
                            [nsbundle addObject:@{@"address": @(addr), @"method": name}];
                            break;
                        }
                    }
                }

                addr += 4;
            }
        }
    }

    return @{
        @"nsfilemanager": nsfilemanager,
        @"nsfilehandle": nsfilehandle,
        @"nsdata": nsdata,
        @"nsstring": nsstring,
        @"nsbundle": nsbundle
    };
}

- (NSArray *)findSwiftFileOperations:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *swiftOps = [NSMutableArray array];

    // Swift file operation patterns
    NSArray *swiftPatterns = @[
        @"FileManager", @"FileHandle", @"URL.contentsOf",
        @"Data.write", @"String.write", @"Bundle.url"
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

- (NSDictionary *)extractFilePathStrings:(NSObject<HPDisassembledFile> *)file {
    NSMutableArray *absolutePaths = [NSMutableArray array];
    NSMutableArray *relativePaths = [NSMutableArray array];
    NSMutableArray *homePaths = [NSMutableArray array];
    NSMutableArray *tmpPaths = [NSMutableArray array];
    NSMutableArray *extensions = [NSMutableArray array];

    // Scan all string sections
    for (NSObject<HPSegment> *segment in file.segments) {
        for (NSObject<HPSection> *section in segment.sections) {
            if ([section.sectionName containsString:@"string"] ||
                [section.sectionName containsString:@"cstring"] ||
                [section.sectionName isEqualToString:@"__const"]) {

                Address addr = section.startAddress;
                Address endAddr = section.endAddress;

                while (addr < endAddr) {
                    NSString *str = [self readStringAtAddress:addr file:file maxLength:256];

                    if (str && str.length > 2) {
                        // Absolute paths
                        if ([str hasPrefix:@"/"] && [str containsString:@"/"]) {
                            [absolutePaths addObject:@{@"address": @(addr), @"path": str}];
                        }
                        // Relative paths
                        else if ([str hasPrefix:@"../"] || [str hasPrefix:@"./"]) {
                            [relativePaths addObject:@{@"address": @(addr), @"path": str}];
                        }
                        // Home paths
                        else if ([str hasPrefix:@"~/"]) {
                            [homePaths addObject:@{@"address": @(addr), @"path": str}];
                        }
                        // Temp paths
                        else if ([str containsString:@"/tmp"] || [str containsString:@"/var/tmp"] ||
                                [str containsString:@"NSTemporaryDirectory"]) {
                            [tmpPaths addObject:@{@"address": @(addr), @"path": str}];
                        }
                        // File extensions
                        else if ([str containsString:@"."]) {
                            NSRange range = [str rangeOfString:@"." options:NSBackwardsSearch];
                            if (range.location != NSNotFound && range.location < str.length - 1) {
                                NSString *ext = [str substringFromIndex:range.location];
                                if (ext.length <= 10 && ![ext containsString:@"/"]) {
                                    [extensions addObject:@{@"address": @(addr), @"extension": ext, @"string": str}];
                                }
                            }
                        }
                    }

                    addr += 1;
                }
            }
        }
    }

    return @{
        @"absolute_paths": absolutePaths,
        @"relative_paths": relativePaths,
        @"home_paths": homePaths,
        @"tmp_paths": tmpPaths,
        @"extension_patterns": extensions
    };
}

#pragma mark - Helper Methods

- (void)logAndReportArray:(NSArray *)items title:(NSString *)title report:(NSMutableString *)report document:(NSObject<HPDocument> *)document {
    if (items.count > 0) {
        [report appendFormat:@"%@: %lu\n\n", title, (unsigned long)items.count];
        [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] %@: %lu", title, (unsigned long)items.count]];

        for (NSDictionary *item in items) {
            if (item[@"function"]) {
                [report appendFormat:@"  [0x%llx] %@\n",
                    [item[@"address"] unsignedLongLongValue], item[@"function"]];
                [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   [0x%llx] %@",
                    [item[@"address"] unsignedLongLongValue], item[@"function"]]];
            } else if (item[@"method"]) {
                [report appendFormat:@"  [0x%llx] %@\n",
                    [item[@"address"] unsignedLongLongValue], item[@"method"]];
                [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   [0x%llx] %@",
                    [item[@"address"] unsignedLongLongValue], item[@"method"]]];
            } else if (item[@"symbol"]) {
                [report appendFormat:@"  [0x%llx] %@\n",
                    [item[@"address"] unsignedLongLongValue], item[@"symbol"]];
                [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   [0x%llx] %@",
                    [item[@"address"] unsignedLongLongValue], item[@"symbol"]]];
            } else if (item[@"path"]) {
                [report appendFormat:@"  [0x%llx] %@\n",
                    [item[@"address"] unsignedLongLongValue], item[@"path"]];
                [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   [0x%llx] %@",
                    [item[@"address"] unsignedLongLongValue], item[@"path"]]];
            } else if (item[@"extension"]) {
                [report appendFormat:@"  [0x%llx] %@ (%@)\n",
                    [item[@"address"] unsignedLongLongValue], item[@"extension"], item[@"string"]];
                [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer]   [0x%llx] %@ (%@)",
                    [item[@"address"] unsignedLongLongValue], item[@"extension"], item[@"string"]]];
            }
        }
        [report appendString:@"\n"];
    } else {
        [report appendFormat:@"%@: 0\n\n", title];
        [document logInfoMessage:[NSString stringWithFormat:@"[FileOpAnalyzer] %@: 0", title]];
    }
}

- (NSString *)readStringAtAddress:(Address)addr file:(NSObject<HPDisassembledFile> *)file maxLength:(NSUInteger)maxLen {
    NSMutableString *result = [NSMutableString string];

    for (NSUInteger i = 0; i < maxLen; i++) {
        uint8_t byte = [file readUInt8AtVirtualAddress:addr + i];

        if (byte == 0) {
            break;
        }

        if (byte >= 32 && byte < 127) {
            [result appendFormat:@"%c", (char)byte];
        } else {
            break;
        }
    }

    return result.length >= 4 ? result : nil;
}

@end

#pragma clang diagnostic pop
