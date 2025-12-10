/*
 SyscallAnalyzer.m
 System Call Analyzer Plugin for Hopper Disassembler

 Comprehensive detection of direct system call usage across:
 - BSD System Calls
 - Mach Traps
 - Syscall Instructions & Wrappers
 - Dangerous/Security-Critical Syscalls
 - Syscall Number References
 - macOS-Specific Syscalls

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

#import "SyscallAnalyzer.h"

@implementation SyscallAnalyzer

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
    return @"com.zeyadazima.hopper.SyscallAnalyzer";
}

- (NSString *)pluginUUID {
    return @"C3D4E5F6-0A1B-11EF-F678-0800200C9C33";
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Syscall Analyzer";
}

- (NSString *)pluginDescription {
    return @"Comprehensive system call analyzer detecting BSD syscalls, Mach traps, syscall wrappers, dangerous syscalls, syscall numbers, and macOS-specific operations";
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
    return @[@"syscallanalyzer"];
}

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"System Call Analyzer",
            HPM_SELECTOR: NSStringFromSelector(@selector(analyzeSyscalls:))
        }
    ];
}

#pragma mark - Main Analysis Entry Point

- (void)analyzeSyscalls:(nullable id)sender {
    NSObject<HPDocument> *document = [self.services currentDocument];
    if (!document) {
        [self.services logMessage:@"[SyscallAnalyzer] No document open"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[SyscallAnalyzer] No disassembled file available"];
        return;
    }

    [document logInfoMessage:@"[SyscallAnalyzer] Starting comprehensive system call analysis..."];

    NSMutableString *report = [NSMutableString string];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                 SYSTEM CALL ANALYSIS\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    NSUInteger totalDetections = 0;

    // Phase 1: BSD System Calls
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 1: Analyzing BSD system calls..."];
    NSDictionary *bsdResults = [self detectBSDSyscalls:file document:document];
    NSUInteger bsdCount = [self addBSDResultsToReport:report results:bsdResults];
    totalDetections += bsdCount;

    // Phase 2: Mach Traps
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 2: Analyzing Mach traps..."];
    NSDictionary *machResults = [self detectMachTraps:file document:document];
    NSUInteger machCount = [self addMachResultsToReport:report results:machResults];
    totalDetections += machCount;

    // Phase 3: Syscall Instructions & Wrappers
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 3: Analyzing syscall instructions and wrappers..."];
    NSDictionary *wrapperResults = [self detectSyscallWrappers:file document:document];
    NSUInteger wrapperCount = [self addWrapperResultsToReport:report results:wrapperResults];
    totalDetections += wrapperCount;

    // Phase 4: Dangerous/Security-Critical Syscalls
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 4: Analyzing dangerous syscalls..."];
    NSDictionary *dangerousResults = [self detectDangerousSyscalls:file document:document];
    NSUInteger dangerousCount = [self addDangerousResultsToReport:report results:dangerousResults];
    totalDetections += dangerousCount;

    // Phase 5: Syscall Number References
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 5: Analyzing syscall number references..."];
    NSDictionary *numberResults = [self detectSyscallNumbers:file document:document];
    NSUInteger numberCount = [self addNumberResultsToReport:report results:numberResults];
    totalDetections += numberCount;

    // Phase 6: macOS-Specific Syscalls
    [document logInfoMessage:@"[SyscallAnalyzer] Phase 6: Analyzing macOS-specific syscalls..."];
    NSDictionary *macosResults = [self detectMacOSSyscalls:file document:document];
    NSUInteger macosCount = [self addMacOSResultsToReport:report results:macosResults];
    totalDetections += macosCount;

    // Summary
    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                         SUMMARY\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total System Call Indicators: %lu\n\n", (unsigned long)totalDetections];

    if (totalDetections > 0) {
        [report appendString:@"System Call Usage Detected\n\n"];
        [report appendString:@"Analysis Notes:\n"];
        [report appendString:@"1. BSD Syscalls: Standard POSIX/BSD system calls\n"];
        [report appendString:@"2. Mach Traps: Low-level Mach kernel operations\n"];
        [report appendString:@"3. Syscall Wrappers: Indirect syscall invocation patterns\n"];
        [report appendString:@"4. Dangerous Syscalls: Security-sensitive operations requiring scrutiny\n"];
        [report appendString:@"5. Syscall Numbers: Direct numeric syscall references\n"];
        [report appendString:@"6. macOS-Specific: Darwin/XNU-specific system calls\n\n"];

        if (dangerousCount > 0) {
            [report appendString:@"⚠️  SECURITY WARNING: Dangerous syscalls detected!\n"];
            [report appendString:@"Review these operations carefully for security implications.\n"];
        }
    } else {
        [report appendString:@"✓ No direct system call usage detected\n"];
        [report appendString:@"Note: Binary may use higher-level library functions\n"];
    }

    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];

    // Save report to file
    NSString *reportPath = [NSString stringWithFormat:@"/tmp/syscall_analysis_%@.txt",
                           [[NSDate date] descriptionWithLocale:nil]];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@":" withString:@"-"];

    NSError *error = nil;
    [report writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (!error) {
        [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Report saved to: %@", reportPath]];
    }

    // Display summary in console
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[SyscallAnalyzer] Analysis Complete"];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Total Indicators: %lu", (unsigned long)totalDetections]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] BSD Syscalls: %lu", (unsigned long)bsdCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Mach Traps: %lu", (unsigned long)machCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Syscall Wrappers: %lu", (unsigned long)wrapperCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Dangerous Syscalls: %lu", (unsigned long)dangerousCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Syscall Numbers: %lu", (unsigned long)numberCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] macOS-Specific: %lu", (unsigned long)macosCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[SyscallAnalyzer] Report saved to: %@", reportPath]];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
}

#pragma mark - Phase 1: BSD System Calls Detection

- (NSDictionary *)detectBSDSyscalls:(NSObject<HPDisassembledFile> *)file
                           document:(NSObject<HPDocument> *)document {
    NSMutableArray *fileIOAPIs = [NSMutableArray array];
    NSMutableArray *processAPIs = [NSMutableArray array];
    NSMutableArray *signalAPIs = [NSMutableArray array];
    NSMutableArray *memoryAPIs = [NSMutableArray array];

    // File I/O syscalls (25 patterns)
    NSArray *fileIOPatterns = @[
        @"SYS_read", @"SYS_write", @"SYS_open", @"SYS_close",
        @"SYS_lseek", @"SYS_fstat", @"SYS_stat", @"SYS_lstat",
        @"SYS_access", @"SYS_dup", @"SYS_dup2",
        @"SYS_fcntl", @"SYS_ioctl",
        @"SYS_readv", @"SYS_writev",
        @"SYS_pread", @"SYS_pwrite",
        @"SYS_openat", @"SYS_fstatat",
        @"SYS_readlink", @"SYS_readlinkat",
        @"SYS_mkdir", @"SYS_rmdir", @"SYS_unlink",
        @"SYS_rename"
    ];

    // Process management syscalls (20 patterns)
    NSArray *processPatterns = @[
        @"SYS_fork", @"SYS_vfork", @"SYS_execve",
        @"SYS_posix_spawn",
        @"SYS_exit", @"SYS__exit",
        @"SYS_wait4", @"SYS_waitpid",
        @"SYS_getpid", @"SYS_getppid",
        @"SYS_getuid", @"SYS_geteuid",
        @"SYS_getgid", @"SYS_getegid",
        @"SYS_setuid", @"SYS_setgid",
        @"SYS_kill", @"SYS_killpg",
        @"SYS_getpgrp", @"SYS_setpgid"
    ];

    // Signal handling syscalls (12 patterns)
    NSArray *signalPatterns = @[
        @"SYS_sigaction", @"SYS_signal",
        @"SYS_sigprocmask", @"SYS_sigsuspend",
        @"SYS_sigpending", @"SYS_sigaltstack",
        @"SYS_sigreturn",
        @"SYS_sigwait", @"SYS_sigwaitinfo",
        @"SYS_kill", @"SYS_pthread_kill",
        @"SYS_sigqueue"
    ];

    // Memory management syscalls (15 patterns)
    NSArray *memoryPatterns = @[
        @"SYS_mmap", @"SYS_munmap",
        @"SYS_mprotect", @"SYS_madvise",
        @"SYS_mincore", @"SYS_msync",
        @"SYS_mlock", @"SYS_munlock",
        @"SYS_mlockall", @"SYS_munlockall",
        @"SYS_brk", @"SYS_sbrk",
        @"SYS_shmat", @"SYS_shmdt", @"SYS_shmget"
    ];

    [self scanStringsForPatterns:fileIOPatterns inFile:file results:fileIOAPIs maxResults:100];
    [self scanStringsForPatterns:processPatterns inFile:file results:processAPIs maxResults:100];
    [self scanStringsForPatterns:signalPatterns inFile:file results:signalAPIs maxResults:100];
    [self scanStringsForPatterns:memoryPatterns inFile:file results:memoryAPIs maxResults:100];

    return @{
        @"fileio": [fileIOAPIs copy],
        @"process": [processAPIs copy],
        @"signal": [signalAPIs copy],
        @"memory": [memoryAPIs copy]
    };
}

- (NSUInteger)addBSDResultsToReport:(NSMutableString *)report
                            results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 1: BSD SYSTEM CALLS\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *fileIOAPIs = results[@"fileio"];
    NSArray *processAPIs = results[@"process"];
    NSArray *signalAPIs = results[@"signal"];
    NSArray *memoryAPIs = results[@"memory"];

    [report appendFormat:@"File I/O Syscalls: %lu\n", (unsigned long)fileIOAPIs.count];
    if (fileIOAPIs.count > 0) {
        [report appendString:@"  File system operations detected\n"];
        for (NSDictionary *match in [fileIOAPIs subarrayWithRange:NSMakeRange(0, MIN(5, fileIOAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (fileIOAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(fileIOAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += fileIOAPIs.count;

    [report appendFormat:@"Process Management Syscalls: %lu\n", (unsigned long)processAPIs.count];
    if (processAPIs.count > 0) {
        [report appendString:@"  Process control operations detected\n"];
        for (NSDictionary *match in [processAPIs subarrayWithRange:NSMakeRange(0, MIN(5, processAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (processAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(processAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += processAPIs.count;

    [report appendFormat:@"Signal Handling Syscalls: %lu\n", (unsigned long)signalAPIs.count];
    if (signalAPIs.count > 0) {
        [report appendString:@"  Signal operations detected\n"];
        for (NSDictionary *match in [signalAPIs subarrayWithRange:NSMakeRange(0, MIN(5, signalAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (signalAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(signalAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += signalAPIs.count;

    [report appendFormat:@"Memory Management Syscalls: %lu\n", (unsigned long)memoryAPIs.count];
    if (memoryAPIs.count > 0) {
        [report appendString:@"  Memory operations detected\n"];
        for (NSDictionary *match in [memoryAPIs subarrayWithRange:NSMakeRange(0, MIN(5, memoryAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (memoryAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(memoryAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += memoryAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No BSD system calls detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 2: Mach Traps Detection

- (NSDictionary *)detectMachTraps:(NSObject<HPDisassembledFile> *)file
                         document:(NSObject<HPDocument> *)document {
    NSMutableArray *msgTraps = [NSMutableArray array];
    NSMutableArray *threadTraps = [NSMutableArray array];
    NSMutableArray *semaphoreTraps = [NSMutableArray array];
    NSMutableArray *portTraps = [NSMutableArray array];

    // Mach message traps (10 patterns)
    NSArray *msgPatterns = @[
        @"mach_msg_trap", @"mach_msg",
        @"mach_msg_overwrite_trap",
        @"mach_reply_port",
        @"msg_send_trap", @"msg_receive_trap",
        @"MACH_MSG_", @"MACH_SEND_", @"MACH_RCV_",
        @"mach_msg2_trap"
    ];

    // Thread traps (12 patterns)
    NSArray *threadPatterns = @[
        @"thread_self_trap", @"task_self_trap",
        @"thread_switch", @"thread_switch_trap",
        @"thread_get_state", @"thread_set_state",
        @"_kernelrpc_mach_port_construct_trap",
        @"_kernelrpc_mach_port_destruct_trap",
        @"thread_create", @"thread_terminate",
        @"swtch_pri", @"swtch"
    ];

    // Semaphore traps (10 patterns)
    NSArray *semaphorePatterns = @[
        @"semaphore_signal_trap",
        @"semaphore_signal_all_trap",
        @"semaphore_wait_trap",
        @"semaphore_wait_signal_trap",
        @"semaphore_timedwait_trap",
        @"semaphore_create", @"semaphore_destroy",
        @"SYNC_POLICY_", @"sync_wait",
        @"clock_sleep_trap"
    ];

    // Port operation traps (12 patterns)
    NSArray *portPatterns = @[
        @"mach_port_allocate_trap",
        @"mach_port_deallocate_trap",
        @"mach_port_insert_right_trap",
        @"mach_port_extract_right_trap",
        @"mach_port_construct_trap",
        @"mach_port_destruct_trap",
        @"mach_port_guard_trap",
        @"mach_port_unguard_trap",
        @"mk_timer_create_trap",
        @"mk_timer_destroy_trap",
        @"mk_timer_arm_trap",
        @"mk_timer_cancel_trap"
    ];

    [self scanStringsForPatterns:msgPatterns inFile:file results:msgTraps maxResults:100];
    [self scanStringsForPatterns:threadPatterns inFile:file results:threadTraps maxResults:100];
    [self scanStringsForPatterns:semaphorePatterns inFile:file results:semaphoreTraps maxResults:100];
    [self scanStringsForPatterns:portPatterns inFile:file results:portTraps maxResults:100];

    return @{
        @"message": [msgTraps copy],
        @"thread": [threadTraps copy],
        @"semaphore": [semaphoreTraps copy],
        @"port": [portTraps copy]
    };
}

- (NSUInteger)addMachResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 2: MACH TRAPS\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *msgTraps = results[@"message"];
    NSArray *threadTraps = results[@"thread"];
    NSArray *semaphoreTraps = results[@"semaphore"];
    NSArray *portTraps = results[@"port"];

    [report appendFormat:@"Mach Message Traps: %lu\n", (unsigned long)msgTraps.count];
    if (msgTraps.count > 0) {
        [report appendString:@"  Mach IPC operations detected\n"];
        for (NSDictionary *match in [msgTraps subarrayWithRange:NSMakeRange(0, MIN(5, msgTraps.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (msgTraps.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(msgTraps.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += msgTraps.count;

    [report appendFormat:@"Thread/Task Traps: %lu\n", (unsigned long)threadTraps.count];
    if (threadTraps.count > 0) {
        [report appendString:@"  Thread manipulation operations detected\n"];
        for (NSDictionary *match in [threadTraps subarrayWithRange:NSMakeRange(0, MIN(5, threadTraps.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (threadTraps.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(threadTraps.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += threadTraps.count;

    [report appendFormat:@"Semaphore Traps: %lu\n", (unsigned long)semaphoreTraps.count];
    if (semaphoreTraps.count > 0) {
        [report appendString:@"  Synchronization primitives detected\n"];
        for (NSDictionary *match in [semaphoreTraps subarrayWithRange:NSMakeRange(0, MIN(5, semaphoreTraps.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (semaphoreTraps.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(semaphoreTraps.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += semaphoreTraps.count;

    [report appendFormat:@"Port Operation Traps: %lu\n", (unsigned long)portTraps.count];
    if (portTraps.count > 0) {
        [report appendString:@"  Mach port operations detected\n"];
        for (NSDictionary *match in [portTraps subarrayWithRange:NSMakeRange(0, MIN(5, portTraps.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (portTraps.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(portTraps.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += portTraps.count;

    if (total == 0) {
        [report appendString:@"✓ No Mach traps detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 3: Syscall Instructions & Wrappers Detection

- (NSDictionary *)detectSyscallWrappers:(NSObject<HPDisassembledFile> *)file
                               document:(NSObject<HPDocument> *)document {
    NSMutableArray *wrapperAPIs = [NSMutableArray array];
    NSMutableArray *indirectAPIs = [NSMutableArray array];

    // Syscall wrappers (15 patterns)
    NSArray *wrapperPatterns = @[
        @"__syscall", @"syscall",
        @"__mac_syscall",
        @"__pthread_kill",
        @"__sysctl",
        @"___sysctl",
        @"__sysctlbyname",
        @"_syscall",
        @"cerror", @"cerror_nocancel",
        @"__commpage_", @"_commpage",
        @"SYSCALL", @"syscall_",
        @"indirect_syscall"
    ];

    // Indirect syscall patterns (10 patterns)
    NSArray *indirectPatterns = @[
        @"syscall_indirect",
        @"dispatch_syscall",
        @"invoke_syscall",
        @"call_syscall",
        @"indirect_call",
        @"syscall_wrapper",
        @"syscall_gate",
        @"enter_syscall",
        @"syscall_entry",
        @"syscall_stub"
    ];

    [self scanStringsForPatterns:wrapperPatterns inFile:file results:wrapperAPIs maxResults:100];
    [self scanStringsForPatterns:indirectPatterns inFile:file results:indirectAPIs maxResults:100];

    return @{
        @"wrapper": [wrapperAPIs copy],
        @"indirect": [indirectAPIs copy]
    };
}

- (NSUInteger)addWrapperResultsToReport:(NSMutableString *)report
                                results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 3: SYSCALL INSTRUCTIONS & WRAPPERS\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *wrapperAPIs = results[@"wrapper"];
    NSArray *indirectAPIs = results[@"indirect"];

    [report appendFormat:@"Syscall Wrappers: %lu\n", (unsigned long)wrapperAPIs.count];
    if (wrapperAPIs.count > 0) {
        [report appendString:@"  Syscall wrapper functions detected\n"];
        for (NSDictionary *match in [wrapperAPIs subarrayWithRange:NSMakeRange(0, MIN(5, wrapperAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (wrapperAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(wrapperAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += wrapperAPIs.count;

    [report appendFormat:@"Indirect Syscall Patterns: %lu\n", (unsigned long)indirectAPIs.count];
    if (indirectAPIs.count > 0) {
        [report appendString:@"  Indirect syscall invocation detected\n"];
        for (NSDictionary *match in [indirectAPIs subarrayWithRange:NSMakeRange(0, MIN(5, indirectAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (indirectAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(indirectAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += indirectAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No syscall wrappers detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 4: Dangerous/Security-Critical Syscalls Detection

- (NSDictionary *)detectDangerousSyscalls:(NSObject<HPDisassembledFile> *)file
                                 document:(NSObject<HPDocument> *)document {
    NSMutableArray *antiDebugAPIs = [NSMutableArray array];
    NSMutableArray *injectionAPIs = [NSMutableArray array];
    NSMutableArray *kernelAPIs = [NSMutableArray array];
    NSMutableArray *execMemAPIs = [NSMutableArray array];

    // Anti-debugging syscalls (10 patterns)
    NSArray *antiDebugPatterns = @[
        @"SYS_ptrace", @"ptrace",
        @"PT_DENY_ATTACH", @"PT_TRACE_ME",
        @"SYS_sysctl", @"KERN_PROC",
        @"P_TRACED",
        @"task_get_exception_ports",
        @"exception_raise",
        @"debugger_detection"
    ];

    // Process injection syscalls (12 patterns)
    NSArray *injectionPatterns = @[
        @"task_for_pid", @"SYS_task_for_pid",
        @"thread_create_running",
        @"SYS_thread_create",
        @"vm_read", @"vm_write",
        @"SYS_vm_read", @"SYS_vm_write",
        @"mach_vm_read", @"mach_vm_write",
        @"vm_remap", @"vm_copy"
    ];

    // Kernel operation syscalls (15 patterns)
    NSArray *kernelPatterns = @[
        @"SYS_kextload", @"kextload",
        @"SYS_kextunload", @"kextunload",
        @"iokit_user_client_trap",
        @"IOConnectTrap",
        @"host_get_special_port",
        @"processor_set_tasks",
        @"SYS_reboot",
        @"SYS_mount", @"SYS_unmount",
        @"kernel_memory", @"kernel_task",
        @"HOST_PRIV_PORT"
    ];

    // Executable memory syscalls (10 patterns)
    NSArray *execMemPatterns = @[
        @"mprotect", @"SYS_mprotect",
        @"PROT_EXEC", @"PROT_WRITE",
        @"MAP_ANON", @"MAP_PRIVATE",
        @"vm_protect",
        @"mach_vm_protect",
        @"vm_allocate",
        @"executable_memory"
    ];

    [self scanStringsForPatterns:antiDebugPatterns inFile:file results:antiDebugAPIs maxResults:100];
    [self scanStringsForPatterns:injectionPatterns inFile:file results:injectionAPIs maxResults:100];
    [self scanStringsForPatterns:kernelPatterns inFile:file results:kernelAPIs maxResults:100];
    [self scanStringsForPatterns:execMemPatterns inFile:file results:execMemAPIs maxResults:100];

    return @{
        @"antidebug": [antiDebugAPIs copy],
        @"injection": [injectionAPIs copy],
        @"kernel": [kernelAPIs copy],
        @"execmem": [execMemAPIs copy]
    };
}

- (NSUInteger)addDangerousResultsToReport:(NSMutableString *)report
                                  results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 4: DANGEROUS/SECURITY-CRITICAL SYSCALLS\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *antiDebugAPIs = results[@"antidebug"];
    NSArray *injectionAPIs = results[@"injection"];
    NSArray *kernelAPIs = results[@"kernel"];
    NSArray *execMemAPIs = results[@"execmem"];

    [report appendFormat:@"Anti-Debugging Syscalls: %lu\n", (unsigned long)antiDebugAPIs.count];
    if (antiDebugAPIs.count > 0) {
        [report appendString:@"  ⚠️  Anti-debugging operations detected\n"];
        for (NSDictionary *match in [antiDebugAPIs subarrayWithRange:NSMakeRange(0, MIN(5, antiDebugAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (antiDebugAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(antiDebugAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += antiDebugAPIs.count;

    [report appendFormat:@"Process Injection Syscalls: %lu\n", (unsigned long)injectionAPIs.count];
    if (injectionAPIs.count > 0) {
        [report appendString:@"  ⚠️  Process injection capabilities detected\n"];
        for (NSDictionary *match in [injectionAPIs subarrayWithRange:NSMakeRange(0, MIN(5, injectionAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (injectionAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(injectionAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += injectionAPIs.count;

    [report appendFormat:@"Kernel Operation Syscalls: %lu\n", (unsigned long)kernelAPIs.count];
    if (kernelAPIs.count > 0) {
        [report appendString:@"  ⚠️  Kernel-level operations detected\n"];
        for (NSDictionary *match in [kernelAPIs subarrayWithRange:NSMakeRange(0, MIN(5, kernelAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (kernelAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(kernelAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += kernelAPIs.count;

    [report appendFormat:@"Executable Memory Syscalls: %lu\n", (unsigned long)execMemAPIs.count];
    if (execMemAPIs.count > 0) {
        [report appendString:@"  ⚠️  Executable memory allocation detected\n"];
        for (NSDictionary *match in [execMemAPIs subarrayWithRange:NSMakeRange(0, MIN(5, execMemAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (execMemAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(execMemAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += execMemAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No dangerous syscalls detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 5: Syscall Number References Detection

- (NSDictionary *)detectSyscallNumbers:(NSObject<HPDisassembledFile> *)file
                              document:(NSObject<HPDocument> *)document {
    NSMutableArray *syscallNums = [NSMutableArray array];
    NSMutableArray *machNums = [NSMutableArray array];

    // Syscall number constants (20 patterns)
    NSArray *syscallNumPatterns = @[
        @"0x2000000", @"0x2000001", @"0x2000002", @"0x2000003",
        @"0x2000004", @"0x2000005", @"0x2000006",
        @"SYS_syscall", @"__NR_",
        @"syscall_number", @"syscall_num",
        @"SYSCALL_", @"syscall_class",
        @"BSD_SYSCALL", @"MACH_SYSCALL",
        @"syscall_base", @"syscall_max",
        @"nsysent", @"syscall_table",
        @"sysent"
    ];

    // Mach trap numbers (15 patterns)
    NSArray *machNumPatterns = @[
        @"-26", @"-27", @"-28", @"-29",
        @"-31", @"-32", @"-33",
        @"MACH_TRAP_", @"mach_trap_",
        @"trap_number", @"trap_num",
        @"KERN_", @"mach_trap_table",
        @"mach_trap_count",
        @"negative_trap"
    ];

    [self scanStringsForPatterns:syscallNumPatterns inFile:file results:syscallNums maxResults:100];
    [self scanStringsForPatterns:machNumPatterns inFile:file results:machNums maxResults:100];

    return @{
        @"syscall": [syscallNums copy],
        @"mach": [machNums copy]
    };
}

- (NSUInteger)addNumberResultsToReport:(NSMutableString *)report
                               results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 5: SYSCALL NUMBER REFERENCES\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *syscallNums = results[@"syscall"];
    NSArray *machNums = results[@"mach"];

    [report appendFormat:@"Syscall Number Constants: %lu\n", (unsigned long)syscallNums.count];
    if (syscallNums.count > 0) {
        [report appendString:@"  Direct syscall number references detected\n"];
        for (NSDictionary *match in [syscallNums subarrayWithRange:NSMakeRange(0, MIN(5, syscallNums.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (syscallNums.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(syscallNums.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += syscallNums.count;

    [report appendFormat:@"Mach Trap Numbers: %lu\n", (unsigned long)machNums.count];
    if (machNums.count > 0) {
        [report appendString:@"  Mach trap number references detected\n"];
        for (NSDictionary *match in [machNums subarrayWithRange:NSMakeRange(0, MIN(5, machNums.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (machNums.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(machNums.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += machNums.count;

    if (total == 0) {
        [report appendString:@"✓ No syscall number references detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 6: macOS-Specific Syscalls Detection

- (NSDictionary *)detectMacOSSyscalls:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *darwinAPIs = [NSMutableArray array];
    NSMutableArray *sandboxAPIs = [NSMutableArray array];
    NSMutableArray *securityAPIs = [NSMutableArray array];

    // Darwin-specific syscalls (15 patterns)
    NSArray *darwinPatterns = @[
        @"shared_region_check_np",
        @"shared_region_map_np",
        @"guarded_open_np",
        @"guarded_close_np",
        @"change_fdguard_np",
        @"connectx", @"disconnectx",
        @"peeloff",
        @"socket_delegate",
        @"workq_", @"__workq_",
        @"bsdthread_", @"__bsdthread_",
        @"coalition_", @"ledger_"
    ];

    // Sandbox syscalls (12 patterns)
    NSArray *sandboxPatterns = @[
        @"__mac_syscall", @"mac_syscall",
        @"__sandbox_ms",
        @"sandbox_init", @"sandbox_free_error",
        @"MAC_", @"mac_",
        @"SYS_mac_", @"SYS___mac_",
        @"sandbox_", @"SANDBOX_",
        @"mac_policy"
    ];

    // Security framework syscalls (12 patterns)
    NSArray *securityPatterns = @[
        @"csops", @"csops_audittoken",
        @"SYS_csops", @"SYS_csops_audittoken",
        @"CS_OPS_", @"cs_ops_",
        @"code_signature",
        @"amfi_", @"AMFI_",
        @"entitlement_",
        @"platform_binary",
        @"cs_enforcement"
    ];

    [self scanStringsForPatterns:darwinPatterns inFile:file results:darwinAPIs maxResults:100];
    [self scanStringsForPatterns:sandboxPatterns inFile:file results:sandboxAPIs maxResults:100];
    [self scanStringsForPatterns:securityPatterns inFile:file results:securityAPIs maxResults:100];

    return @{
        @"darwin": [darwinAPIs copy],
        @"sandbox": [sandboxAPIs copy],
        @"security": [securityAPIs copy]
    };
}

- (NSUInteger)addMacOSResultsToReport:(NSMutableString *)report
                              results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 6: macOS-SPECIFIC SYSCALLS\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *darwinAPIs = results[@"darwin"];
    NSArray *sandboxAPIs = results[@"sandbox"];
    NSArray *securityAPIs = results[@"security"];

    [report appendFormat:@"Darwin-Specific Syscalls: %lu\n", (unsigned long)darwinAPIs.count];
    if (darwinAPIs.count > 0) {
        [report appendString:@"  Darwin/XNU-specific operations detected\n"];
        for (NSDictionary *match in [darwinAPIs subarrayWithRange:NSMakeRange(0, MIN(5, darwinAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (darwinAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(darwinAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += darwinAPIs.count;

    [report appendFormat:@"Sandbox Syscalls: %lu\n", (unsigned long)sandboxAPIs.count];
    if (sandboxAPIs.count > 0) {
        [report appendString:@"  Sandbox/MAC framework operations detected\n"];
        for (NSDictionary *match in [sandboxAPIs subarrayWithRange:NSMakeRange(0, MIN(5, sandboxAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (sandboxAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(sandboxAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += sandboxAPIs.count;

    [report appendFormat:@"Security Framework Syscalls: %lu\n", (unsigned long)securityAPIs.count];
    if (securityAPIs.count > 0) {
        [report appendString:@"  Code signing/security operations detected\n"];
        for (NSDictionary *match in [securityAPIs subarrayWithRange:NSMakeRange(0, MIN(5, securityAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (securityAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(securityAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += securityAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No macOS-specific syscalls detected\n\n"];
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
