/*
 RootkitDetector.m
 Rootkit Detection Plugin for Hopper Disassembler

 Comprehensive detection of rootkit techniques across:
 - Kernel Extensions and IOKit
 - System Call Hooking
 - Function Hooking and Interposing
 - Kernel Memory Manipulation
 - Process Hiding Techniques
 - Privilege Escalation

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

#import "RootkitDetector.h"

@implementation RootkitDetector

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
    return @"com.zeyadazima.hopper.RootkitDetector";
}

- (NSString *)pluginUUID {
    return @"A1B2C3D4-8F9E-11EF-D456-0800200C9A11";
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Rootkit Detector";
}

- (NSString *)pluginDescription {
    return @"Comprehensive rootkit detection analyzing kernel extensions, syscall hooking, function hooking, kernel memory manipulation, process hiding, and privilege escalation techniques";
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
    return @[@"rootkitdetector"];
}

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Rootkit Detector",
            HPM_SELECTOR: NSStringFromSelector(@selector(detectRootkit:))
        }
    ];
}

#pragma mark - Main Analysis Entry Point

- (void)detectRootkit:(nullable id)sender {
    NSObject<HPDocument> *document = [self.services currentDocument];
    if (!document) {
        [self.services logMessage:@"[RootkitDetector] No document open"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[RootkitDetector] No disassembled file available"];
        return;
    }

    [document logInfoMessage:@"[RootkitDetector] Starting comprehensive rootkit detection..."];

    NSMutableString *report = [NSMutableString string];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                  ROOTKIT DETECTION ANALYSIS\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    NSUInteger totalDetections = 0;

    // Phase 1: Kernel Extension Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 1: Analyzing kernel extension APIs..."];
    NSDictionary *kextResults = [self detectKernelExtensions:file document:document];
    NSUInteger kextCount = [self addKextResultsToReport:report results:kextResults];
    totalDetections += kextCount;

    // Phase 2: System Call Hooking Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 2: Analyzing syscall hooking patterns..."];
    NSDictionary *syscallResults = [self detectSyscallHooking:file document:document];
    NSUInteger syscallCount = [self addSyscallResultsToReport:report results:syscallResults];
    totalDetections += syscallCount;

    // Phase 3: Function Hooking Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 3: Analyzing function hooking techniques..."];
    NSDictionary *hookResults = [self detectFunctionHooking:file document:document];
    NSUInteger hookCount = [self addHookResultsToReport:report results:hookResults];
    totalDetections += hookCount;

    // Phase 4: Kernel Memory Manipulation Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 4: Analyzing kernel memory manipulation..."];
    NSDictionary *memoryResults = [self detectKernelMemory:file document:document];
    NSUInteger memoryCount = [self addMemoryResultsToReport:report results:memoryResults];
    totalDetections += memoryCount;

    // Phase 5: Process Hiding Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 5: Analyzing process hiding techniques..."];
    NSDictionary *hideResults = [self detectProcessHiding:file document:document];
    NSUInteger hideCount = [self addHideResultsToReport:report results:hideResults];
    totalDetections += hideCount;

    // Phase 6: Privilege Escalation Detection
    [document logInfoMessage:@"[RootkitDetector] Phase 6: Analyzing privilege escalation..."];
    NSDictionary *privescResults = [self detectPrivilegeEscalation:file document:document];
    NSUInteger privescCount = [self addPrivescResultsToReport:report results:privescResults];
    totalDetections += privescCount;

    // Summary
    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                         SUMMARY\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Rootkit Indicators: %lu\n\n", (unsigned long)totalDetections];

    if (totalDetections > 0) {
        [report appendString:@"⚠️  ROOTKIT TECHNIQUES DETECTED\n\n"];
        [report appendString:@"Security Recommendations:\n"];
        [report appendString:@"1. Kernel Integrity: Check loaded kernel extensions with kextstat\n"];
        [report appendString:@"2. System Protection: Enable System Integrity Protection (SIP)\n"];
        [report appendString:@"3. Memory Analysis: Perform kernel memory dump and analysis\n"];
        [report appendString:@"4. Process Monitoring: Use kernel-level process monitoring tools\n"];
        [report appendString:@"5. Integrity Verification: Validate system call table integrity\n"];
        [report appendString:@"6. Behavioral Analysis: Monitor for process hiding and privilege escalation\n"];
        [report appendString:@"7. Sandbox Testing: Execute in isolated environment with kernel debugging\n"];
        [report appendString:@"8. Forensics: Capture memory snapshot before system reboot\n"];
    } else {
        [report appendString:@"✓ No obvious rootkit techniques detected\n"];
        [report appendString:@"Note: Advanced rootkits may use obfuscation or novel techniques\n"];
    }

    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];

    // Save report to file
    NSString *reportPath = [NSString stringWithFormat:@"/tmp/rootkit_analysis_%@.txt",
                           [[NSDate date] descriptionWithLocale:nil]];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@":" withString:@"-"];

    NSError *error = nil;
    [report writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (!error) {
        [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Report saved to: %@", reportPath]];
    }

    // Display summary in console
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[RootkitDetector] Analysis Complete"];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Total Indicators: %lu", (unsigned long)totalDetections]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Kernel Extensions: %lu", (unsigned long)kextCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Syscall Hooking: %lu", (unsigned long)syscallCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Function Hooking: %lu", (unsigned long)hookCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Kernel Memory: %lu", (unsigned long)memoryCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Process Hiding: %lu", (unsigned long)hideCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Privilege Escalation: %lu", (unsigned long)privescCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[RootkitDetector] Report saved to: %@", reportPath]];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
}

#pragma mark - Phase 1: Kernel Extension Detection

- (NSDictionary *)detectKernelExtensions:(NSObject<HPDisassembledFile> *)file
                                document:(NSObject<HPDocument> *)document {
    NSMutableArray *kextAPIs = [NSMutableArray array];
    NSMutableArray *iokitAPIs = [NSMutableArray array];
    NSMutableArray *kernelAPIs = [NSMutableArray array];
    NSMutableArray *kextPaths = [NSMutableArray array];

    // Kext loading APIs (12 patterns)
    NSArray *kextPatterns = @[
        @"kextload", @"kextunload", @"kextstat",
        @"KextManagerLoadKextWithIdentifier",
        @"KextManagerLoadKextWithURL",
        @"OSKextLoadKextWithIdentifier",
        @"OSKextCopyLoadedKextInfo",
        @"kmod_load", @"kmod_unload", @"kmod_control",
        @"KXKextManagerLoadKext",
        @"kernel_extension"
    ];

    // IOKit kernel APIs (25 patterns)
    NSArray *iokitPatterns = @[
        @"IOServiceMatching", @"IOServiceGetMatchingServices",
        @"IOServiceOpen", @"IOServiceClose",
        @"IOConnectCallMethod", @"IOConnectCallScalarMethod",
        @"IOConnectCallStructMethod", @"IOConnectCallAsyncMethod",
        @"IOConnectMapMemory", @"IOConnectUnmapMemory",
        @"IORegistryEntryCreateCFProperty",
        @"IORegistryEntryGetName",
        @"IOIteratorNext",
        @"IOObjectRelease", @"IOObjectRetain",
        @"IOServiceAddInterestNotification",
        @"IOServiceAddMatchingNotification",
        @"IOKitWaitQuiet",
        @"IOMasterPort", @"kIOMasterPortDefault",
        @"IOReturn", @"kern_return_t",
        @"io_connect_t", @"io_service_t", @"io_iterator_t"
    ];

    // Kernel-level APIs (20 patterns)
    NSArray *kernelPatterns = @[
        @"kernel_task", @"kernel", @"_kernel",
        @"mach_kernel",
        @"kern_", @"KERN_",
        @"sysctl_", @"sysctlbyname",
        @"host_get_", @"host_info",
        @"processor_set_", @"processor_info",
        @"task_threads", @"thread_info",
        @"vm_region", @"vm_read", @"vm_write",
        @"mach_vm_", @"mach_port_",
        @"bootstrap_look_up", @"bootstrap_register"
    ];

    // Kext paths (10 patterns)
    NSArray *pathPatterns = @[
        @"/System/Library/Extensions", @".kext",
        @"/Library/Extensions",
        @"IOKit.framework", @"Kernel.framework",
        @"com.apple.kext", @"com.apple.driver",
        @"kernel.development",
        @"/System/Library/Kernels",
        @"kernelcache"
    ];

    [self scanStringsForPatterns:kextPatterns inFile:file results:kextAPIs maxResults:100];
    [self scanStringsForPatterns:iokitPatterns inFile:file results:iokitAPIs maxResults:100];
    [self scanStringsForPatterns:kernelPatterns inFile:file results:kernelAPIs maxResults:100];
    [self scanStringsForPatterns:pathPatterns inFile:file results:kextPaths maxResults:100];

    return @{
        @"kext": [kextAPIs copy],
        @"iokit": [iokitAPIs copy],
        @"kernel": [kernelAPIs copy],
        @"paths": [kextPaths copy]
    };
}

- (NSUInteger)addKextResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 1: KERNEL EXTENSION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *kextAPIs = results[@"kext"];
    NSArray *iokitAPIs = results[@"iokit"];
    NSArray *kernelAPIs = results[@"kernel"];
    NSArray *kextPaths = results[@"paths"];

    [report appendFormat:@"Kext Loading APIs: %lu\n", (unsigned long)kextAPIs.count];
    if (kextAPIs.count > 0) {
        [report appendString:@"  Kernel extension loading detected - rootkit may install kext\n"];
        for (NSDictionary *match in [kextAPIs subarrayWithRange:NSMakeRange(0, MIN(5, kextAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (kextAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(kextAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += kextAPIs.count;

    [report appendFormat:@"IOKit Kernel APIs: %lu\n", (unsigned long)iokitAPIs.count];
    if (iokitAPIs.count > 0) {
        [report appendString:@"  IOKit operations detected - kernel driver communication\n"];
        for (NSDictionary *match in [iokitAPIs subarrayWithRange:NSMakeRange(0, MIN(5, iokitAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (iokitAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(iokitAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += iokitAPIs.count;

    [report appendFormat:@"Kernel-Level APIs: %lu\n", (unsigned long)kernelAPIs.count];
    if (kernelAPIs.count > 0) {
        [report appendString:@"  Kernel task operations detected - direct kernel interaction\n"];
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

    [report appendFormat:@"Kext Paths: %lu\n", (unsigned long)kextPaths.count];
    if (kextPaths.count > 0) {
        [report appendString:@"  Kext path references detected\n"];
        for (NSDictionary *match in [kextPaths subarrayWithRange:NSMakeRange(0, MIN(3, kextPaths.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (kextPaths.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(kextPaths.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += kextPaths.count;

    if (total == 0) {
        [report appendString:@"✓ No kernel extension operations detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 2: System Call Hooking Detection

- (NSDictionary *)detectSyscallHooking:(NSObject<HPDisassembledFile> *)file
                              document:(NSObject<HPDocument> *)document {
    NSMutableArray *syscallAPIs = [NSMutableArray array];
    NSMutableArray *tableAPIs = [NSMutableArray array];
    NSMutableArray *hookAPIs = [NSMutableArray array];

    // System call APIs (15 patterns)
    NSArray *syscallPatterns = @[
        @"syscall", @"__syscall",
        @"sysent", @"nsysent",
        @"syscall_table", @"sysent_table",
        @"sys_call_table",
        @"SYS_", @"__NR_",
        @"syscall_num", @"syscall_number",
        @"_syscall", @"do_syscall",
        @"sysctlbyname", @"sysctl"
    ];

    // Table manipulation (12 patterns)
    NSArray *tablePatterns = @[
        @"sysent", @"sy_call", @"sy_narg",
        @"nsysent", @"syscall_count",
        @"write_cr0", @"read_cr0",
        @"wp_disable", @"wp_enable",
        @"kernel_map", @"kernel_pmap",
        @"pmap_protect", @"vm_protect"
    ];

    // Hooking indicators (18 patterns)
    NSArray *hookPatterns = @[
        @"hook", @"Hook", @"HOOK",
        @"orig_", @"original_",
        @"hooked_", @"_hooked",
        @"trampoline", @"Trampoline",
        @"detour", @"Detour",
        @"redirect", @"Redirect",
        @"hijack", @"Hijack",
        @"intercept", @"Intercept",
        @"patch", @"Patch"
    ];

    [self scanStringsForPatterns:syscallPatterns inFile:file results:syscallAPIs maxResults:100];
    [self scanStringsForPatterns:tablePatterns inFile:file results:tableAPIs maxResults:100];
    [self scanStringsForPatterns:hookPatterns inFile:file results:hookAPIs maxResults:100];

    return @{
        @"syscall": [syscallAPIs copy],
        @"table": [tableAPIs copy],
        @"hook": [hookAPIs copy]
    };
}

- (NSUInteger)addSyscallResultsToReport:(NSMutableString *)report
                                results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 2: SYSTEM CALL HOOKING DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *syscallAPIs = results[@"syscall"];
    NSArray *tableAPIs = results[@"table"];
    NSArray *hookAPIs = results[@"hook"];

    [report appendFormat:@"System Call APIs: %lu\n", (unsigned long)syscallAPIs.count];
    if (syscallAPIs.count > 0) {
        [report appendString:@"  System call operations detected\n"];
        for (NSDictionary *match in [syscallAPIs subarrayWithRange:NSMakeRange(0, MIN(5, syscallAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (syscallAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(syscallAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += syscallAPIs.count;

    [report appendFormat:@"Table Manipulation: %lu\n", (unsigned long)tableAPIs.count];
    if (tableAPIs.count > 0) {
        [report appendString:@"  ⚠️  Syscall table manipulation detected - classic rootkit technique\n"];
        for (NSDictionary *match in [tableAPIs subarrayWithRange:NSMakeRange(0, MIN(5, tableAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (tableAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(tableAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += tableAPIs.count;

    [report appendFormat:@"Hooking Indicators: %lu\n", (unsigned long)hookAPIs.count];
    if (hookAPIs.count > 0) {
        [report appendString:@"  ⚠️  Hook/intercept patterns detected\n"];
        for (NSDictionary *match in [hookAPIs subarrayWithRange:NSMakeRange(0, MIN(5, hookAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (hookAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(hookAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += hookAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No syscall hooking detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 3: Function Hooking Detection

- (NSDictionary *)detectFunctionHooking:(NSObject<HPDisassembledFile> *)file
                               document:(NSObject<HPDocument> *)document {
    NSMutableArray *swizzleAPIs = [NSMutableArray array];
    NSMutableArray *interposeAPIs = [NSMutableArray array];
    NSMutableArray *inlineHooks = [NSMutableArray array];
    NSMutableArray *dynamicAPIs = [NSMutableArray array];

    // Method swizzling (Objective-C) (15 patterns)
    NSArray *swizzlePatterns = @[
        @"method_exchangeImplementations",
        @"method_setImplementation",
        @"class_replaceMethod",
        @"method_getImplementation",
        @"class_getInstanceMethod",
        @"class_getClassMethod",
        @"swizzle", @"Swizzle", @"SWIZZLE",
        @"method_exchange",
        @"IMP", @"Method",
        @"objc_msgSend",
        @"_objc_msgForward",
        @"objc_setHook_getClass"
    ];

    // DYLD interposing (12 patterns)
    NSArray *interposePatterns = @[
        @"DYLD_INTERPOSE", @"__interpose",
        @"__DATA,__interpose",
        @"dyld_interpose",
        @"interpose_", @"_interpose",
        @"DYLD_INSERT_LIBRARIES",
        @"dyld_", @"_dyld_",
        @"rebind", @"rebinding",
        @"fishhook"
    ];

    // Inline hooking (15 patterns)
    NSArray *inlinePatterns = @[
        @"inline_hook", @"InlineHook",
        @"jmp", @"JMP",
        @"patch_function", @"function_patch",
        @"trampoline", @"Trampoline",
        @"detour", @"Detour",
        @"mprotect", @"vm_protect",
        @"mach_vm_protect",
        @"hook_function",
        @"substitute"
    ];

    // Dynamic resolution (10 patterns)
    NSArray *dynamicPatterns = @[
        @"dlsym", @"dlopen", @"dlclose",
        @"NSClassFromString",
        @"NSSelectorFromString",
        @"class_getMethodImplementation",
        @"objc_getClass",
        @"objc_lookUpClass",
        @"CFBundleGetFunctionPointerForName",
        @"NSGetSelectorName"
    ];

    [self scanStringsForPatterns:swizzlePatterns inFile:file results:swizzleAPIs maxResults:100];
    [self scanStringsForPatterns:interposePatterns inFile:file results:interposeAPIs maxResults:100];
    [self scanStringsForPatterns:inlinePatterns inFile:file results:inlineHooks maxResults:100];
    [self scanStringsForPatterns:dynamicPatterns inFile:file results:dynamicAPIs maxResults:100];

    return @{
        @"swizzle": [swizzleAPIs copy],
        @"interpose": [interposeAPIs copy],
        @"inline": [inlineHooks copy],
        @"dynamic": [dynamicAPIs copy]
    };
}

- (NSUInteger)addHookResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 3: FUNCTION HOOKING DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *swizzleAPIs = results[@"swizzle"];
    NSArray *interposeAPIs = results[@"interpose"];
    NSArray *inlineHooks = results[@"inline"];
    NSArray *dynamicAPIs = results[@"dynamic"];

    [report appendFormat:@"Method Swizzling (ObjC): %lu\n", (unsigned long)swizzleAPIs.count];
    if (swizzleAPIs.count > 0) {
        [report appendString:@"  Objective-C method swizzling detected\n"];
        for (NSDictionary *match in [swizzleAPIs subarrayWithRange:NSMakeRange(0, MIN(5, swizzleAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (swizzleAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(swizzleAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += swizzleAPIs.count;

    [report appendFormat:@"DYLD Interposing: %lu\n", (unsigned long)interposeAPIs.count];
    if (interposeAPIs.count > 0) {
        [report appendString:@"  ⚠️  DYLD interposing detected - function replacement\n"];
        for (NSDictionary *match in [interposeAPIs subarrayWithRange:NSMakeRange(0, MIN(5, interposeAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (interposeAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(interposeAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += interposeAPIs.count;

    [report appendFormat:@"Inline Hooking: %lu\n", (unsigned long)inlineHooks.count];
    if (inlineHooks.count > 0) {
        [report appendString:@"  ⚠️  Inline hook patterns detected - code patching\n"];
        for (NSDictionary *match in [inlineHooks subarrayWithRange:NSMakeRange(0, MIN(5, inlineHooks.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (inlineHooks.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(inlineHooks.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += inlineHooks.count;

    [report appendFormat:@"Dynamic Resolution: %lu\n", (unsigned long)dynamicAPIs.count];
    if (dynamicAPIs.count > 0) {
        [report appendString:@"  Dynamic function resolution detected\n"];
        for (NSDictionary *match in [dynamicAPIs subarrayWithRange:NSMakeRange(0, MIN(3, dynamicAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (dynamicAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(dynamicAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += dynamicAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No function hooking detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 4: Kernel Memory Manipulation Detection

- (NSDictionary *)detectKernelMemory:(NSObject<HPDisassembledFile> *)file
                            document:(NSObject<HPDocument> *)document {
    NSMutableArray *memReadAPIs = [NSMutableArray array];
    NSMutableArray *memWriteAPIs = [NSMutableArray array];
    NSMutableArray *memAllocAPIs = [NSMutableArray array];
    NSMutableArray *dkomAPIs = [NSMutableArray array];

    // Memory read APIs (12 patterns)
    NSArray *readPatterns = @[
        @"vm_read", @"vm_read_overwrite",
        @"mach_vm_read", @"mach_vm_read_overwrite",
        @"vm_region", @"vm_region_64",
        @"mach_vm_region", @"mach_vm_region_recurse",
        @"task_read", @"processor_set_tasks",
        @"copyin", @"copyout"
    ];

    // Memory write APIs (15 patterns)
    NSArray *writePatterns = @[
        @"vm_write", @"mach_vm_write",
        @"vm_protect", @"mach_vm_protect",
        @"vm_copy", @"vm_remap",
        @"mach_vm_copy", @"mach_vm_remap",
        @"task_write",
        @"copyin", @"copyout",
        @"pmap_enter", @"pmap_remove",
        @"kernel_memory_allocate",
        @"kmem_alloc"
    ];

    // Memory allocation (10 patterns)
    NSArray *allocPatterns = @[
        @"kernel_memory_allocate",
        @"kmem_alloc", @"kmem_free",
        @"kalloc", @"kfree",
        @"OSMalloc", @"OSFree",
        @"IOMalloc", @"IOFree",
        @"vm_allocate"
    ];

    // DKOM (Direct Kernel Object Manipulation) (15 patterns)
    NSArray *dkomPatterns = @[
        @"proc_list", @"allproc",
        @"proc_find", @"proc_iterate",
        @"task_list", @"tasks",
        @"thread_list",
        @"kauth_cred_", @"cred_",
        @"ucred", @"pcred",
        @"vnode", @"vnop_",
        @"mount_list", @"mountlist"
    ];

    [self scanStringsForPatterns:readPatterns inFile:file results:memReadAPIs maxResults:100];
    [self scanStringsForPatterns:writePatterns inFile:file results:memWriteAPIs maxResults:100];
    [self scanStringsForPatterns:allocPatterns inFile:file results:memAllocAPIs maxResults:100];
    [self scanStringsForPatterns:dkomPatterns inFile:file results:dkomAPIs maxResults:100];

    return @{
        @"read": [memReadAPIs copy],
        @"write": [memWriteAPIs copy],
        @"alloc": [memAllocAPIs copy],
        @"dkom": [dkomAPIs copy]
    };
}

- (NSUInteger)addMemoryResultsToReport:(NSMutableString *)report
                               results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 4: KERNEL MEMORY MANIPULATION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *memReadAPIs = results[@"read"];
    NSArray *memWriteAPIs = results[@"write"];
    NSArray *memAllocAPIs = results[@"alloc"];
    NSArray *dkomAPIs = results[@"dkom"];

    [report appendFormat:@"Memory Read APIs: %lu\n", (unsigned long)memReadAPIs.count];
    if (memReadAPIs.count > 0) {
        [report appendString:@"  Kernel memory read operations detected\n"];
        for (NSDictionary *match in [memReadAPIs subarrayWithRange:NSMakeRange(0, MIN(5, memReadAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (memReadAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(memReadAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += memReadAPIs.count;

    [report appendFormat:@"Memory Write APIs: %lu\n", (unsigned long)memWriteAPIs.count];
    if (memWriteAPIs.count > 0) {
        [report appendString:@"  ⚠️  Kernel memory write operations detected - code patching\n"];
        for (NSDictionary *match in [memWriteAPIs subarrayWithRange:NSMakeRange(0, MIN(5, memWriteAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (memWriteAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(memWriteAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += memWriteAPIs.count;

    [report appendFormat:@"Memory Allocation: %lu\n", (unsigned long)memAllocAPIs.count];
    if (memAllocAPIs.count > 0) {
        [report appendString:@"  Kernel memory allocation detected\n"];
        for (NSDictionary *match in [memAllocAPIs subarrayWithRange:NSMakeRange(0, MIN(3, memAllocAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (memAllocAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(memAllocAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += memAllocAPIs.count;

    [report appendFormat:@"DKOM Indicators: %lu\n", (unsigned long)dkomAPIs.count];
    if (dkomAPIs.count > 0) {
        [report appendString:@"  ⚠️  Direct Kernel Object Manipulation detected - process/cred manipulation\n"];
        for (NSDictionary *match in [dkomAPIs subarrayWithRange:NSMakeRange(0, MIN(5, dkomAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (dkomAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(dkomAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += dkomAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No kernel memory manipulation detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 5: Process Hiding Detection

- (NSDictionary *)detectProcessHiding:(NSObject<HPDisassembledFile> *)file
                             document:(NSObject<HPDocument> *)document {
    NSMutableArray *procAPIs = [NSMutableArray array];
    NSMutableArray *hideAPIs = [NSMutableArray array];
    NSMutableArray *listAPIs = [NSMutableArray array];

    // Process APIs (15 patterns)
    NSArray *procPatterns = @[
        @"proc_list", @"allproc",
        @"proc_find", @"proc_findpid",
        @"proc_iterate", @"proc_listpids",
        @"task_for_pid", @"pid_for_task",
        @"proc_name", @"proc_pidpath",
        @"kinfo_proc",
        @"sysctl", @"KERN_PROC",
        @"proc_selfpid", @"getpid"
    ];

    // Hiding indicators (12 patterns)
    NSArray *hidePatterns = @[
        @"hide", @"Hide", @"HIDE",
        @"hidden", @"Hidden",
        @"invisible", @"Invisible",
        @"conceal", @"Conceal",
        @"stealth", @"Stealth",
        @"unlink_proc", @"remove_proc"
    ];

    // List manipulation (10 patterns)
    NSArray *listPatterns = @[
        @"LIST_REMOVE", @"LIST_INSERT",
        @"TAILQ_REMOVE", @"TAILQ_INSERT",
        @"next", @"prev",
        @"p_list", @"p_hash",
        @"le_next", @"le_prev"
    ];

    [self scanStringsForPatterns:procPatterns inFile:file results:procAPIs maxResults:100];
    [self scanStringsForPatterns:hidePatterns inFile:file results:hideAPIs maxResults:100];
    [self scanStringsForPatterns:listPatterns inFile:file results:listAPIs maxResults:100];

    return @{
        @"process": [procAPIs copy],
        @"hide": [hideAPIs copy],
        @"list": [listAPIs copy]
    };
}

- (NSUInteger)addHideResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 5: PROCESS HIDING DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *procAPIs = results[@"process"];
    NSArray *hideAPIs = results[@"hide"];
    NSArray *listAPIs = results[@"list"];

    [report appendFormat:@"Process APIs: %lu\n", (unsigned long)procAPIs.count];
    if (procAPIs.count > 0) {
        [report appendString:@"  Process enumeration/manipulation detected\n"];
        for (NSDictionary *match in [procAPIs subarrayWithRange:NSMakeRange(0, MIN(5, procAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (procAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(procAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += procAPIs.count;

    [report appendFormat:@"Hiding Indicators: %lu\n", (unsigned long)hideAPIs.count];
    if (hideAPIs.count > 0) {
        [report appendString:@"  ⚠️  Process hiding patterns detected\n"];
        for (NSDictionary *match in [hideAPIs subarrayWithRange:NSMakeRange(0, MIN(5, hideAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (hideAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(hideAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += hideAPIs.count;

    [report appendFormat:@"List Manipulation: %lu\n", (unsigned long)listAPIs.count];
    if (listAPIs.count > 0) {
        [report appendString:@"  ⚠️  Linked list manipulation - process list tampering\n"];
        for (NSDictionary *match in [listAPIs subarrayWithRange:NSMakeRange(0, MIN(5, listAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (listAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(listAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += listAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No process hiding detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 6: Privilege Escalation Detection

- (NSDictionary *)detectPrivilegeEscalation:(NSObject<HPDisassembledFile> *)file
                                   document:(NSObject<HPDocument> *)document {
    NSMutableArray *credAPIs = [NSMutableArray array];
    NSMutableArray *exploitAPIs = [NSMutableArray array];
    NSMutableArray *authAPIs = [NSMutableArray array];
    NSMutableArray *taskAPIs = [NSMutableArray array];

    // Credential manipulation (18 patterns)
    NSArray *credPatterns = @[
        @"setuid", @"seteuid", @"setreuid",
        @"setgid", @"setegid", @"setregid",
        @"kauth_cred_", @"proc_ucred",
        @"cred_", @"ucred", @"pcred",
        @"posix_cred_get",
        @"chown", @"chmod",
        @"Authorization", @"AuthorizationCreate",
        @"SFAuthorization", @"SMJobBless"
    ];

    // Exploit indicators (15 patterns)
    NSArray *exploitPatterns = @[
        @"exploit", @"Exploit", @"EXPLOIT",
        @"shellcode", @"Shellcode",
        @"rop", @"ROP",
        @"payload", @"Payload",
        @"overflow", @"Overflow",
        @"spray", @"heap_spray",
        @"use_after_free",
        @"race_condition", @"TOCTOU"
    ];

    // Authorization/authentication (12 patterns)
    NSArray *authPatterns = @[
        @"AuthorizationExecuteWithPrivileges",
        @"Authorization", @"kAuthorization",
        @"SFAuthorization",
        @"admin", @"Admin", @"administrator",
        @"root", @"Root",
        @"privilege", @"Privilege",
        @"elevated"
    ];

    // Task port manipulation (12 patterns)
    NSArray *taskPatterns = @[
        @"task_for_pid", @"pid_for_task",
        @"task_get_special_port",
        @"task_set_special_port",
        @"host_get_special_port",
        @"processor_set_tasks",
        @"mach_port_allocate",
        @"mach_port_insert_right",
        @"TASK_BOOTSTRAP_PORT",
        @"HOST_PRIV_PORT",
        @"task_threads", @"thread_create"
    ];

    [self scanStringsForPatterns:credPatterns inFile:file results:credAPIs maxResults:100];
    [self scanStringsForPatterns:exploitPatterns inFile:file results:exploitAPIs maxResults:100];
    [self scanStringsForPatterns:authPatterns inFile:file results:authAPIs maxResults:100];
    [self scanStringsForPatterns:taskPatterns inFile:file results:taskAPIs maxResults:100];

    return @{
        @"credentials": [credAPIs copy],
        @"exploit": [exploitAPIs copy],
        @"authorization": [authAPIs copy],
        @"task": [taskAPIs copy]
    };
}

- (NSUInteger)addPrivescResultsToReport:(NSMutableString *)report
                                results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 6: PRIVILEGE ESCALATION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *credAPIs = results[@"credentials"];
    NSArray *exploitAPIs = results[@"exploit"];
    NSArray *authAPIs = results[@"authorization"];
    NSArray *taskAPIs = results[@"task"];

    [report appendFormat:@"Credential Manipulation: %lu\n", (unsigned long)credAPIs.count];
    if (credAPIs.count > 0) {
        [report appendString:@"  ⚠️  Credential manipulation detected - privilege escalation\n"];
        for (NSDictionary *match in [credAPIs subarrayWithRange:NSMakeRange(0, MIN(5, credAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (credAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(credAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += credAPIs.count;

    [report appendFormat:@"Exploit Indicators: %lu\n", (unsigned long)exploitAPIs.count];
    if (exploitAPIs.count > 0) {
        [report appendString:@"  ⚠️  Exploit patterns detected - potential kernel exploit\n"];
        for (NSDictionary *match in [exploitAPIs subarrayWithRange:NSMakeRange(0, MIN(5, exploitAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (exploitAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(exploitAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += exploitAPIs.count;

    [report appendFormat:@"Authorization APIs: %lu\n", (unsigned long)authAPIs.count];
    if (authAPIs.count > 0) {
        [report appendString:@"  Authorization/privilege operations detected\n"];
        for (NSDictionary *match in [authAPIs subarrayWithRange:NSMakeRange(0, MIN(5, authAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (authAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(authAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += authAPIs.count;

    [report appendFormat:@"Task Port Manipulation: %lu\n", (unsigned long)taskAPIs.count];
    if (taskAPIs.count > 0) {
        [report appendString:@"  ⚠️  Task port operations detected - privilege escalation vector\n"];
        for (NSDictionary *match in [taskAPIs subarrayWithRange:NSMakeRange(0, MIN(5, taskAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (taskAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(taskAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += taskAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No privilege escalation detected\n\n"];
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
