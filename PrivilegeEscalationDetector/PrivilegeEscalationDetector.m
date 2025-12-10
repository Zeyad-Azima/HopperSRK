/*
 PrivilegeEscalationDetector.m
 Privilege Escalation Detection Plugin for Hopper Disassembler

 Comprehensive detection of privilege escalation techniques across:
 - SUID/SGID Programs
 - Credential Manipulation
 - Kernel Exploits
 - Authorization Framework Abuse
 - Elevated Execution
 - Capabilities & Entitlements

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

#import "PrivilegeEscalationDetector.h"

@implementation PrivilegeEscalationDetector

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
    return @"com.zeyadazima.hopper.PrivilegeEscalationDetector";
}

- (NSString *)pluginUUID {
    return @"B2C3D4E5-9F0A-11EF-E567-0800200C9B22";
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"Privilege Escalation Detector";
}

- (NSString *)pluginDescription {
    return @"Comprehensive privilege escalation detection analyzing SUID/SGID, credential manipulation, kernel exploits, authorization abuse, elevated execution, and entitlement abuse";
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
    return @[@"privescdetector"];
}

- (NSArray *)toolMenuDescription {
    return @[
        @{
            HPM_TITLE: @"Privilege Escalation Detector",
            HPM_SELECTOR: NSStringFromSelector(@selector(detectPrivilegeEscalation:))
        }
    ];
}

#pragma mark - Main Analysis Entry Point

- (void)detectPrivilegeEscalation:(nullable id)sender {
    NSObject<HPDocument> *document = [self.services currentDocument];
    if (!document) {
        [self.services logMessage:@"[PrivEscDetector] No document open"];
        return;
    }

    NSObject<HPDisassembledFile> *file = document.disassembledFile;
    if (!file) {
        [self.services logMessage:@"[PrivEscDetector] No disassembled file available"];
        return;
    }

    [document logInfoMessage:@"[PrivEscDetector] Starting comprehensive privilege escalation detection..."];

    NSMutableString *report = [NSMutableString string];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"            PRIVILEGE ESCALATION DETECTION ANALYSIS\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Analysis Date: %@\n\n", [NSDate date]];

    NSUInteger totalDetections = 0;

    // Phase 1: SUID/SGID Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 1: Analyzing SUID/SGID patterns..."];
    NSDictionary *suidResults = [self detectSUIDSGID:file document:document];
    NSUInteger suidCount = [self addSUIDResultsToReport:report results:suidResults];
    totalDetections += suidCount;

    // Phase 2: Credential Manipulation Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 2: Analyzing credential manipulation..."];
    NSDictionary *credResults = [self detectCredentialManipulation:file document:document];
    NSUInteger credCount = [self addCredResultsToReport:report results:credResults];
    totalDetections += credCount;

    // Phase 3: Kernel Exploit Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 3: Analyzing kernel exploit patterns..."];
    NSDictionary *exploitResults = [self detectKernelExploits:file document:document];
    NSUInteger exploitCount = [self addExploitResultsToReport:report results:exploitResults];
    totalDetections += exploitCount;

    // Phase 4: Authorization Framework Abuse Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 4: Analyzing authorization framework abuse..."];
    NSDictionary *authResults = [self detectAuthorizationAbuse:file document:document];
    NSUInteger authCount = [self addAuthResultsToReport:report results:authResults];
    totalDetections += authCount;

    // Phase 5: Elevated Execution Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 5: Analyzing elevated execution methods..."];
    NSDictionary *elevatedResults = [self detectElevatedExecution:file document:document];
    NSUInteger elevatedCount = [self addElevatedResultsToReport:report results:elevatedResults];
    totalDetections += elevatedCount;

    // Phase 6: Capabilities & Entitlements Detection
    [document logInfoMessage:@"[PrivEscDetector] Phase 6: Analyzing capability and entitlement abuse..."];
    NSDictionary *capResults = [self detectCapabilitiesEntitlements:file document:document];
    NSUInteger capCount = [self addCapResultsToReport:report results:capResults];
    totalDetections += capCount;

    // Summary
    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];
    [report appendString:@"                         SUMMARY\n"];
    [report appendString:@"═══════════════════════════════════════════════════════════════\n\n"];
    [report appendFormat:@"Total Privilege Escalation Indicators: %lu\n\n", (unsigned long)totalDetections];

    if (totalDetections > 0) {
        [report appendString:@"⚠️  PRIVILEGE ESCALATION TECHNIQUES DETECTED\n\n"];
        [report appendString:@"Security Recommendations:\n"];
        [report appendString:@"1. SUID/SGID: Audit setuid/setgid binaries and file permissions\n"];
        [report appendString:@"2. Credentials: Monitor credential access and modification\n"];
        [report appendString:@"3. Kernel Security: Keep kernel patched, enable kernel protections\n"];
        [report appendString:@"4. Authorization: Restrict AuthorizationExecuteWithPrivileges usage\n"];
        [report appendString:@"5. Elevated Execution: Monitor sudo usage and admin script execution\n"];
        [report appendString:@"6. Entitlements: Validate code signing and entitlement grants\n"];
        [report appendString:@"7. Sandboxing: Enable App Sandbox for third-party applications\n"];
        [report appendString:@"8. Monitoring: Deploy EDR to detect privilege escalation attempts\n"];
    } else {
        [report appendString:@"✓ No obvious privilege escalation techniques detected\n"];
        [report appendString:@"Note: Advanced techniques may use novel exploitation methods\n"];
    }

    [report appendString:@"\n═══════════════════════════════════════════════════════════════\n"];

    // Save report to file
    NSString *reportPath = [NSString stringWithFormat:@"/tmp/privesc_analysis_%@.txt",
                           [[NSDate date] descriptionWithLocale:nil]];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    reportPath = [reportPath stringByReplacingOccurrencesOfString:@":" withString:@"-"];

    NSError *error = nil;
    [report writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (!error) {
        [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Report saved to: %@", reportPath]];
    }

    // Display summary in console
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:@"[PrivEscDetector] Analysis Complete"];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Total Indicators: %lu", (unsigned long)totalDetections]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] SUID/SGID: %lu", (unsigned long)suidCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Credential Manipulation: %lu", (unsigned long)credCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Kernel Exploits: %lu", (unsigned long)exploitCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Authorization Abuse: %lu", (unsigned long)authCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Elevated Execution: %lu", (unsigned long)elevatedCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Capabilities/Entitlements: %lu", (unsigned long)capCount]];
    [document logInfoMessage:[NSString stringWithFormat:@"[PrivEscDetector] Report saved to: %@", reportPath]];
    [document logInfoMessage:@"══════════════════════════════════════════════════════"];
}

#pragma mark - Phase 1: SUID/SGID Detection

- (NSDictionary *)detectSUIDSGID:(NSObject<HPDisassembledFile> *)file
                        document:(NSObject<HPDocument> *)document {
    NSMutableArray *setuidAPIs = [NSMutableArray array];
    NSMutableArray *filePermAPIs = [NSMutableArray array];
    NSMutableArray *filePathAPIs = [NSMutableArray array];

    // Setuid/setgid APIs (18 patterns)
    NSArray *setuidPatterns = @[
        @"setuid", @"seteuid", @"setreuid", @"setresuid",
        @"setgid", @"setegid", @"setregid", @"setresgid",
        @"setgroups", @"initgroups",
        @"getuid", @"geteuid", @"getgid", @"getegid",
        @"issetugid",
        @"set_user_id", @"set_group_id",
        @"effective_user_id"
    ];

    // File permission APIs (20 patterns)
    NSArray *filePermPatterns = @[
        @"chmod", @"fchmod", @"fchmodat",
        @"chown", @"fchown", @"lchown", @"fchownat",
        @"access", @"faccessat",
        @"stat", @"fstat", @"lstat", @"fstatat",
        @"st_mode", @"S_ISUID", @"S_ISGID", @"S_ISVTX",
        @"0755", @"0777", @"04755"
    ];

    // Sensitive file paths (15 patterns)
    NSArray *filePathPatterns = @[
        @"/usr/bin/", @"/usr/sbin/",
        @"/bin/", @"/sbin/",
        @"/usr/local/bin/",
        @"/etc/sudoers", @"sudoers",
        @"/etc/pam.d", @"pam.d",
        @"/etc/authorization",
        @"authorized_keys",
        @"/Library/LaunchDaemons",
        @"/System/Library/CoreServices",
        @"setuid", @"suid"
    ];

    [self scanStringsForPatterns:setuidPatterns inFile:file results:setuidAPIs maxResults:100];
    [self scanStringsForPatterns:filePermPatterns inFile:file results:filePermAPIs maxResults:100];
    [self scanStringsForPatterns:filePathPatterns inFile:file results:filePathAPIs maxResults:100];

    return @{
        @"setuid": [setuidAPIs copy],
        @"permissions": [filePermAPIs copy],
        @"paths": [filePathAPIs copy]
    };
}

- (NSUInteger)addSUIDResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 1: SUID/SGID DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *setuidAPIs = results[@"setuid"];
    NSArray *filePermAPIs = results[@"permissions"];
    NSArray *filePathAPIs = results[@"paths"];

    [report appendFormat:@"Setuid/Setgid APIs: %lu\n", (unsigned long)setuidAPIs.count];
    if (setuidAPIs.count > 0) {
        [report appendString:@"  ⚠️  UID/GID manipulation detected - privilege changes\n"];
        for (NSDictionary *match in [setuidAPIs subarrayWithRange:NSMakeRange(0, MIN(5, setuidAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (setuidAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(setuidAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += setuidAPIs.count;

    [report appendFormat:@"File Permission APIs: %lu\n", (unsigned long)filePermAPIs.count];
    if (filePermAPIs.count > 0) {
        [report appendString:@"  File permission manipulation detected\n"];
        for (NSDictionary *match in [filePermAPIs subarrayWithRange:NSMakeRange(0, MIN(5, filePermAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (filePermAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(filePermAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += filePermAPIs.count;

    [report appendFormat:@"Sensitive File Paths: %lu\n", (unsigned long)filePathAPIs.count];
    if (filePathAPIs.count > 0) {
        [report appendString:@"  Sensitive system paths referenced\n"];
        for (NSDictionary *match in [filePathAPIs subarrayWithRange:NSMakeRange(0, MIN(5, filePathAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (filePathAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(filePathAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += filePathAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No SUID/SGID operations detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 2: Credential Manipulation Detection

- (NSDictionary *)detectCredentialManipulation:(NSObject<HPDisassembledFile> *)file
                                      document:(NSObject<HPDocument> *)document {
    NSMutableArray *credAPIs = [NSMutableArray array];
    NSMutableArray *kauthAPIs = [NSMutableArray array];
    NSMutableArray *pamAPIs = [NSMutableArray array];
    NSMutableArray *keychainAPIs = [NSMutableArray array];

    // Credential structure APIs (15 patterns)
    NSArray *credPatterns = @[
        @"ucred", @"pcred", @"xucred",
        @"cr_uid", @"cr_gid", @"cr_groups",
        @"proc_ucred", @"kauth_cred_get",
        @"posix_cred_get",
        @"cred_", @"credential",
        @"p_ucred", @"p_cred",
        @"getlogin", @"setlogin"
    ];

    // Kauth (Kernel Authorization) APIs (12 patterns)
    NSArray *kauthPatterns = @[
        @"kauth_cred_", @"kauth_authorize_",
        @"kauth_cred_get", @"kauth_cred_getuid",
        @"kauth_cred_setuid", @"kauth_cred_setgid",
        @"KAUTH_", @"kauth_scope",
        @"kauth_listener",
        @"posix_cred_get", @"posix_cred_set",
        @"chgproccnt"
    ];

    // PAM (Pluggable Authentication Modules) (15 patterns)
    NSArray *pamPatterns = @[
        @"pam_", @"PAM_",
        @"pam_authenticate", @"pam_setcred",
        @"pam_acct_mgmt", @"pam_open_session",
        @"pam_start", @"pam_end",
        @"/etc/pam.d", @"pam.d",
        @"pam_handle", @"pam_conv",
        @"pam_sm_", @"PAM_SUCCESS",
        @"libpam"
    ];

    // Keychain credential access (10 patterns)
    NSArray *keychainPatterns = @[
        @"SecKeychainFindGenericPassword",
        @"SecKeychainFindInternetPassword",
        @"SecKeychainItemCopyContent",
        @"SecItemCopyMatching",
        @"kSecClassGenericPassword",
        @"kSecClassInternetPassword",
        @"kSecReturnData",
        @"password", @"Password",
        @"credentials"
    ];

    [self scanStringsForPatterns:credPatterns inFile:file results:credAPIs maxResults:100];
    [self scanStringsForPatterns:kauthPatterns inFile:file results:kauthAPIs maxResults:100];
    [self scanStringsForPatterns:pamPatterns inFile:file results:pamAPIs maxResults:100];
    [self scanStringsForPatterns:keychainPatterns inFile:file results:keychainAPIs maxResults:100];

    return @{
        @"credentials": [credAPIs copy],
        @"kauth": [kauthAPIs copy],
        @"pam": [pamAPIs copy],
        @"keychain": [keychainAPIs copy]
    };
}

- (NSUInteger)addCredResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 2: CREDENTIAL MANIPULATION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *credAPIs = results[@"credentials"];
    NSArray *kauthAPIs = results[@"kauth"];
    NSArray *pamAPIs = results[@"pam"];
    NSArray *keychainAPIs = results[@"keychain"];

    [report appendFormat:@"Credential Structure APIs: %lu\n", (unsigned long)credAPIs.count];
    if (credAPIs.count > 0) {
        [report appendString:@"  ⚠️  Direct credential structure access detected\n"];
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

    [report appendFormat:@"Kauth APIs: %lu\n", (unsigned long)kauthAPIs.count];
    if (kauthAPIs.count > 0) {
        [report appendString:@"  ⚠️  Kernel authorization manipulation detected\n"];
        for (NSDictionary *match in [kauthAPIs subarrayWithRange:NSMakeRange(0, MIN(5, kauthAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (kauthAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(kauthAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += kauthAPIs.count;

    [report appendFormat:@"PAM APIs: %lu\n", (unsigned long)pamAPIs.count];
    if (pamAPIs.count > 0) {
        [report appendString:@"  PAM authentication operations detected\n"];
        for (NSDictionary *match in [pamAPIs subarrayWithRange:NSMakeRange(0, MIN(5, pamAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (pamAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(pamAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += pamAPIs.count;

    [report appendFormat:@"Keychain Credential Access: %lu\n", (unsigned long)keychainAPIs.count];
    if (keychainAPIs.count > 0) {
        [report appendString:@"  Keychain credential access detected\n"];
        for (NSDictionary *match in [keychainAPIs subarrayWithRange:NSMakeRange(0, MIN(3, keychainAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (keychainAPIs.count > 3) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(keychainAPIs.count - 3)];
        }
        [report appendString:@"\n"];
    }
    total += keychainAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No credential manipulation detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 3: Kernel Exploit Detection

- (NSDictionary *)detectKernelExploits:(NSObject<HPDisassembledFile> *)file
                              document:(NSObject<HPDocument> *)document {
    NSMutableArray *exploitAPIs = [NSMutableArray array];
    NSMutableArray *memCorruptAPIs = [NSMutableArray array];
    NSMutableArray *vulnerabilityAPIs = [NSMutableArray array];
    NSMutableArray *bypassAPIs = [NSMutableArray array];

    // Exploit indicators (20 patterns)
    NSArray *exploitPatterns = @[
        @"exploit", @"Exploit", @"EXPLOIT",
        @"shellcode", @"Shellcode",
        @"payload", @"Payload",
        @"rop", @"ROP", @"rop_chain",
        @"spray", @"heap_spray",
        @"jop", @"JOP",
        @"gadget", @"Gadget",
        @"pivot", @"stack_pivot",
        @"0day", @"zero_day",
        @"CVE-", @"vulnerability"
    ];

    // Memory corruption (18 patterns)
    NSArray *memCorruptPatterns = @[
        @"overflow", @"Overflow", @"buffer_overflow",
        @"underflow", @"Underflow",
        @"use_after_free", @"UAF",
        @"double_free",
        @"heap_overflow", @"stack_overflow",
        @"out_of_bounds", @"OOB",
        @"type_confusion",
        @"integer_overflow", @"int_overflow",
        @"format_string",
        @"memcpy", @"strcpy", @"strcat"
    ];

    // Vulnerability exploitation (15 patterns)
    NSArray *vulnPatterns = @[
        @"race_condition", @"TOCTOU",
        @"time_of_check",
        @"symbolic_link", @"symlink_race",
        @"uninitialized", @"uninit",
        @"null_deref", @"null_pointer",
        @"dangling_pointer",
        @"memory_leak",
        @"info_leak", @"infoleak",
        @"side_channel",
        @"spectre", @"meltdown"
    ];

    // Security bypass (12 patterns)
    NSArray *bypassPatterns = @[
        @"bypass", @"Bypass",
        @"disable_", @"_disable",
        @"ASLR", @"aslr",
        @"DEP", @"NX",
        @"SMAP", @"SMEP",
        @"kASLR", @"kaslr"
    ];

    [self scanStringsForPatterns:exploitPatterns inFile:file results:exploitAPIs maxResults:100];
    [self scanStringsForPatterns:memCorruptPatterns inFile:file results:memCorruptAPIs maxResults:100];
    [self scanStringsForPatterns:vulnPatterns inFile:file results:vulnerabilityAPIs maxResults:100];
    [self scanStringsForPatterns:bypassPatterns inFile:file results:bypassAPIs maxResults:100];

    return @{
        @"exploit": [exploitAPIs copy],
        @"corruption": [memCorruptAPIs copy],
        @"vulnerability": [vulnerabilityAPIs copy],
        @"bypass": [bypassAPIs copy]
    };
}

- (NSUInteger)addExploitResultsToReport:(NSMutableString *)report
                                results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 3: KERNEL EXPLOIT DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *exploitAPIs = results[@"exploit"];
    NSArray *memCorruptAPIs = results[@"corruption"];
    NSArray *vulnerabilityAPIs = results[@"vulnerability"];
    NSArray *bypassAPIs = results[@"bypass"];

    [report appendFormat:@"Exploit Indicators: %lu\n", (unsigned long)exploitAPIs.count];
    if (exploitAPIs.count > 0) {
        [report appendString:@"  ⚠️  Exploit patterns detected - potential kernel exploit code\n"];
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

    [report appendFormat:@"Memory Corruption: %lu\n", (unsigned long)memCorruptAPIs.count];
    if (memCorruptAPIs.count > 0) {
        [report appendString:@"  ⚠️  Memory corruption techniques detected\n"];
        for (NSDictionary *match in [memCorruptAPIs subarrayWithRange:NSMakeRange(0, MIN(5, memCorruptAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (memCorruptAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(memCorruptAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += memCorruptAPIs.count;

    [report appendFormat:@"Vulnerability Exploitation: %lu\n", (unsigned long)vulnerabilityAPIs.count];
    if (vulnerabilityAPIs.count > 0) {
        [report appendString:@"  ⚠️  Vulnerability exploitation patterns detected\n"];
        for (NSDictionary *match in [vulnerabilityAPIs subarrayWithRange:NSMakeRange(0, MIN(5, vulnerabilityAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (vulnerabilityAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(vulnerabilityAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += vulnerabilityAPIs.count;

    [report appendFormat:@"Security Bypass: %lu\n", (unsigned long)bypassAPIs.count];
    if (bypassAPIs.count > 0) {
        [report appendString:@"  ⚠️  Security mechanism bypass detected\n"];
        for (NSDictionary *match in [bypassAPIs subarrayWithRange:NSMakeRange(0, MIN(5, bypassAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (bypassAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(bypassAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += bypassAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No kernel exploit patterns detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 4: Authorization Framework Abuse Detection

- (NSDictionary *)detectAuthorizationAbuse:(NSObject<HPDisassembledFile> *)file
                                  document:(NSObject<HPDocument> *)document {
    NSMutableArray *authAPIs = [NSMutableArray array];
    NSMutableArray *smjobAPIs = [NSMutableArray array];
    NSMutableArray *securityAPIs = [NSMutableArray array];

    // Authorization Framework (20 patterns)
    NSArray *authPatterns = @[
        @"AuthorizationCreate",
        @"AuthorizationExecuteWithPrivileges",
        @"AuthorizationCopyRights",
        @"AuthorizationMakeExternalForm",
        @"AuthorizationCreateFromExternalForm",
        @"AuthorizationFree",
        @"SFAuthorization",
        @"kAuthorizationRightExecute",
        @"kAuthorizationEmptyEnvironment",
        @"Authorization", @"authorization",
        @"kAuthorization",
        @"admin_right", @"system.privilege",
        @"com.apple.security.authorization",
        @"right", @"Right",
        @"/var/db/auth.db",
        @"/etc/authorization",
        @"authorization.plist"
    ];

    // SMJobBless and privileged helper (15 patterns)
    NSArray *smjobPatterns = @[
        @"SMJobBless", @"SMJobSubmit", @"SMJobRemove",
        @"SMJobCopyDictionary",
        @"SMCopyAllJobDictionaries",
        @"PrivilegedHelperTools",
        @"com.apple.security.application-groups",
        @"privileged_helper", @"helper_tool",
        @"SMJobBlessSubmit",
        @"xpc_connection_set_privileged",
        @"Contents/Library/LaunchServices",
        @"LaunchServices", @"launch_services",
        @"bless"
    ];

    // Security Framework privilege APIs (12 patterns)
    NSArray *securityPatterns = @[
        @"SecTaskCopyValueForEntitlement",
        @"SecCodeCopySelf",
        @"SecCodeCheckValidity",
        @"SecRequirementCreateWithString",
        @"SecStaticCodeCreateWithPath",
        @"kSecGuestAttributePid",
        @"get-task-allow",
        @"task_for_pid-allow",
        @"com.apple.security.cs.debugger",
        @"admin", @"Admin",
        @"elevated"
    ];

    [self scanStringsForPatterns:authPatterns inFile:file results:authAPIs maxResults:100];
    [self scanStringsForPatterns:smjobPatterns inFile:file results:smjobAPIs maxResults:100];
    [self scanStringsForPatterns:securityPatterns inFile:file results:securityAPIs maxResults:100];

    return @{
        @"authorization": [authAPIs copy],
        @"smjob": [smjobAPIs copy],
        @"security": [securityAPIs copy]
    };
}

- (NSUInteger)addAuthResultsToReport:(NSMutableString *)report
                             results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 4: AUTHORIZATION FRAMEWORK ABUSE DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *authAPIs = results[@"authorization"];
    NSArray *smjobAPIs = results[@"smjob"];
    NSArray *securityAPIs = results[@"security"];

    [report appendFormat:@"Authorization Framework: %lu\n", (unsigned long)authAPIs.count];
    if (authAPIs.count > 0) {
        [report appendString:@"  ⚠️  Authorization framework usage detected\n"];
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

    [report appendFormat:@"SMJobBless/Privileged Helper: %lu\n", (unsigned long)smjobAPIs.count];
    if (smjobAPIs.count > 0) {
        [report appendString:@"  ⚠️  Privileged helper tool installation detected\n"];
        for (NSDictionary *match in [smjobAPIs subarrayWithRange:NSMakeRange(0, MIN(5, smjobAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (smjobAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(smjobAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += smjobAPIs.count;

    [report appendFormat:@"Security Framework: %lu\n", (unsigned long)securityAPIs.count];
    if (securityAPIs.count > 0) {
        [report appendString:@"  Security entitlement checking detected\n"];
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
        [report appendString:@"✓ No authorization framework abuse detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 5: Elevated Execution Detection

- (NSDictionary *)detectElevatedExecution:(NSObject<HPDisassembledFile> *)file
                                 document:(NSObject<HPDocument> *)document {
    NSMutableArray *sudoAPIs = [NSMutableArray array];
    NSMutableArray *scriptAPIs = [NSMutableArray array];
    NSMutableArray *launchdAPIs = [NSMutableArray array];

    // Sudo and su (15 patterns)
    NSArray *sudoPatterns = @[
        @"sudo", @"SUDO", @"/usr/bin/sudo",
        @"su", @"/bin/su",
        @"sudoers", @"/etc/sudoers",
        @"NOPASSWD", @"SETENV",
        @"visudo",
        @"doas",
        @"pkexec", @"polkit",
        @"gksu", @"kdesudo"
    ];

    // AppleScript/Shell elevated execution (20 patterns)
    NSArray *scriptPatterns = @[
        @"osascript", @"/usr/bin/osascript",
        @"AppleScript", @"do shell script",
        @"with administrator privileges",
        @"with prompt",
        @"NSAppleScript",
        @"tell application \"System Events\"",
        @"activate", @"with administrator",
        @"kAEOpenApplication",
        @"kAEQuitApplication",
        @"sh -c", @"bash -c",
        @"/bin/sh", @"/bin/bash",
        @"system(", @"popen(",
        @"exec"
    ];

    // Launchd privileged execution (12 patterns)
    NSArray *launchdPatterns = @[
        @"launchctl", @"/bin/launchctl",
        @"launchctl load",
        @"launchctl submit",
        @"launchctl bootout",
        @"launchctl bootstrap",
        @"/Library/LaunchDaemons",
        @"RunAtLoad", @"KeepAlive",
        @"SessionCreate",
        @"LaunchServices",
        @"launch_activate_socket"
    ];

    [self scanStringsForPatterns:sudoPatterns inFile:file results:sudoAPIs maxResults:100];
    [self scanStringsForPatterns:scriptPatterns inFile:file results:scriptAPIs maxResults:100];
    [self scanStringsForPatterns:launchdPatterns inFile:file results:launchdAPIs maxResults:100];

    return @{
        @"sudo": [sudoAPIs copy],
        @"script": [scriptAPIs copy],
        @"launchd": [launchdAPIs copy]
    };
}

- (NSUInteger)addElevatedResultsToReport:(NSMutableString *)report
                                 results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 5: ELEVATED EXECUTION DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *sudoAPIs = results[@"sudo"];
    NSArray *scriptAPIs = results[@"script"];
    NSArray *launchdAPIs = results[@"launchd"];

    [report appendFormat:@"Sudo/Su Execution: %lu\n", (unsigned long)sudoAPIs.count];
    if (sudoAPIs.count > 0) {
        [report appendString:@"  ⚠️  Sudo/su usage detected - privilege elevation via password\n"];
        for (NSDictionary *match in [sudoAPIs subarrayWithRange:NSMakeRange(0, MIN(5, sudoAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (sudoAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(sudoAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += sudoAPIs.count;

    [report appendFormat:@"Script Elevated Execution: %lu\n", (unsigned long)scriptAPIs.count];
    if (scriptAPIs.count > 0) {
        [report appendString:@"  ⚠️  Elevated script execution detected (AppleScript/shell)\n"];
        for (NSDictionary *match in [scriptAPIs subarrayWithRange:NSMakeRange(0, MIN(5, scriptAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (scriptAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(scriptAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += scriptAPIs.count;

    [report appendFormat:@"Launchd Privileged Execution: %lu\n", (unsigned long)launchdAPIs.count];
    if (launchdAPIs.count > 0) {
        [report appendString:@"  Launchd daemon/agent operations detected\n"];
        for (NSDictionary *match in [launchdAPIs subarrayWithRange:NSMakeRange(0, MIN(5, launchdAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (launchdAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(launchdAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += launchdAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No elevated execution detected\n\n"];
    }

    return total;
}

#pragma mark - Phase 6: Capabilities & Entitlements Detection

- (NSDictionary *)detectCapabilitiesEntitlements:(NSObject<HPDisassembledFile> *)file
                                        document:(NSObject<HPDocument> *)document {
    NSMutableArray *taskPortAPIs = [NSMutableArray array];
    NSMutableArray *entitlementAPIs = [NSMutableArray array];
    NSMutableArray *debugAPIs = [NSMutableArray array];

    // Task port APIs (18 patterns)
    NSArray *taskPortPatterns = @[
        @"task_for_pid", @"pid_for_task",
        @"task_get_special_port",
        @"task_set_special_port",
        @"task_threads", @"thread_create",
        @"TASK_BOOTSTRAP_PORT",
        @"HOST_PRIV_PORT",
        @"host_get_special_port",
        @"processor_set_tasks",
        @"mach_port_allocate",
        @"mach_port_insert_right",
        @"bootstrap_look_up",
        @"bootstrap_register",
        @"mach_task_self",
        @"current_task",
        @"kernel_task"
    ];

    // Entitlements (25 patterns)
    NSArray *entitlementPatterns = @[
        @"com.apple.security.cs.allow-jit",
        @"com.apple.security.cs.allow-unsigned-executable-memory",
        @"com.apple.security.cs.allow-dyld-environment-variables",
        @"com.apple.security.cs.disable-library-validation",
        @"com.apple.security.cs.disable-executable-page-protection",
        @"com.apple.security.get-task-allow",
        @"task_for_pid-allow",
        @"com.apple.system-task-ports",
        @"com.apple.security.cs.debugger",
        @"com.apple.private.security.clear-library-validation",
        @"com.apple.private.tcc.allow",
        @"com.apple.rootless.install",
        @"com.apple.private.kernel.get-kext-info",
        @"com.apple.private.iokit.user-access",
        @"platform-application",
        @"entitlement", @"Entitlement",
        @"SecTaskCopyValueForEntitlement",
        @"kSecGuestAttributePid",
        @"codesign", @"--entitlements",
        @".entitlements",
        @"embedded.provisionprofile",
        @"provisioning"
    ];

    // Debugging capabilities (12 patterns)
    NSArray *debugPatterns = @[
        @"ptrace", @"PT_DENY_ATTACH", @"PT_TRACE_ME",
        @"get-task-allow",
        @"debugserver", @"lldb", @"gdb",
        @"CS_DEBUGGED",
        @"debug", @"Debug", @"DEBUG",
        @"DYLD_INSERT_LIBRARIES"
    ];

    [self scanStringsForPatterns:taskPortPatterns inFile:file results:taskPortAPIs maxResults:100];
    [self scanStringsForPatterns:entitlementPatterns inFile:file results:entitlementAPIs maxResults:100];
    [self scanStringsForPatterns:debugPatterns inFile:file results:debugAPIs maxResults:100];

    return @{
        @"taskport": [taskPortAPIs copy],
        @"entitlement": [entitlementAPIs copy],
        @"debug": [debugAPIs copy]
    };
}

- (NSUInteger)addCapResultsToReport:(NSMutableString *)report
                            results:(NSDictionary *)results {
    [report appendString:@"───────────────────────────────────────────────────────────────\n"];
    [report appendString:@"Phase 6: CAPABILITIES & ENTITLEMENTS DETECTION\n"];
    [report appendString:@"───────────────────────────────────────────────────────────────\n\n"];

    NSUInteger total = 0;

    NSArray *taskPortAPIs = results[@"taskport"];
    NSArray *entitlementAPIs = results[@"entitlement"];
    NSArray *debugAPIs = results[@"debug"];

    [report appendFormat:@"Task Port APIs: %lu\n", (unsigned long)taskPortAPIs.count];
    if (taskPortAPIs.count > 0) {
        [report appendString:@"  ⚠️  Task port manipulation detected - process injection vector\n"];
        for (NSDictionary *match in [taskPortAPIs subarrayWithRange:NSMakeRange(0, MIN(5, taskPortAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (taskPortAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(taskPortAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += taskPortAPIs.count;

    [report appendFormat:@"Entitlements: %lu\n", (unsigned long)entitlementAPIs.count];
    if (entitlementAPIs.count > 0) {
        [report appendString:@"  ⚠️  Dangerous entitlements detected\n"];
        for (NSDictionary *match in [entitlementAPIs subarrayWithRange:NSMakeRange(0, MIN(5, entitlementAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (entitlementAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(entitlementAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += entitlementAPIs.count;

    [report appendFormat:@"Debugging Capabilities: %lu\n", (unsigned long)debugAPIs.count];
    if (debugAPIs.count > 0) {
        [report appendString:@"  Debugging operations detected\n"];
        for (NSDictionary *match in [debugAPIs subarrayWithRange:NSMakeRange(0, MIN(5, debugAPIs.count))]) {
            [report appendFormat:@"  • 0x%llx: %@\n",
             [match[@"address"] unsignedLongLongValue],
             match[@"string"]];
        }
        if (debugAPIs.count > 5) {
            [report appendFormat:@"  ... and %lu more\n", (unsigned long)(debugAPIs.count - 5)];
        }
        [report appendString:@"\n"];
    }
    total += debugAPIs.count;

    if (total == 0) {
        [report appendString:@"✓ No dangerous capabilities or entitlements detected\n\n"];
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
