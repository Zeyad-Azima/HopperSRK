/*
 ProcessInjectionAnalyzer.h
 Process & Code Injection Analyzer Plugin for Hopper Disassembler

 Comprehensive process and code injection detection including:
 - Process creation (C: fork/exec*, Objective-C: NSTask, Swift: Process)
 - Dynamic library loading (C: dlopen, Objective-C: NSBundle, Swift: Bundle)
 - Mach-based injection (task_for_pid, mach_port, vm_* operations)
 - Process manipulation (ptrace, anti-debugging)
 - Privilege escalation patterns

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Process & Code Injection Analyzer Tool Plugin
 *
 * Automatically performs comprehensive process and code injection analysis:
 * - C Process APIs (fork, vfork, exec*, posix_spawn, system, popen)
 * - Objective-C Process APIs (NSTask, NSProcessInfo)
 * - Swift Process APIs (Process, ProcessInfo)
 * - C Dynamic Loading (dlopen, dlsym, dyld_*)
 * - Objective-C/Swift Loading (NSBundle, Bundle, CFBundle)
 * - Mach injection vectors (task_for_pid, thread_create, vm_*)
 * - Ptrace and debugging operations
 * - Privilege escalation (setuid, Authorization*, SMJobBless)
 */
@interface ProcessInjectionAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic process and code injection analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeProcessInjection:(nullable id)sender;

@end

#pragma clang diagnostic pop
