/*
 RootkitDetector.h
 Rootkit Detection Plugin for Hopper Disassembler

 Comprehensive detection of rootkit techniques including:
 - Kernel Extensions (kext loading, IOKit, kernel module manipulation)
 - System Call Hooking (syscall interception, sysent table manipulation)
 - Function Hooking (method swizzling, dylib interposing, IAT hooking)
 - Kernel Memory Manipulation (kernel memory read/write, DKOM)
 - Process Hiding (process list manipulation, PID hiding)
 - Privilege Escalation (kernel exploits, setuid, task_for_pid abuse)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Rootkit Detection Tool Plugin
 *
 * Automatically detects rootkit techniques and kernel-level malware:
 * - Kernel Extension Loading: kextload, IOKit services, kernel modules
 * - System Call Hooking: syscall table manipulation, sysent hooking
 * - Function Hooking: Method swizzling, DYLD interposing, inline hooks
 * - Kernel Memory Access: kernel memory read/write, DKOM techniques
 * - Process Hiding: Process list manipulation, PID concealment
 * - Privilege Escalation: Kernel exploits, credential manipulation
 */
@interface RootkitDetector : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic rootkit technique detection
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)detectRootkit:(nullable id)sender;

@end

#pragma clang diagnostic pop
