/*
 PrivilegeEscalationDetector.h
 Privilege Escalation Detection Plugin for Hopper Disassembler

 Comprehensive detection of privilege escalation techniques including:
 - SUID/SGID Programs (setuid, setgid, file permission manipulation)
 - Credential Manipulation (uid/gid modification, credential theft)
 - Kernel Exploits (kernel vulnerabilities, memory corruption)
 - Authorization Framework Abuse (AuthorizationExecuteWithPrivileges, SMJobBless)
 - Elevated Execution (sudo, osascript, AppleScript)
 - Capabilities & Entitlements (task_for_pid, debugging entitlements)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Privilege Escalation Detection Tool Plugin
 *
 * Automatically detects privilege escalation techniques:
 * - SUID/SGID: setuid, setgid, chmod, file permission changes
 * - Credential Theft: kauth_cred, ucred, proc_ucred manipulation
 * - Kernel Exploits: Exploit primitives, kernel memory corruption
 * - Authorization Abuse: AuthorizationExecuteWithPrivileges, SMJobBless
 * - Elevated Execution: sudo, osascript, do shell script
 * - Entitlements: task_for_pid, get-task-allow, debugging rights
 */
@interface PrivilegeEscalationDetector : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic privilege escalation detection
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)detectPrivilegeEscalation:(nullable id)sender;

@end

#pragma clang diagnostic pop
