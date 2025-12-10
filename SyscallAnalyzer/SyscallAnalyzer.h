/*
 SyscallAnalyzer.h
 System Call Analyzer Plugin for Hopper Disassembler

 Comprehensive detection of direct system call usage including:
 - BSD System Calls (read, write, open, close, fork, execve)
 - Mach Traps (mach_msg_trap, thread_self_trap, semaphore traps)
 - Syscall Instructions & Wrappers (syscall, __syscall, __mac_syscall)
 - Dangerous/Security-Critical Syscalls (ptrace, task_for_pid, kextload)
 - Syscall Number References (0x2000000+ range, syscall constants)
 - macOS-Specific Syscalls (Darwin, XNU, sandbox syscalls)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * System Call Analyzer Tool Plugin
 *
 * Automatically detects direct system call usage:
 * - BSD Syscalls: read, write, open, fork, execve, kill, etc.
 * - Mach Traps: mach_msg_trap, thread operations, semaphores
 * - Syscall Wrappers: __syscall, __mac_syscall, indirect patterns
 * - Dangerous Syscalls: ptrace, task_for_pid, vm_read, vm_write
 * - Syscall Numbers: Direct numeric references, constants
 * - Darwin/XNU: macOS-specific system calls and operations
 */
@interface SyscallAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic system call analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeSyscalls:(nullable id)sender;

@end

#pragma clang diagnostic pop
