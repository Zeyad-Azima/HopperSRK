/*
 AntiAnalysisDetector.h
 Anti-Analysis Detection Plugin for Hopper Disassembler

 Comprehensive detection of anti-analysis techniques including:
 - Anti-debugging (ptrace, sysctl, timing checks)
 - Anti-VM/Sandbox detection (hardware checks, file checks)
 - Code integrity verification (checksumming, signature validation)
 - Environment detection (debugger tools, analysis tools)
 - Evasion techniques (string obfuscation, API resolution)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Anti-Analysis Detection Tool Plugin
 *
 * Automatically detects anti-analysis and evasion techniques:
 * - Anti-Debugging: ptrace(PT_DENY_ATTACH), sysctl checks, timing-based detection
 * - Anti-VM/Sandbox: hardware enumeration, VM artifact checks, sandbox detection
 * - Code Integrity: self-checksumming, signature validation, tamper detection
 * - Environment Detection: debugger/tool string searches, process enumeration
 * - Dynamic API Resolution: dlsym usage, runtime symbol lookup
 */
@interface AntiAnalysisDetector : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic anti-analysis technique detection
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)detectAntiAnalysis:(nullable id)sender;

@end

#pragma clang diagnostic pop
