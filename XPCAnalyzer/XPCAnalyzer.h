/*
 XPCAnalyzer.h
 XPC Analysis Plugin for Hopper Disassembler

 Analyzes XPC services, connections, and potential vulnerabilities
 in macOS binaries.

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * XPC Analyzer Tool Plugin
 *
 * Automatically performs comprehensive XPC security analysis:
 * - XPC service detection and enumeration
 * - XPC connection establishment analysis
 * - Message handler identification
 * - Entitlement and validation checks
 * - Security vulnerability assessment
 * - Attack surface mapping
 * - Full exploitation report generation
 */
@interface XPCAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic XPC analysis
 * Runs all analyses and generates comprehensive security report
 */
- (void)analyzeXPC:(nullable id)sender;

@end

#pragma clang diagnostic pop
