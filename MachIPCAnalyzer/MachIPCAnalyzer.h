/*
 MachIPCAnalyzer.h
 Mach IPC Analyzer Plugin for Hopper Disassembler

 Comprehensive Mach IPC detection including:
 - MIG (Mach Interface Generator) subsystems
 - Mach port operations
 - Bootstrap service operations
 - Message handler detection
 - Subsystem structure analysis
 - Authorization pattern detection

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Mach IPC Analyzer Tool Plugin
 *
 * Automatically performs comprehensive Mach IPC analysis:
 * - MIG subsystem detection (message ID ranges, dispatcher functions)
 * - Mach port API detection (mach_port_*, mach_msg, etc.)
 * - Bootstrap service operations (bootstrap_look_up, bootstrap_check_in)
 * - Message handler and routine descriptor identification
 * - Authorization pattern analysis
 * - Service name extraction
 */
@interface MachIPCAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic Mach IPC analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeMachIPC:(nullable id)sender;

@end

#pragma clang diagnostic pop
