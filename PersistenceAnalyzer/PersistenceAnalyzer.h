/*
 PersistenceAnalyzer.h
 Persistence Mechanism Analyzer Plugin for Hopper Disassembler

 Comprehensive detection of persistence mechanisms including:
 - Launch Agents/Daemons (SMJobBless, plist manipulation)
 - Login Items (LSSharedFileList, startup items)
 - Cron Jobs (crontab, at, periodic scripts)
 - Kernel Extensions (kext loading, IOKit)
 - Browser Extensions (Safari, Chrome, Firefox)
 - Dylib Injection (DYLD_INSERT_LIBRARIES, interposing)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Persistence Mechanism Analyzer Tool Plugin
 *
 * Automatically detects malware persistence techniques:
 * - Launch Agents/Daemons: SMJobBless, SMJobSubmit, plist paths
 * - Login Items: LSSharedFileList, SMLoginItemSetEnabled
 * - Cron/Scheduled Tasks: crontab, at commands, periodic scripts
 * - Kernel Extensions: IOKit, kext loading, kernel module insertion
 * - Browser Extensions: Safari/Chrome/Firefox extension paths
 * - Dylib Injection: DYLD environment variables, dylib interposing
 * - System Modification: rc.common, sudoers, periodic scripts
 */
@interface PersistenceAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic persistence mechanism detection
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzePersistence:(nullable id)sender;

@end

#pragma clang diagnostic pop
