/*
 FileOpAnalyzer.h
 File Operations Security Analyzer Plugin for Hopper Disassembler

 Comprehensive file operation vulnerability detection including:
 - Symlink/Hardlink attack vectors
 - TOCTOU (Time-of-check-time-of-use) vulnerabilities
 - Insecure file permissions and ownership
 - Path traversal vulnerabilities
 - Temporary file security issues

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * File Operations Security Analyzer Tool Plugin
 *
 * Automatically performs comprehensive file operation security analysis:
 * - File operation API detection (POSIX, BSD, Darwin-specific)
 * - Symlink/hardlink attack vulnerability detection
 * - TOCTOU race condition identification
 * - Insecure temporary file usage patterns
 * - Path traversal vulnerability detection
 * - File permission/ownership security analysis
 * - Directory traversal and creation patterns
 * - Atomic operation verification
 */
@interface FileOpAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic file operation security analysis
 * Runs all analyses and generates comprehensive security report with console output
 */
- (void)analyzeFileOps:(nullable id)sender;

@end

#pragma clang diagnostic pop
