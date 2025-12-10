/*
 C2Analyzer.h
 Command & Control (C2) Communication Analyzer Plugin for Hopper Disassembler

 Comprehensive detection of C2 communication patterns including:
 - Network Communication (HTTP/HTTPS, DNS, raw sockets, custom protocols)
 - Domain Generation Algorithms (DGA patterns, crypto functions)
 - Encryption & Encoding (Base64, AES, RSA, custom encoding)
 - C2 Frameworks (Cobalt Strike, Metasploit, Empire, Sliver)
 - Data Exfiltration (compression, chunking, steganography)
 - Beaconing & Timing (sleep, jitter, time-based triggers)

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Command & Control (C2) Communication Analyzer Tool Plugin
 *
 * Automatically detects C2 communication patterns and techniques:
 * - Network APIs: Socket programming, URL loading, DNS queries
 * - Domain Generation: Crypto-based domain generation, hash functions
 * - Encryption: Symmetric/asymmetric encryption, encoding schemes
 * - C2 Frameworks: Cobalt Strike, Metasploit, Empire, Sliver signatures
 * - Exfiltration: Data compression, chunking, covert channels
 * - Beaconing: Sleep patterns, jitter, periodic callbacks
 */
@interface C2Analyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic C2 communication analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeC2:(nullable id)sender;

@end

#pragma clang diagnostic pop
