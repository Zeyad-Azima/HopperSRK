/*
 NetworkAnalyzer.h
 Network Operations Analyzer Plugin for Hopper Disassembler

 Comprehensive network operation detection including:
 - Socket operations (C API)
 - URL operations (Objective-C, Swift)
 - Network framework usage
 - Protocol detection (HTTP/HTTPS, WebSocket, TCP/UDP)
 - TLS/SSL operations
 - URL and IP address extraction

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Network Operations Analyzer Tool Plugin
 *
 * Automatically performs comprehensive network operation analysis:
 * - C socket API detection (socket, connect, bind, send, recv, etc.)
 * - Objective-C network APIs (NSURLSession, NSURLConnection, CFNetwork)
 * - Swift network APIs (URLSession, Network.framework)
 * - TLS/SSL detection (SecureTransport, OpenSSL)
 * - URL and IP address extraction from strings
 * - Protocol detection and analysis
 */
@interface NetworkAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic network operation analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeNetwork:(nullable id)sender;

@end

#pragma clang diagnostic pop
