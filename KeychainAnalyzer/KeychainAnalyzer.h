/*
 KeychainAnalyzer.h
 Keychain & Credential Security Analyzer Plugin for Hopper Disassembler

 Comprehensive keychain and credential operation detection including:
 - Keychain operations (SecItem* APIs)
 - CommonCrypto and cryptographic operations
 - LocalAuthentication (TouchID/FaceID)
 - Password and credential string extraction
 - Certificate and identity management
 - Secure enclave operations

 Copyright (c) 2025 Zeyad Azima. All rights reserved.
 */

@import Foundation;
#import <Hopper/Hopper.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedClassInspection"

/**
 * Keychain & Credential Security Analyzer Tool Plugin
 *
 * Automatically performs comprehensive keychain and credential analysis:
 * - Security.framework Keychain APIs (SecItem*, SecKeychain*)
 * - CommonCrypto operations (CCCrypt, CCHmac, CCKeyDerivation, etc.)
 * - LocalAuthentication (LAContext, biometric authentication)
 * - Password and credential string detection
 * - Certificate management (SecCertificate*, SecIdentity*)
 * - Secure Enclave operations
 * - Encryption/decryption patterns
 */
@interface KeychainAnalyzer : NSObject <HopperTool>

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;

/**
 * Performs complete automatic keychain and credential analysis
 * Runs all analyses and generates comprehensive report with console output
 */
- (void)analyzeKeychain:(nullable id)sender;

@end

#pragma clang diagnostic pop
