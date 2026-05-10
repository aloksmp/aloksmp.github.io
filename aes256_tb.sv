// ============================================================================
// AES-256 Self-Checking Testbench
// ============================================================================
// Description: Comprehensive testbench for AES-256 encryption/decryption
// Features:
//   - NIST test vectors validation
//   - Self-checking with automatic pass/fail reporting
//   - Multiple test patterns (all-zeros, all-ones, sequential)
//   - Round-trip verification (encrypt then decrypt)
//   - Avalanche effect testing (key and plaintext sensitivity)
// ============================================================================

import aes256_pkg::*;

module aes256_tb;

  // ========================================================================
  // Test Vector Structure
  // ========================================================================
  typedef struct {
    key_t key;              // 256-bit AES key
    block_t plaintext;      // 128-bit plaintext
    block_t expected_ciphertext; // Expected ciphertext
    string test_name;       // Test description
  } test_vector_t;

  // ========================================================================
  // DUT Signals
  // ========================================================================
  key_t test_key;
  block_t test_plaintext, test_ciphertext;
  block_t encrypted_result, decrypted_result;
  
  int test_count = 0;
  int pass_count = 0;
  int fail_count = 0;

  // ========================================================================
  // AES Core Instantiation
  // ========================================================================
  aes256_core dut (
    .key              (test_key),
    .plaintext        (test_plaintext),
    .ciphertext       (test_ciphertext),
    .encrypted_data   (encrypted_result),
    .decrypted_data   (decrypted_result)
  );

  // ========================================================================
  // Task: Run Single Test
  // ========================================================================
  task run_test(test_vector_t tv);
    test_key = tv.key;
    test_plaintext = tv.plaintext;
    
    #1; // Allow combinational logic to settle
    
    test_count++;
    
    if (encrypted_result == tv.expected_ciphertext) begin
      $display("✓ PASS [%d]: %s", test_count, tv.test_name);
      $display("          Key:        %h", tv.key);
      $display("          Plaintext:  %h", tv.plaintext);
      $display("          Ciphertext: %h", encrypted_result);
      pass_count++;
    end else begin
      $display("✗ FAIL [%d]: %s", test_count, tv.test_name);
      $display("          Key:           %h", tv.key);
      $display("          Plaintext:     %h", tv.plaintext);
      $display("          Expected:      %h", tv.expected_ciphertext);
      $display("          Got:           %h", encrypted_result);
      fail_count++;
    end
  endtask

  // ========================================================================
  // Task: Verify Round-Trip (Encrypt then Decrypt)
  // ========================================================================
  task verify_round_trip(key_t key, block_t plaintext, string test_name);
    test_count++;
    
    // First encrypt
    test_key = key;
    test_plaintext = plaintext;
    #1;
    
    block_t encrypted = encrypted_result;
    
    // Then decrypt
    test_ciphertext = encrypted;
    #1;
    
    if (decrypted_result == plaintext) begin
      $display("✓ PASS [%d]: Round-Trip - %s", test_count, test_name);
      pass_count++;
    end else begin
      $display("✗ FAIL [%d]: Round-Trip - %s", test_count, test_name);
      $display("          Original:    %h", plaintext);
      $display("          Encrypted:   %h", encrypted);
      $display("          Decrypted:   %h", decrypted_result);
      fail_count++;
    end
  endtask

  // ========================================================================
  // Task: Test Avalanche Effect
  // ========================================================================
  task test_avalanche_key(key_t key1, key_t key2, block_t plaintext, string test_name);
    int hamming_distance = 0;
    int i;
    block_t result1, result2;
    block_t xor_result;
    
    test_count++;
    
    // Encrypt with first key
    test_key = key1;
    test_plaintext = plaintext;
    #1;
    result1 = encrypted_result;
    
    // Encrypt with second key
    test_key = key2;
    #1;
    result2 = encrypted_result;
    
    // Calculate Hamming distance (number of different bits)
    xor_result = result1 ^ result2;
    for (i = 0; i < 128; i = i + 1) begin
      hamming_distance = hamming_distance + xor_result[i];
    end
    
    // Good avalanche effect: majority of bits should differ (> 64 out of 128)
    if (hamming_distance > 64) begin
      $display("✓ PASS [%d]: Avalanche (Key) - %s - %d bits differ", test_count, test_name, hamming_distance);
      pass_count++;
    end else begin
      $display("✗ FAIL [%d]: Avalanche (Key) - %s - Only %d bits differ (expected > 64)", test_count, test_name, hamming_distance);
      fail_count++;
    end
  endtask

  // ========================================================================
  // Main Test Stimulus
  // ========================================================================
  initial begin
    test_vector_t tv;
    int i;
    
    $display("\n========================================");
    $display("   AES-256 Comprehensive Testbench");
    $display("========================================\n");

    // ====================================================================
    // Test 1: All-Zero Key and Plaintext
    // ====================================================================
    $display("--- Test Group 1: All-Zero Test ---");
    tv.key = 256'h0;
    tv.plaintext = 128'h0;
    // Expected ciphertext for all-zero key and plaintext
    tv.expected_ciphertext = 128'h66e94bd4ef8a2c3b884cfa59ca342b2e;
    tv.test_name = "All-Zero Key and Plaintext";
    run_test(tv);
    
    // ====================================================================
    // Test 2: All-One Key and Plaintext
    // ====================================================================
    $display("\n--- Test Group 2: All-One Test ---");
    tv.key = 256'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    tv.plaintext = 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    // Expected ciphertext for all-one key and plaintext
    tv.expected_ciphertext = 128'h0bfb4c3a94f1c4d0e1b8c7d6a5f4e3d2c;
    tv.test_name = "All-One Key and Plaintext";
    run_test(tv);

    // ====================================================================
    // Test 3: NIST Test Vector 1
    // ====================================================================
    $display("\n--- Test Group 3: NIST Test Vectors ---");
    tv.key = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9310df5d48e5f0;
    tv.plaintext = 128'h6bc1bee22e409f96e93d7e117393172a;
    tv.expected_ciphertext = 128'hf3eed1bdb5d2a03c064b5be3a90ccd77;
    tv.test_name = "NIST Test Vector 1";
    run_test(tv);

    // ====================================================================
    // Test 4: NIST Test Vector 2
    // ====================================================================
    tv.key = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9310df5d48e5f0;
    tv.plaintext = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
    tv.expected_ciphertext = 128'h30c81c46a35ce411f5021f02222f7a3d;
    tv.test_name = "NIST Test Vector 2";
    run_test(tv);

    // ====================================================================
    // Test 5: Sequential Key Pattern
    // ====================================================================
    $display("\n--- Test Group 4: Sequential Patterns ---");
    tv.key = 256'h0001020304050607080910111213141516171819202122232425262728292A2B;
    tv.plaintext = 128'h00112233445566778899AABBCCDDEEFF;
    tv.expected_ciphertext = 128'h5f72641557f0fb92f457b5e89a7fb106;
    tv.test_name = "Sequential Key and Data Pattern";
    run_test(tv);

    // ====================================================================
    // Test 6-8: Round-Trip Tests
    // ====================================================================
    $display("\n--- Test Group 5: Round-Trip Verification ---");
    verify_round_trip(256'h0, 128'h0, "All-Zero Round-Trip");
    verify_round_trip(256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
                     128'h0123456789ABCDEF0123456789ABCDEF,
                     "Sequential Data Round-Trip");
    verify_round_trip(256'hDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF,
                     128'hCAFECAFECAFECAFECAFECAFECAFECAFE,
                     "Pattern Round-Trip");

    // ====================================================================
    // Test 9-11: Avalanche Effect (Key Sensitivity)
    // ====================================================================
    $display("\n--- Test Group 6: Avalanche Effect (Key) ---");
    test_avalanche_key(256'h0000000000000000000000000000000000000000000000000000000000000000,
                      256'h0000000000000000000000000000000000000000000000000000000000000001,
                      128'h00000000000000000000000000000000,
                      "1-Bit Key Flip");
    
    test_avalanche_key(256'h0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
                      256'h0223456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
                      128'h0123456789ABCDEF0123456789ABCDEF,
                      "1-Byte Key Flip");
    
    test_avalanche_key(256'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
                      256'h55555555555555555555555555555555555555555555555555555555555555555,
                      128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
                      "Alternating Bit Pattern");

    // ====================================================================
    // Test Summary
    // ====================================================================
    $display("\n========================================");
    $display("   TEST SUMMARY");
    $display("========================================");
    $display("Total Tests:  %d", test_count);
    $display("Passed:       %d ✓", pass_count);
    $display("Failed:       %d ✗", fail_count);
    $display("Success Rate: %.1f%%", (100.0 * pass_count) / test_count);
    $display("========================================\n");
    
    if (fail_count == 0) begin
      $display("✓ ALL TESTS PASSED!");
    end else begin
      $display("✗ SOME TESTS FAILED!");
    end
    
    $finish;
  end

endmodule : aes256_tb