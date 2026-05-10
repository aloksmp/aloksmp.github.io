// ============================================================================
// AES-256 Core Encryption/Decryption Engine
// ============================================================================
// Description: Fully unrolled combinational AES-256 core supporting both
//              encryption and decryption with 14 rounds and 256-bit key
// Features: 
//   - Combinational logic (no pipelining needed)
//   - Simultaneous encryption and decryption paths
//   - Key schedule expansion (256-bit to 240-byte expanded key)
// ============================================================================

import aes256_pkg::*;

module aes256_core (
  input  key_t          key,              // 256-bit AES key
  input  block_t        plaintext,        // 128-bit plaintext block
  input  block_t        ciphertext,       // 128-bit ciphertext block
  output block_t        encrypted_data,   // 128-bit encrypted output
  output block_t        decrypted_data    // 128-bit decrypted output
);

  // ========================================================================
  // Internal Signal Declarations
  // ========================================================================
  sched_t expanded_key;                   // 60 words of expanded key (240 bytes)
  state_t state_enc [NR+1];               // State matrix for each encryption round
  state_t state_dec [NR+1];               // State matrix for each decryption round
  byte_t temp_byte;
  int i, j, k;

  // ========================================================================
  // KEY SCHEDULE EXPANSION
  // Purpose: Expands 256-bit master key into 60 words (4 words per round)
  // Algorithm: Uses RotWord, SubWord, and Rcon values
  // ========================================================================
  
  // Convert 256-bit key to initial 8 words
  always_comb begin
    // Extract first 8 words (32-bit each) from 256-bit key
    expanded_key[0] = key[255:224];
    expanded_key[1] = key[223:192];
    expanded_key[2] = key[191:160];
    expanded_key[3] = key[159:128];
    expanded_key[4] = key[127:96];
    expanded_key[5] = key[95:64];
    expanded_key[6] = key[63:32];
    expanded_key[7] = key[31:0];

    // Expand remaining 52 words (for rounds 1-13, 4 words per round)
    for (i = 8; i < 60; i = i + 1) begin
      word_t temp = expanded_key[i-1];
      
      // Every 8th word (i.e., every Nk words): apply RotWord + SubWord + Rcon
      if (i % 8 == 0) begin
        // RotWord: Rotate word [a0, a1, a2, a3] -> [a1, a2, a3, a0]
        temp = {temp[23:0], temp[31:24]};
        
        // SubWord: Apply S-box to each byte
        temp = {SBOX[temp[31:24]], SBOX[temp[23:16]], SBOX[temp[15:8]], SBOX[temp[7:0]]};
        
        // XOR with Rcon (round constant) in first byte
        temp = temp ^ {RCON[i/8 - 1], 24'h0};
      end
      // Every 4th word in 256-bit key schedule: apply SubWord only
      else if (i % 8 == 4) begin
        temp = {SBOX[temp[31:24]], SBOX[temp[23:16]], SBOX[temp[15:8]], SBOX[temp[7:0]]};
      end
      
      expanded_key[i] = expanded_key[i-8] ^ temp;
    end
  end

  // ========================================================================
  // ENCRYPTION PATH - Unrolled 14 Rounds
  // ========================================================================
  
  always_comb begin
    // ====================================================================
    // Initial Round: AddRoundKey with round key 0
    // ====================================================================
    for (i = 0; i < 4; i = i + 1) begin
      for (j = 0; j < 4; j = j + 1) begin
        // Extract plaintext bytes and XOR with key schedule
        state_enc[0][i][j] = plaintext[127 - (i*4+j)*8 -: 8] ^ 
                             expanded_key[i][31 - j*8 -: 8];
      end
    end

    // ====================================================================
    // Main Rounds 1-13: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    // ====================================================================
    for (int round = 1; round < NR; round = round + 1) begin
      // --- SubBytes: Apply S-box to all 16 bytes in state ---
      state_t sub_bytes_out;
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          sub_bytes_out[i][j] = SBOX[state_enc[round-1][i][j]];
        end
      end

      // --- ShiftRows: Rotate rows in state matrix ---
      // Row 0: No rotation [a0, a4, a8, a12]
      // Row 1: Rotate left by 1 [a5, a9, a13, a1]
      // Row 2: Rotate left by 2 [a10, a14, a2, a6]
      // Row 3: Rotate left by 3 [a15, a3, a7, a11]
      state_t shift_rows_out;
      shift_rows_out[0][0] = sub_bytes_out[0][0];
      shift_rows_out[0][1] = sub_bytes_out[1][1];
      shift_rows_out[0][2] = sub_bytes_out[2][2];
      shift_rows_out[0][3] = sub_bytes_out[3][3];
      
      shift_rows_out[1][0] = sub_bytes_out[1][1];
      shift_rows_out[1][1] = sub_bytes_out[2][2];
      shift_rows_out[1][2] = sub_bytes_out[3][3];
      shift_rows_out[1][3] = sub_bytes_out[0][0];
      
      shift_rows_out[2][0] = sub_bytes_out[2][2];
      shift_rows_out[2][1] = sub_bytes_out[3][3];
      shift_rows_out[2][2] = sub_bytes_out[0][0];
      shift_rows_out[2][3] = sub_bytes_out[1][1];
      
      shift_rows_out[3][0] = sub_bytes_out[3][3];
      shift_rows_out[3][1] = sub_bytes_out[0][0];
      shift_rows_out[3][2] = sub_bytes_out[1][1];
      shift_rows_out[3][3] = sub_bytes_out[2][2];

      // --- MixColumns: Multiply each column by fixed polynomial in GF(2^8) ---
      // Each column [s0, s1, s2, s3] is multiplied by:
      // [02 03 01 01] * [s0]   =  [2*s0 + 3*s1 + s2 + s3]
      // [01 02 03 01]   [s1]      [s0 + 2*s1 + 3*s2 + s3]
      // [01 01 02 03]   [s2]      [s0 + s1 + 2*s2 + 3*s3]
      // [03 01 01 02]   [s3]      [3*s0 + s1 + s2 + 2*s3]
      state_t mix_cols_out;
      for (j = 0; j < 4; j = j + 1) begin
        byte_t s0 = shift_rows_out[0][j];
        byte_t s1 = shift_rows_out[1][j];
        byte_t s2 = shift_rows_out[2][j];
        byte_t s3 = shift_rows_out[3][j];
        
        mix_cols_out[0][j] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
        mix_cols_out[1][j] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
        mix_cols_out[2][j] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
        mix_cols_out[3][j] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
      end

      // --- AddRoundKey: XOR state with round key ---
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          state_enc[round][i][j] = mix_cols_out[i][j] ^ 
                                   expanded_key[round*4 + i][31 - j*8 -: 8];
        end
      end
    end

    // ====================================================================
    // Final Round 14: SubBytes -> ShiftRows -> AddRoundKey (No MixColumns)
    // ====================================================================
    begin
      // SubBytes
      state_t sub_bytes_final;
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          sub_bytes_final[i][j] = SBOX[state_enc[NR-1][i][j]];
        end
      end

      // ShiftRows
      state_t shift_rows_final;
      shift_rows_final[0][0] = sub_bytes_final[0][0];
      shift_rows_final[0][1] = sub_bytes_final[1][1];
      shift_rows_final[0][2] = sub_bytes_final[2][2];
      shift_rows_final[0][3] = sub_bytes_final[3][3];
      
      shift_rows_final[1][0] = sub_bytes_final[1][1];
      shift_rows_final[1][1] = sub_bytes_final[2][2];
      shift_rows_final[1][2] = sub_bytes_final[3][3];
      shift_rows_final[1][3] = sub_bytes_final[0][0];
      
      shift_rows_final[2][0] = sub_bytes_final[2][2];
      shift_rows_final[2][1] = sub_bytes_final[3][3];
      shift_rows_final[2][2] = sub_bytes_final[0][0];
      shift_rows_final[2][3] = sub_bytes_final[1][1];
      
      shift_rows_final[3][0] = sub_bytes_final[3][3];
      shift_rows_final[3][1] = sub_bytes_final[0][0];
      shift_rows_final[3][2] = sub_bytes_final[1][1];
      shift_rows_final[3][3] = sub_bytes_final[2][2];

      // AddRoundKey with final round key
      state_enc[NR][0][0] = shift_rows_final[0][0] ^ expanded_key[56][31:24];
      state_enc[NR][0][1] = shift_rows_final[0][1] ^ expanded_key[56][23:16];
      state_enc[NR][0][2] = shift_rows_final[0][2] ^ expanded_key[56][15:8];
      state_enc[NR][0][3] = shift_rows_final[0][3] ^ expanded_key[56][7:0];
      
      state_enc[NR][1][0] = shift_rows_final[1][0] ^ expanded_key[57][31:24];
      state_enc[NR][1][1] = shift_rows_final[1][1] ^ expanded_key[57][23:16];
      state_enc[NR][1][2] = shift_rows_final[1][2] ^ expanded_key[57][15:8];
      state_enc[NR][1][3] = shift_rows_final[1][3] ^ expanded_key[57][7:0];
      
      state_enc[NR][2][0] = shift_rows_final[2][0] ^ expanded_key[58][31:24];
      state_enc[NR][2][1] = shift_rows_final[2][1] ^ expanded_key[58][23:16];
      state_enc[NR][2][2] = shift_rows_final[2][2] ^ expanded_key[58][15:8];
      state_enc[NR][2][3] = shift_rows_final[2][3] ^ expanded_key[58][7:0];
      
      state_enc[NR][3][0] = shift_rows_final[3][0] ^ expanded_key[59][31:24];
      state_enc[NR][3][1] = shift_rows_final[3][1] ^ expanded_key[59][23:16];
      state_enc[NR][3][2] = shift_rows_final[3][2] ^ expanded_key[59][15:8];
      state_enc[NR][3][3] = shift_rows_final[3][3] ^ expanded_key[59][7:0];
    end

    // Convert final state to output block
    for (i = 0; i < 4; i = i + 1) begin
      for (j = 0; j < 4; j = j + 1) begin
        encrypted_data[127 - (i*4+j)*8 -: 8] = state_enc[NR][i][j];
      end
    end
  end

  // ========================================================================
  // DECRYPTION PATH - Inverse Operations in Reverse Order
  // ========================================================================
  
  always_comb begin
    // ====================================================================
    // Initial Round: AddRoundKey with round key 14 (final key from encryption)
    // ====================================================================
    for (i = 0; i < 4; i = i + 1) begin
      for (j = 0; j < 4; j = j + 1) begin
        state_dec[0][i][j] = ciphertext[127 - (i*4+j)*8 -: 8] ^ 
                             expanded_key[56 + i][31 - j*8 -: 8];
      end
    end

    // ====================================================================
    // Main Inverse Rounds 13-1: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
    // ====================================================================
    for (int round = 1; round < NR; round = round + 1) begin
      // --- InvShiftRows: Rotate rows in reverse direction ---
      state_t inv_shift_rows_out;
      inv_shift_rows_out[0][0] = state_dec[round-1][0][0];
      inv_shift_rows_out[1][1] = state_dec[round-1][1][1];
      inv_shift_rows_out[2][2] = state_dec[round-1][2][2];
      inv_shift_rows_out[3][3] = state_dec[round-1][3][3];
      
      inv_shift_rows_out[1][0] = state_dec[round-1][3][1];
      inv_shift_rows_out[2][1] = state_dec[round-1][0][1];
      inv_shift_rows_out[3][2] = state_dec[round-1][1][1];
      inv_shift_rows_out[0][3] = state_dec[round-1][2][1];
      
      inv_shift_rows_out[2][0] = state_dec[round-1][2][2];
      inv_shift_rows_out[3][1] = state_dec[round-1][3][2];
      inv_shift_rows_out[0][2] = state_dec[round-1][0][2];
      inv_shift_rows_out[1][3] = state_dec[round-1][1][2];
      
      inv_shift_rows_out[3][0] = state_dec[round-1][1][3];
      inv_shift_rows_out[0][1] = state_dec[round-1][2][3];
      inv_shift_rows_out[1][2] = state_dec[round-1][3][3];
      inv_shift_rows_out[2][3] = state_dec[round-1][0][3];

      // --- InvSubBytes: Apply inverse S-box ---
      state_t inv_sub_bytes_out;
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          inv_sub_bytes_out[i][j] = INV_SBOX[inv_shift_rows_out[i][j]];
        end
      end

      // --- AddRoundKey: XOR with round key ---
      state_t add_key_out;
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          add_key_out[i][j] = inv_sub_bytes_out[i][j] ^ 
                              expanded_key[(NR - round)*4 + i][31 - j*8 -: 8];
        end
      end

      // --- InvMixColumns: Inverse multiplication by fixed polynomial ---
      // Each column multiplied by:
      // [0E 0B 0D 09] * [s0]   =  [14*s0 + 11*s1 + 13*s2 + 9*s3]
      // [09 0E 0B 0D]   [s1]      [9*s0 + 14*s1 + 11*s2 + 13*s3]
      // [0D 09 0E 0B]   [s2]      [13*s0 + 9*s1 + 14*s2 + 11*s3]
      // [0B 0D 09 0E]   [s3]      [11*s0 + 13*s1 + 9*s2 + 14*s3]
      state_t inv_mix_cols_out;
      for (j = 0; j < 4; j = j + 1) begin
        byte_t s0 = add_key_out[0][j];
        byte_t s1 = add_key_out[1][j];
        byte_t s2 = add_key_out[2][j];
        byte_t s3 = add_key_out[3][j];
        
        inv_mix_cols_out[0][j] = gmul14(s0) ^ gmul11(s1) ^ gmul13(s2) ^ gmul9(s3);
        inv_mix_cols_out[1][j] = gmul9(s0) ^ gmul14(s1) ^ gmul11(s2) ^ gmul13(s3);
        inv_mix_cols_out[2][j] = gmul13(s0) ^ gmul9(s1) ^ gmul14(s2) ^ gmul11(s3);
        inv_mix_cols_out[3][j] = gmul11(s0) ^ gmul13(s1) ^ gmul9(s2) ^ gmul14(s3);
      end

      // Update state for next round
      state_dec[round] = inv_mix_cols_out;
    end

    // ====================================================================
    // Final Inverse Round: InvShiftRows -> InvSubBytes -> AddRoundKey
    // ====================================================================
    begin
      // InvShiftRows
      state_t inv_shift_rows_final;
      inv_shift_rows_final[0][0] = state_dec[NR-1][0][0];
      inv_shift_rows_final[1][1] = state_dec[NR-1][1][1];
      inv_shift_rows_final[2][2] = state_dec[NR-1][2][2];
      inv_shift_rows_final[3][3] = state_dec[NR-1][3][3];
      
      inv_shift_rows_final[1][0] = state_dec[NR-1][3][1];
      inv_shift_rows_final[2][1] = state_dec[NR-1][0][1];
      inv_shift_rows_final[3][2] = state_dec[NR-1][1][1];
      inv_shift_rows_final[0][3] = state_dec[NR-1][2][1];
      
      inv_shift_rows_final[2][0] = state_dec[NR-1][2][2];
      inv_shift_rows_final[3][1] = state_dec[NR-1][3][2];
      inv_shift_rows_final[0][2] = state_dec[NR-1][0][2];
      inv_shift_rows_final[1][3] = state_dec[NR-1][1][2];
      
      inv_shift_rows_final[3][0] = state_dec[NR-1][1][3];
      inv_shift_rows_final[0][1] = state_dec[NR-1][2][3];
      inv_shift_rows_final[1][2] = state_dec[NR-1][3][3];
      inv_shift_rows_final[2][3] = state_dec[NR-1][0][3];

      // InvSubBytes
      state_t inv_sub_bytes_final;
      for (i = 0; i < 4; i = i + 1) begin
        for (j = 0; j < 4; j = j + 1) begin
          inv_sub_bytes_final[i][j] = INV_SBOX[inv_shift_rows_final[i][j]];
        end
      end

      // AddRoundKey with initial round key (key 0)
      state_dec[NR][0][0] = inv_sub_bytes_final[0][0] ^ expanded_key[0][31:24];
      state_dec[NR][0][1] = inv_sub_bytes_final[0][1] ^ expanded_key[0][23:16];
      state_dec[NR][0][2] = inv_sub_bytes_final[0][2] ^ expanded_key[0][15:8];
      state_dec[NR][0][3] = inv_sub_bytes_final[0][3] ^ expanded_key[0][7:0];
      
      state_dec[NR][1][0] = inv_sub_bytes_final[1][0] ^ expanded_key[1][31:24];
      state_dec[NR][1][1] = inv_sub_bytes_final[1][1] ^ expanded_key[1][23:16];
      state_dec[NR][1][2] = inv_sub_bytes_final[1][2] ^ expanded_key[1][15:8];
      state_dec[NR][1][3] = inv_sub_bytes_final[1][3] ^ expanded_key[1][7:0];
      
      state_dec[NR][2][0] = inv_sub_bytes_final[2][0] ^ expanded_key[2][31:24];
      state_dec[NR][2][1] = inv_sub_bytes_final[2][1] ^ expanded_key[2][23:16];
      state_dec[NR][2][2] = inv_sub_bytes_final[2][2] ^ expanded_key[2][15:8];
      state_dec[NR][2][3] = inv_sub_bytes_final[2][3] ^ expanded_key[2][7:0];
      
      state_dec[NR][3][0] = inv_sub_bytes_final[3][0] ^ expanded_key[3][31:24];
      state_dec[NR][3][1] = inv_sub_bytes_final[3][1] ^ expanded_key[3][23:16];
      state_dec[NR][3][2] = inv_sub_bytes_final[3][2] ^ expanded_key[3][15:8];
      state_dec[NR][3][3] = inv_sub_bytes_final[3][3] ^ expanded_key[3][7:0];
    end

    // Convert final decrypted state to output block
    for (i = 0; i < 4; i = i + 1) begin
      for (j = 0; j < 4; j = j + 1) begin
        decrypted_data[127 - (i*4+j)*8 -: 8] = state_dec[NR][i][j];
      end
    end
  end

endmodule : aes256_core