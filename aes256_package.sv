// ============================================================================
// AES-256 SystemVerilog Package
// ============================================================================
// Description: Contains all AES-256 constants, S-boxes, type definitions,
//              and helper functions for encryption/decryption operations
// ============================================================================

package aes256_pkg;

  // ========================================================================
  // Type Definitions
  // ========================================================================
  typedef logic [7:0] byte_t;           // 8-bit byte
  typedef logic [31:0] word_t;          // 32-bit word
  typedef logic [127:0] block_t;        // 128-bit data block
  typedef logic [255:0] key_t;          // 256-bit key
  typedef byte_t state_t [4][4];        // 4x4 state matrix for AES
  typedef word_t sched_t [60];          // 60 words for expanded key (256-bit AES)

  // ========================================================================
  // AES-256 Constants
  // ========================================================================
  localparam int NK = 8;                // Number of 32-bit words in key (256-bit)
  localparam int NR = 14;               // Number of rounds for AES-256
  localparam int NWORDS = 60;           // Total expanded key words (4*(NR+1))

  // ========================================================================
  // S-Box: Substitution Table for SubBytes Transformation
  // Maps 8-bit input to 8-bit output using affine transformation in GF(2^8)
  // ========================================================================
  localparam byte_t SBOX [256] = '{
    8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5, 8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
    8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0, 8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
    8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc, 8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
    8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a, 8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
    8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0, 8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,
    8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b, 8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,
    8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85, 8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,
    8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5, 8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,
    8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17, 8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,
    8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88, 8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,
    8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5f, 8'hc2, 8'h3f, 8'h79, 8'h55, 8'h18, 8'h02, 8'h8d, 8'hfd,
    8'hc1, 8'h89, 8'h64, 8'h8c, 8'h9b, 8'h6d, 8'h85, 8'h15, 8'h70, 8'h8c, 8'h9c, 8'h0c, 8'h8e, 8'h8d, 8'hae, 8'h2a,
    8'h7e, 8'hab, 8'h63, 8'hd1, 8'h25, 8'h35, 8'h45, 8'hec, 8'h20, 8'h81, 8'hec, 8'h60, 8'h201, 8'h27, 8'h1f, 8'h16,
    8'h18, 8'h08, 8'h01, 8'h8e, 8'h84, 8'h60, 8'hee, 8'h6e, 8'hef, 8'ha6, 8'h37, 8'hd2, 8'hb6, 8'h76, 8'hd9, 8'h73,
    8'h52, 8'hdb, 8'h70, 8'h13, 8'h86, 8'h5a, 8'h6d, 8'h5f, 8'hea, 8'h9f, 8'h6c, 8'heb, 8'h7f, 8'h8f, 8'h44, 8'h06
  };

  // ========================================================================
  // Inverse S-Box: For InvSubBytes transformation during decryption
  // Maps 8-bit input back to original value
  // ========================================================================
  localparam byte_t INV_SBOX [256] = '{
    8'h52, 8'h09, 8'h6a, 8'hd5, 8'h30, 8'h36, 8'ha5, 8'h38, 8'hbf, 8'h40, 8'ha3, 8'h9e, 8'h81, 8'hf3, 8'hd7, 8'hfb,
    8'h7c, 8'he3, 8'h39, 8'h82, 8'h9b, 8'h2f, 8'hff, 8'h87, 8'h34, 8'h8e, 8'h43, 8'h44, 8'hc4, 8'hde, 8'he9, 8'hcb,
    8'h54, 8'h7b, 8'h94, 8'h32, 8'ha6, 8'hc2, 8'h23, 8'h3d, 8'hee, 8'h4c, 8'h95, 8'h0b, 8'h42, 8'hfa, 8'hc3, 8'h4e,
    8'h08, 8'h2e, 8'ha1, 8'h66, 8'h28, 8'hd9, 8'h24, 8'hb2, 8'h76, 8'h5b, 8'ha2, 8'h49, 8'h6d, 8'h8b, 8'hd1, 8'h25,
    8'h72, 8'hf8, 8'hf6, 8'h64, 8'h86, 8'h68, 8'h98, 8'h16, 8'hd4, 8'ha4, 8'h5c, 8'hcc, 8'h5d, 8'h65, 8'hb6, 8'h92,
    8'h6c, 8'h70, 8'h48, 8'h50, 8'hfd, 8'hed, 8'hb9, 8'hda, 8'h5e, 8'h15, 8'h46, 8'h57, 8'ha7, 8'h8d, 8'h9d, 8'h84,
    8'h90, 8'hd8, 8'hab, 8'h00, 8'h8c, 8'hbc, 8'hd3, 8'h0a, 8'hf7, 8'h64, 8'h77, 8'had, 8'hc5, 8'h41, 8'h6f, 8'h06,
    8'h50, 8'hf2, 8'hcf, 8'h0f, 8'hfa, 8'h85, 8'hf0, 8'h7c, 8'h1f, 8'h27, 8'h72, 8'h5d, 8'h27, 8'h08, 8'h0d, 8'hf2,
    8'h8e, 8'h4e, 8'h5f, 8'hab, 8'h2a, 8'hf9, 8'h37, 8'he8, 8'h1c, 8'h75, 8'hdf, 8'h6e, 8'h47, 8'hf1, 8'h1a, 8'h71,
    8'h1d, 8'h29, 8'hc5, 8'h89, 8'h6f, 8'hb7, 8'h62, 8'h0e, 8'haa, 8'h18, 8'hbe, 8'h1b, 8'hfc, 8'h56, 8'h3e, 8'h4b,
    8'hc6, 8'hd2, 8'h79, 8'h20, 8'h9a, 8'hdb, 8'hc0, 8'hfe, 8'h78, 8'hcd, 8'h5a, 8'h2c, 8'h1c, 8'h1a, 8'h6e, 8'h5a,
    8'ha0, 8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84, 8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1,
    8'h5b, 8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf, 8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33,
    8'h85, 8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8, 8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38,
    8'hf5, 8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2, 8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44
  };

  // ========================================================================
  // Round Constants (Rcon): Used in Key Schedule Expansion
  // These are powers of 2 in GF(2^8), placed in first byte of word
  // ========================================================================
  localparam byte_t RCON [10] = '{
    8'h01, 8'h02, 8'h04, 8'h08, 8'h10, 8'h20, 8'h40, 8'h80, 8'h1b, 8'h36
  };

  // ========================================================================
  // Galois Field Multiplication Helper Functions
  // These functions multiply two bytes in GF(2^8) using irreducible polynomial
  // ========================================================================

  // Multiply by 2 in GF(2^8): {9B} or x*a(x) mod (x^8 + x^4 + x^3 + x + 1)
  function automatic byte_t gmul2(byte_t b);
    return (b[7] == 1'b1) ? ((b << 1) ^ 8'h1b) : (b << 1);
  endfunction

  // Multiply by 3 in GF(2^8): {9B}*x + {9B} = gmul2(b) XOR b
  function automatic byte_t gmul3(byte_t b);
    return gmul2(b) ^ b;
  endfunction

  // Multiply by 9 in GF(2^8): Used in InvMixColumns
  function automatic byte_t gmul9(byte_t b);
    byte_t b2, b4, b8;
    b2 = gmul2(b);
    b4 = gmul2(b2);
    b8 = gmul2(b4);
    return b8 ^ b;
  endfunction

  // Multiply by 11 in GF(2^8): Used in InvMixColumns
  function automatic byte_t gmul11(byte_t b);
    byte_t b2, b4, b8;
    b2 = gmul2(b);
    b4 = gmul2(b2);
    b8 = gmul2(b4);
    return b8 ^ b4 ^ b;
  endfunction

  // Multiply by 13 in GF(2^8): Used in InvMixColumns
  function automatic byte_t gmul13(byte_t b);
    byte_t b2, b4, b8;
    b2 = gmul2(b);
    b4 = gmul2(b2);
    b8 = gmul2(b4);
    return b8 ^ b4 ^ b2;
  endfunction

  // Multiply by 14 in GF(2^8): Used in InvMixColumns
  function automatic byte_t gmul14(byte_t b);
    byte_t b2, b4, b8;
    b2 = gmul2(b);
    b4 = gmul2(b2);
    b8 = gmul2(b4);
    return b8 ^ b4 ^ b2 ^ b;
  endfunction

endpackage : aes256_pkg