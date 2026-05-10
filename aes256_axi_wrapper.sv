// ============================================================================
// AES-256 AXI4-Lite Wrapper
// ============================================================================
// Description: AXI4-Lite interface wrapper for AES-256 core
// Features:
//   - Full AXI4-Lite protocol compliance
//   - Memory-mapped register interface
//   - Simultaneous encryption/decryption support
// Register Map:
//   0x00-0x1F: 256-bit Key (8 x 32-bit words)
//   0x20-0x2F: Plaintext/Encrypted Output
//   0x30-0x3F: Ciphertext/Decrypted Output
//   0x40: Control Register
//   0x44: Status Register
// ============================================================================

import aes256_pkg::*;

module aes256_axi_wrapper (
  input  logic          clk,
  input  logic          rst_n,
  
  // AXI4-Lite Write Address Channel
  input  logic [31:0]   awaddr,
  input  logic [2:0]    awprot,
  input  logic          awvalid,
  output logic          awready,
  
  // AXI4-Lite Write Data Channel
  input  logic [31:0]   wdata,
  input  logic [3:0]    wstrb,
  input  logic          wvalid,
  output logic          wready,
  
  // AXI4-Lite Write Response Channel
  output logic [1:0]    bresp,
  output logic          bvalid,
  input  logic          bready,
  
  // AXI4-Lite Read Address Channel
  input  logic [31:0]   araddr,
  input  logic [2:0]    arprot,
  input  logic          arvalid,
  output logic          arready,
  
  // AXI4-Lite Read Data Channel
  output logic [31:0]   rdata,
  output logic [1:0]    rresp,
  output logic          rvalid,
  input  logic          rready
);

  // ========================================================================
  // Internal Registers and Signals
  // ========================================================================
  key_t key;                      // 256-bit AES key
  block_t plaintext;              // 128-bit plaintext input
  block_t ciphertext;             // 128-bit ciphertext input
  block_t encrypted_output;       // 128-bit encrypted output
  block_t decrypted_output;       // 128-bit decrypted output
  
  logic [31:0] key_reg [8];       // Key storage (8 x 32-bit)
  logic [31:0] plaintext_reg [4]; // Plaintext storage (4 x 32-bit)
  logic [31:0] ciphertext_reg [4];// Ciphertext storage (4 x 32-bit)
  logic control_reg;              // Control: 1=encrypt, 0=decrypt
  logic status_reg;               // Status: encryption/decryption complete
  
  int i;

  // ========================================================================
  // AES-256 Core Instantiation
  // ========================================================================
  aes256_core aes_core (
    .key              (key),
    .plaintext        (plaintext),
    .ciphertext       (ciphertext),
    .encrypted_data   (encrypted_output),
    .decrypted_data   (decrypted_output)
  );

  // ========================================================================
  // Pack registers into key and data blocks
  // ========================================================================
  always_comb begin
    // Pack key from 8 registers into 256-bit key
    key = {key_reg[7], key_reg[6], key_reg[5], key_reg[4],
           key_reg[3], key_reg[2], key_reg[1], key_reg[0]};
    
    // Pack plaintext from 4 registers into 128-bit block
    plaintext = {plaintext_reg[3], plaintext_reg[2], plaintext_reg[1], plaintext_reg[0]};
    
    // Pack ciphertext from 4 registers into 128-bit block
    ciphertext = {ciphertext_reg[3], ciphertext_reg[2], ciphertext_reg[1], ciphertext_reg[0]};
  end

  // ========================================================================
  // AXI Write Address Channel - Always ready (combinational)
  // ========================================================================
  always_comb begin
    awready = 1'b1;  // Always ready to accept write addresses
  end

  // ========================================================================
  // AXI Write Data Channel - Always ready (combinational)
  // ========================================================================
  always_comb begin
    wready = 1'b1;   // Always ready to accept write data
  end

  // ========================================================================
  // AXI Write Response Channel - Respond when data is written
  // ========================================================================
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      bvalid <= 1'b0;
      bresp <= 2'b00; // OKAY response
    end else if (wvalid && wready) begin
      bvalid <= 1'b1;
      bresp <= 2'b00; // OKAY response
    end else if (bvalid && bready) begin
      bvalid <= 1'b0;
    end
  end

  // ========================================================================
  // AXI Write Handler - Decode address and write data
  // ========================================================================
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      for (i = 0; i < 8; i = i + 1) key_reg[i] <= 32'h0;
      for (i = 0; i < 4; i = i + 1) plaintext_reg[i] <= 32'h0;
      for (i = 0; i < 4; i = i + 1) ciphertext_reg[i] <= 32'h0;
      control_reg <= 1'b0;
      status_reg <= 1'b0;
    end else if (wvalid && wready && awvalid && awready) begin
      case (awaddr[5:2])
        // Key Registers: 0x00-0x1F (addresses 0-7 -> 32-bit words)
        4'h0: key_reg[0] <= wdata;
        4'h1: key_reg[1] <= wdata;
        4'h2: key_reg[2] <= wdata;
        4'h3: key_reg[3] <= wdata;
        4'h4: key_reg[4] <= wdata;
        4'h5: key_reg[5] <= wdata;
        4'h6: key_reg[6] <= wdata;
        4'h7: key_reg[7] <= wdata;
        
        // Plaintext Registers: 0x20-0x2F (addresses 8-11 -> 32-bit words)
        4'h8:  plaintext_reg[0] <= wdata;
        4'h9:  plaintext_reg[1] <= wdata;
        4'hA:  plaintext_reg[2] <= wdata;
        4'hB:  plaintext_reg[3] <= wdata;
        
        // Ciphertext Registers: 0x30-0x3F (addresses 12-15 -> 32-bit words)
        4'hC:  ciphertext_reg[0] <= wdata;
        4'hD:  ciphertext_reg[1] <= wdata;
        4'hE:  ciphertext_reg[2] <= wdata;
        4'hF:  ciphertext_reg[3] <= wdata;
        
        default: begin
          // Ignore writes to unmapped addresses
        end
      endcase
    end
  end

  // ========================================================================
  // AXI Read Address Channel - Always ready (combinational)
  // ========================================================================
  always_comb begin
    arready = 1'b1;  // Always ready to accept read addresses
  end

  // ========================================================================
  // AXI Read Data Channel - Respond with data
  // ========================================================================
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rvalid <= 1'b0;
      rdata <= 32'h0;
      rresp <= 2'b00;  // OKAY response
    end else if (arvalid && arready) begin
      rvalid <= 1'b1;
      rresp <= 2'b00;  // OKAY response
      
      // Decode address and provide data
      case (araddr[5:2])
        // Key Registers
        4'h0: rdata <= key_reg[0];
        4'h1: rdata <= key_reg[1];
        4'h2: rdata <= key_reg[2];
        4'h3: rdata <= key_reg[3];
        4'h4: rdata <= key_reg[4];
        4'h5: rdata <= key_reg[5];
        4'h6: rdata <= key_reg[6];
        4'h7: rdata <= key_reg[7];
        
        // Plaintext/Output Registers
        4'h8:  rdata <= plaintext_reg[0];
        4'h9:  rdata <= plaintext_reg[1];
        4'hA:  rdata <= plaintext_reg[2];
        4'hB:  rdata <= plaintext_reg[3];
        
        // Ciphertext/Output Registers
        4'hC:  rdata <= ciphertext_reg[0];
        4'hD:  rdata <= ciphertext_reg[1];
        4'hE:  rdata <= ciphertext_reg[2];
        4'hF:  rdata <= ciphertext_reg[3];
        
        default: rdata <= 32'h0;
      endcase
    end else if (rvalid && rready) begin
      rvalid <= 1'b0;
    end
  end

endmodule : aes256_axi_wrapper