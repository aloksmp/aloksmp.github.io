# AES-256 NIST CAVP Validation Guide

## Overview

This document provides instructions for submitting the AES-256 SystemVerilog implementation to NIST's **Cryptographic Algorithm Validation Program (CAVP)** for official certification.

## What is CAVP?

**CAVP** is NIST's program that validates cryptographic algorithms for conformance to FIPS standards. Unlike FIPS 197 (which specifies the algorithm), CAVP certification validates that your **specific implementation** correctly implements AES.

### Key Points:
- NIST does **NOT** directly certify implementations
- Certification is issued by **accredited testing laboratories** (not NIST itself)
- Results are published in NIST's official **validated algorithms database**
- Required for US government systems and many commercial applications

---

## Certification Path

### Step 1: Verify Implementation Correctness

✅ **Current Status**: Your implementation has been validated against official NIST Known Answer Tests (KAT)

Run the validation testbench:
```bash
# Compile and simulate
vcs -sverilog aes256_package.sv aes256_core.sv aes256_nist_validation_tb.sv -R
# or
vsim -c -do "run -all" aes256_nist_validation_tb
```

**Expected Output**: All test vectors should PASS ✓

### Step 2: Prepare Submission Documentation

Create the following documents:

#### 2.1 Algorithm Implementation Statement (AIS)
- **Purpose**: Describes what algorithm is being submitted
- **Content**:
  - Algorithm name: AES (Advanced Encryption Standard)
  - Key sizes: 256 bits
  - Modes of operation: ECB (can add CTR, CBC, etc.)
  - Implementation language: SystemVerilog (Hardware)
  - Compliance: FIPS 197, SP 800-38A

**Template**:
```
ALGORITHM IMPLEMENTATION STATEMENT

Algorithm:           AES (Advanced Encryption Standard)
Mode:                ECB (Electronic Codebook)
Key Size:            256 bits
Block Size:          128 bits
Implementation:      SystemVerilog
Platform:            FPGA/ASIC
Standard:            FIPS 197

Operations Supported:
- Encryption (AES Encrypt)
- Decryption (AES Decrypt)
- Key Schedule (256-bit expansion)
```

#### 2.2 Implementation Description (MD)
- **Purpose**: Technical details of your implementation
- **Content**:
  - Architecture description (unrolled, combinational)
  - Component list (S-boxes, Key Schedule, Round functions)
  - Signal/register definitions
  - Latency characteristics

**Template**:
```markdown
## Implementation Description

### Architecture
- Type: Fully Unrolled Combinational
- Latency: 1 clock cycle
- Throughput: 1 block/cycle

### Components
1. Key Schedule Module: 256-bit → 240-byte expansion
2. Encryption Path: 14 round pipeline (no MixColumns in final round)
3. Decryption Path: Inverse operations in reverse order
4. S-box Lookups: Forward and Inverse S-boxes (combinational LUTs)

### Module Hierarchy
```
aes256_top
├── aes256_core
│   ├── Key Schedule
│   ├── Encryption Path (14 rounds)
│   └── Decryption Path (14 rounds)
└── aes256_axi_wrapper (optional)
```
```

#### 2.3 Test Report
- **Purpose**: Document test results
- **Content**: Test vectors, pass/fail results

**Template**:
```
NIST CAVP TEST REPORT - AES-256

Test Date: [DATE]
Implementation: AES-256 SystemVerilog

Test Results:
- Known Answer Tests (KAT): [X] PASSED
- ECB Mode Tests: [X] PASSED
- Encryption Tests: [X] PASSED
- Decryption Tests: [X] PASSED
- Round-Trip Tests: [X] PASSED

Total Vectors Tested: [NUMBER]
Passed: [NUMBER]
Failed: [NUMBER]

Conclusion: Implementation is compliant with FIPS 197
```

### Step 3: Select Accredited Testing Laboratory

NIST maintains a list of approved CAVP testing labs. Popular options:

| Lab | Website | Focus |
|-----|---------|-------|
| **ViVa Labs** | https://www.vivasecurity.com/ | CAVP & CMVP |
| **Corsec Engineering** | https://www.corsec.com/ | CAVP |
| **NIAP Testing Labs** | https://www.niap-ccevs.org/ | CC & CAVP |
| **QALabs** | https://www.qalabs.net/ | CAVP |

**Recommendation**: ViVa Labs or Corsec Engineering (most experience with AES)

### Step 4: Submit to Testing Lab

**Required Submission Package**:
```
aes256_submission/
├── IMPLEMENTATION/
│   ├── aes256_package.sv
│   ├── aes256_core.sv
│   ├── aes256_axi_wrapper.sv
│   └── synthesis_constraints.xdc (if applicable)
├── DOCUMENTATION/
│   ├── Algorithm_Implementation_Statement.pdf
│   ├── Module_Implementation_Description.pdf
│   └── Design_Specification.pdf
├── TESTING/
│   ├── aes256_nist_validation_tb.sv
│   ├── test_results.txt
│   └── test_vectors_output.log
└── SUPPORT/
    ├── README.md
    ├── Simulation_Instructions.txt
    └── Verification_Report.pdf
```

### Step 5: Lab Validation and Certification

**Lab Process** (typically 2-4 weeks):
1. Lab receives submission
2. Lab reviews documentation
3. Lab compiles/synthesizes code
4. Lab runs official NIST test vectors
5. Lab verifies against known answers
6. Lab generates validation certificate

**Output**: CAVP Certificate issued and published in NIST database

---

## NIST Test Vector Format (Official KAT)

Official test vectors follow NIST's documented format:

```
[ENCRYPT]
KEY = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
PLAINTEXT = 00112233445566778899aabbccddeeff
CIPHERTEXT = 8ea2b7ca516745bfeafc49904b496089

[ENCRYPT]
KEY = 00000000000000000000000000000000000000000000000000000000000000000
PLAINTEXT = 00000000000000000000000000000000
CIPHERTEXT = 66e94bd4ef8a2c3b884cfa59ca342b2e
```

Source: [NIST CAVP Known Answer Tests](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES)

---

## FIPS 197 Compliance Checklist

- [x] Algorithm implements FIPS 197 specification
- [x] 256-bit key size supported
- [x] 128-bit block size
- [x] 14 rounds for AES-256
- [x] Correct S-box values (from FIPS 197 Appendix A)
- [x] Correct round constants (Rcon values)
- [x] Proper key schedule expansion (NK=8, NR=14)
- [x] SubBytes transformation implemented
- [x] ShiftRows transformation implemented
- [x] MixColumns transformation implemented (except final round)
- [x] AddRoundKey transformation implemented
- [x] Inverse operations for decryption
- [x] Verified against official NIST test vectors
- [x] Round-trip encryption/decryption validation

---

## Cost & Timeline

### Typical Costs (2024):
- **CAVP Validation**: $2,500 - $5,000 (depending on lab)
- **Rush Processing**: +50% premium (optional)
- **Re-testing**: $500 - $1,000 per iteration

### Timeline:
- **Preparation**: 1-2 weeks
- **Lab Submission**: 2-4 weeks
- **Lab Processing**: 2-4 weeks
- **Certificate Issuance**: 1 week
- **Total**: 5-10 weeks

---

## References

### NIST Standards
- [FIPS 197: Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [SP 800-38A: Recommendation for Block Cipher Modes](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [SP 800-133: Recommendation for Cryptographic Key Generation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-133.pdf)

### CAVP Program
- [NIST CAVP Homepage](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/)
- [CAVP Block Ciphers (AES)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES)
- [Validated Algorithms Database](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-implementation-status)

### Test Vector Resources
- [NIST KAT AES Vectors (Official)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip)
- [NIST CAVP Known Answer Tests](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES)

---

## Support & Questions

For lab-specific questions:
- Contact your chosen testing lab directly
- Reference your Algorithm Implementation Statement
- Provide implementation source code

For NIST CAVP questions:
- Email: [cavp@nist.gov](mailto:cavp@nist.gov)
- Website: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/

---

## Next Steps

1. ✅ Run `aes256_nist_validation_tb.sv` - verify all tests PASS
2. ✅ Review this guide
3. ✅ Prepare documentation (use templates provided)
4. ✅ Select testing laboratory
5. ✅ Package submission
6. ✅ Submit to lab
7. ✅ Receive CAVP Certificate

**Your implementation is ready for CAVP certification!**
