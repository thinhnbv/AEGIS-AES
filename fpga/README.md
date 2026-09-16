# AEGIS-AES FPGA Demo

FPGA demonstration system for AEGIS-AES on ACG525 board (GOWIN GW5A-25).

## Hardware

- **Board**: ACG525 from lecilaser.com
- **FPGA**: GW5A-LV25UG324C2-I1
- **Logic Cells**: 23,040 LUT4
- **Clock**: 50 MHz

## Features

- AES-128 encryption/decryption
- Hardware security monitors:
  - **KLG**: Key Load Guard
  - **FIC**: FSM Integrity Checker
  - **RCM**: Round Counter Monitor
  - **RED**: Rare-Event Detector
  - **ORC**: Output Consistency Checker
- UART interface (115200 baud, 8N1)

## UART Protocol

### PC → FPGA (36 bytes)

| Byte | Description |
|------|-------------|
| 0    | 0x01 (command marker) |
| 1    | 0x00=decrypt, 0x01=encrypt |
| 2-17 | 16-byte key |
| 18-33 | 16-byte plaintext/ciphertext |
| 34   | Checksum (XOR of bytes 0-33) |
| 35   | 0xAA (end marker) |

### FPGA → PC (37 bytes)

| Byte | Description |
|------|-------------|
| 0    | 0x02 (response marker) |
| 1    | Status (0=OK, 1=checksum error) |
| 2-17 | 16-byte result |
| 18-33 | Echoed block |
| 34   | Checksum |
| 35   | 0xBB (end marker) |
| 36   | Round counter value |

## Build

```bash
cd fpga
make bitstream   # Build bitstream (requires Gowin toolchain)
make program     # Program FPGA
make sim        # Run simulation
make view       # View waveforms
```

## Simulation

Uses Icarus Verilog for simulation:

```bash
cd fpga
make sim
make view  # Opens GTKWave
```

## Directory Structure

```
fpga/
├── uart/           # UART modules
│   ├── uart_rx.v
│   ├── uart_tx.v
│   └── uart_cmd_fsm.v
├── constraints/    # Pin and timing constraints
│   ├── acg525.pin
│   └── acg525.cst
├── host/           # PC host software
├── build/          # Build output
├── top_demo.v      # Top-level module
├── Makefile
└── README.md
```
