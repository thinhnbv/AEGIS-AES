//---------------------------------------------------------------
// top_security_demo.v  (Zynq ZC702, xc7z020clg484-1)
//
// Raw-vs-protected AES-128 security demo. Runs the SAME
// key/plaintext through:
//   - a bare, unprotected aes_core_tapped (per-Trojan infected copy)
//   - aegis_aes_top (KLG/FIC/RCM/RED/ORC + TRU) wrapping the same
//     infected core
// and reports both results plus the security status over UART,
// using the protocol implemented by fpga/host/demo_cli.py
// (36-byte request 0xA5.. / 37-byte response 0x5A.., 115200 8N1).
//
// UART noi truc tiep tu STM32F103 (Blue Pill) qua header J40,
// khong can Block Design, khong can Zynq PS, khong can TXS0108E.
//
// Differences vs the Gowin top:
//   - clock is the ZC702 onboard 200 MHz LVDS system clock,
//     declared as clk_p/clk_n so the XDC constrains the pair as LVDS_25;
//     Vivado then AUTO-INFERS the differential input buffer (IBUFDS) -
//     we deliberately do NOT hand-instantiate IBUFDS in the RTL because
//     its unisim port list changes between tool versions and broke
//     2024.1 synthesis (Synth 8-11365 "port N does not exist").
//   - fabric runs at 200 MHz / 8 = 25 MHz (UART + AEGIS), CLK_FREQ =
//     25_000_000 passed to the UART blocks.
//   - UART connects directly to STM32F103 (USB-to-UART) on FPGA pins
//     H17 (RX) / H22 (TX), NOT via Zynq PS EMIO.
//
// Pin map (zc702.xdc, UG850/RDF0171 reference):
//   clk_p/clk_n = D18/C19 (SYSCLK LVDS, bank MRCC)
//   rst_n       = G19     (GPIO_SW_N / SW5, ACTIVE-HIGH: thả=0, nhan=1)
//   uart_rx     = H17     (FPGA nhan tu STM32_TX/PA9)
//   uart_tx     = H22     (FPGA gui den STM32_RX/PA10)
//   led[0:3]    = E15/D15/W17/W5 (PMod1)
//---------------------------------------------------------------
`default_nettype none

module top_security_demo (
    input  wire       clk_p,
    input  wire       clk_n,
    input  wire       rst_n,      // G19 / SW5, ACTIVE-HIGH: thả=0, nhan=1

    input  wire       uart_rx,    // H17: nhan tu STM32_TX
    output wire       uart_tx,    // H22: gui den STM32_RX

    output wire [3:0] led
);

// SW5 la active-high (G19=1 khi nhan). Dao ve active-low cho cac module con.
wire sys_rst_n = ~rst_n;

// SYSCLK la xung LVDS 200 MHz tren ZC702 (D18/C19). Dung IBUFDS
// that de lay cap vi sai thanh 1 clock don - dung port chuan cua
// 7-series (.I/.IB/.O). Ban cu dung sai .N() nen synthesis bao
// Synth 8-11365; ban auto-infer (khong IBUFDS) thi DRC bao
// IOSTDTYPE-1 o write_bitstream. IBUFDS dung port chuan het ca 2 loi.
//
// Khi mo phong (Icarus/Verilator khong co primitive Xilinx), truyen
// -DSIM_IBUFDS_BYPASS de noi thang clk_p -> clk_in200.
wire clk_in200;
`ifdef SIM_IBUFDS_BYPASS
    assign clk_in200 = clk_p;
`else
    IBUFDS u_clkbuff (
        .I  (clk_p),
        .IB (clk_n),
        .O  (clk_in200)
    );
`endif

// ----------------------------------------------------------------
// FABRIC CLOCK: the AEGIS logic + monitors are NOT fast enough for
// 200 MHz (post-route critical path ~28.7 ns => ~34 MHz max, and
// the KLG 128-bit compare is the long path). The demo is a 115200
// UART, so run the fabric at 25 MHz: divide the 200 MHz input by
// 8 with a small counter - no MMCM IP, no Block Design needed.
//
// div_cnt[2] toggles every 4 cycles => 200/8 = 25 MHz. All the
// fabric (UART + raw/protected path + FSM) rides clk_core.
// zc702.xdc carries the matching create_generated_clock (clk25)
// on div_cnt_reg[2].Q - run Implementation, not just Synthesis,
// to close timing on it.
// ----------------------------------------------------------------
reg [2:0] div_cnt;
always @(posedge clk_in200 or negedge sys_rst_n) begin
    if (!sys_rst_n)
        div_cnt <= 3'd0;
    else
        div_cnt <= div_cnt + 3'd1;
end
wire clk_core = div_cnt[2];   // 200 MHz / 8 = 25 MHz

// System clock frequency the UART bit-timing prescaler computes
// from. MUST equal the frequency actually driving clk_core.
localparam integer CLK_FREQ = 25_000_000;

// ---- UART byte-level interface ----
wire [7:0] rx_data;
wire       rx_valid;

wire [7:0] tx_data;
wire       tx_valid;
wire       tx_ready;

// Parameter override theo goi trinh tu (Verilog-2001, hop le voi
// Vivado). Ba parameter cua uart_rx/uart_tx: (CLK_FREQ, BAUD_RATE,
// BIT_PERIOD) - chi cat CLK_FREQ, BAUD_RATE giu mac dinh 115200,
// BIT_PERIOD co thuc hien tu dua tren 2 goc dai dau.
uart_rx #(CLK_FREQ) u_uart_rx (
    .clk          (clk_core),
    .rst_n        (sys_rst_n),
    .uart_rx      (uart_rx),
    .rx_data      (rx_data),
    .rx_valid     (rx_valid),
    .rx_frame_err ()
);

uart_tx #(CLK_FREQ) u_uart_tx (
    .clk      (clk_core),
    .rst_n    (sys_rst_n),
    .tx_data  (tx_data),
    .tx_valid (tx_valid),
    .uart_tx  (uart_tx),
    .tx_ready (tx_ready)
);

// ---- Raw path: bare infected core, no protection ----
wire         raw_init;
wire         raw_next;
wire         raw_ready;
wire [127:0] raw_key;
wire [127:0] raw_block;
wire [127:0] raw_result;
wire         raw_result_valid;

aes_core_tapped u_raw_core (
    .clk               (clk_core),
    .reset_n           (sys_rst_n),

    .encdec            (1'b1),      // always encrypt for this demo
    .init              (raw_init),
    .next              (raw_next),
    .ready             (raw_ready),

    .key               ({raw_key, 128'd0}),
    .keylen            (1'b0),

    .block             (raw_block),
    .result            (raw_result),
    .result_valid      (raw_result_valid),
    .round_keys_flat   (),

    .muxed_round_nr    (),
    .state_before_final(),
    .fsm_state         ()
);

// ---- Protected path: full AEGIS wrapper around the same core ----
wire         prot_key_valid;
wire         prot_data_valid;
wire [127:0] prot_key;
wire [127:0] prot_block;
wire         prot_busy;
wire [127:0] prot_data_out;
wire         prot_data_out_valid;
wire         prot_sec_alarm;
wire         prot_sec_warning;
wire [7:0]   prot_sec_status;

aegis_aes_top #(
    .EN_ORC(1)
) u_protected (
    .clk            (clk_core),
    .rst_n          (sys_rst_n),
    .key            (prot_key),
    .key_valid      (prot_key_valid),
    .data_in        (prot_block),
    .data_in_valid  (prot_data_valid),
    .data_out       (prot_data_out),
    .data_out_valid (prot_data_out_valid),
    .busy           (prot_busy),
    .sec_alarm      (prot_sec_alarm),
    .sec_warning    (prot_sec_warning),
    .sec_status     (prot_sec_status)
);

// Catch-and-hold latch for the protected result: TRU only opens
// data_out_valid for a single cycle (the clean-verdict window), so
// it must be captured the moment it pulses rather than re-read
// later. Cleared each time a new request is issued.
reg  [127:0] prot_result_latched;
reg          prot_result_seen;

always @(posedge clk_core or negedge sys_rst_n) begin
    if (!sys_rst_n) begin
        prot_result_latched <= 128'd0;
        prot_result_seen    <= 1'b0;
    end else begin
        if (prot_data_valid)
            prot_result_seen <= 1'b0;

        if (prot_data_out_valid) begin
            prot_result_latched <= prot_data_out;
            prot_result_seen    <= 1'b1;
        end
    end
end

// ---- Command FSM (default 65535-cycle watchdogs; T05 DoS is
//      the only case that exercises them on the real board) ----
uart_cmd_fsm_security u_cmd (
    .clk             (clk_core),
    .rst_n           (sys_rst_n),

    .rx_data         (rx_data),
    .rx_valid        (rx_valid),

    .tx_data         (tx_data),
    .tx_valid        (tx_valid),
    .tx_ready        (tx_ready),

    .raw_init        (raw_init),
    .raw_next        (raw_next),
    .raw_ready       (raw_ready),
    .raw_key         (raw_key),
    .raw_block       (raw_block),
    .raw_result      (raw_result),

    .prot_key_valid       (prot_key_valid),
    .prot_data_valid      (prot_data_valid),
    .prot_busy            (prot_busy),
    .prot_key             (prot_key),
    .prot_block           (prot_block),
    .prot_result_latched  (prot_result_latched),
    .prot_result_seen     (prot_result_seen),
    .prot_sec_alarm       (prot_sec_alarm),
    .prot_sec_status      (prot_sec_status)
);

// Status LEDs
assign led[0] = ~uart_rx;      // RX activity
assign led[1] = ~uart_tx;      // TX activity
assign led[2] = ~prot_busy;    // lit when protected path idle
assign led[3] = prot_sec_alarm; // lit once TRU has locked down

endmodule

`default_nettype wire

//======================================================================
// EOF top_security_demo.v
//======================================================================
