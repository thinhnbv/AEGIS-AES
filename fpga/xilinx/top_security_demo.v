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
// Differences vs the Gowin top:
//   - clock is the ZC702 onboard 200 MHz LVDS system clock,
//     declared as clk_p/clk_n so the XDC can constrain the pair
//     directly (no PLL/MMCM: 115200 baud at 200 MHz is plenty).
//   - UART RX/TX CLK_FREQ passed explicitly = 200_000_000.
//
// Pin map (zc702.xdc, UG850/RDF0171 reference):
//   clk_p/clk_n = D18/C19 (SYSCLK LVDS, bank MRCC)
//   rst_n       = G19     (GPIO_SW_N, active-low, pullup)
//   uart_rx/tx  = P18/W10 (PMod2, external USB-UART)
//   led[0:3]    = E15/D15/W17/W5 (PMod1)
//---------------------------------------------------------------
`default_nettype none

module top_security_demo (
    input  wire       clk_p,
    input  wire       clk_n,
    input  wire       rst_n,

    input  wire       uart_rx,
    output wire       uart_tx,

    output wire [3:0] led
);

    // Internal single-ended clock derived from the LVDS pair. Only
    // clk_p carries the signal; clk_n exists so the XDC can constrain
    // the differential input pair on the device package.
    wire clk;
    assign clk = clk_p;

    // 200 MHz system clock (ZC702 onboard oscillator).
    localparam integer CLK_FREQ = 200_000_000;

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
        .clk          (clk),
        .rst_n        (rst_n),
        .uart_rx      (uart_rx),
        .rx_data      (rx_data),
        .rx_valid     (rx_valid),
        .rx_frame_err ()
    );

    uart_tx #(CLK_FREQ) u_uart_tx (
        .clk      (clk),
        .rst_n    (rst_n),
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
        .clk               (clk),
        .reset_n           (rst_n),

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
        .clk            (clk),
        .rst_n          (rst_n),
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

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
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
        .clk             (clk),
        .rst_n           (rst_n),

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
    assign led[0] = ~uart_rx;       // RX activity
    assign led[1] = ~uart_tx;       // TX activity
    assign led[2] = ~prot_busy;     // lit when protected path idle
    assign led[3] = prot_sec_alarm; // lit once TRU has locked down

endmodule

`default_nettype wire

//======================================================================
// EOF top_security_demo.v
//======================================================================
