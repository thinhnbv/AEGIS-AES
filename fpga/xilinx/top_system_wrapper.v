`default_nettype none

// top_system_wrapper.v
//
// Top-level cho Zynq ZC702: Block Design (ZYNQ7 PS + UART1 EMIO)
// + custom RTL top_security_demo.
//
// Instantiates:
//   - zc702_system_wrapper  (BD wrapper sinh ra bởi Vivado generate_target)
//   - top_security_demo     (custom RTL: AES + UART + FSM + monitors)
//
// UART cross-connection qua EMIO:
//   PL TX (top_security_demo.uart_tx_emio)  -> PS RX (zc702_system_wrapper.uart_rx_emio)
//   PS TX (zc702_system_wrapper.uart_tx_emio) -> PL RX (top_security_demo.uart_rx_emio)
//
// Cổng clk_p/clk_n/rst_n/led được nối thẳng từ board qua top_security_demo.
// M_AXI_GP0_ACLK_0 gán 0 (không dùng AXI GP từ PL sang PS, chỉ dùng UART qua EMIO).

module top_system_wrapper (
    // ---- Zynq PS DDR3 interface ----
    inout wire [14:0] DDR_addr,
    inout wire [2:0]  DDR_ba,
    inout wire        DDR_cas_n,
    inout wire        DDR_ck_n,
    inout wire        DDR_ck_p,
    inout wire        DDR_cke,
    inout wire        DDR_cs_n,
    inout wire [3:0]  DDR_dm,
    inout wire [31:0] DDR_dq,
    inout wire [3:0]  DDR_dqs_n,
    inout wire [3:0]  DDR_dqs_p,
    inout wire        DDR_odt,
    inout wire        DDR_ras_n,
    inout wire        DDR_reset_n,
    inout wire        DDR_we_n,
    inout wire        FIXED_IO_ddr_vrn,
    inout wire        FIXED_IO_ddr_vrp,
    inout wire [53:0] FIXED_IO_mio,
    inout wire        FIXED_IO_ps_clk,
    inout wire        FIXED_IO_ps_porb,
    inout wire        FIXED_IO_ps_srstb,

    // ---- Board clock & reset ----
    input  wire clk_p,      // SYSCLK P (D18)
    input  wire clk_n,      // SYSCLK N (C19)
    input  wire rst_n,      // G19 / SW5, ACTIVE-HIGH: thả=0, nhan=1

    // ---- User LEDs ----
    output wire [3:0] led   // E15/D15/W17/W5 (PMod1)
);

    // UART cross-connection giữa PS và PL
    wire uart_pl_to_ps;   // top_security_demo TX  -> zc702_system_wrapper RX
    wire uart_ps_to_pl;   // zc702_system_wrapper TX -> top_security_demo RX

    // ---- Zynq PS Block Design wrapper ----
    zc702_system_wrapper u_ps (
        .DDR_addr          (DDR_addr),
        .DDR_ba            (DDR_ba),
        .DDR_cas_n         (DDR_cas_n),
        .DDR_ck_n          (DDR_ck_n),
        .DDR_ck_p          (DDR_ck_p),
        .DDR_cke           (DDR_cke),
        .DDR_cs_n          (DDR_cs_n),
        .DDR_dm            (DDR_dm),
        .DDR_dq            (DDR_dq),
        .DDR_dqs_n         (DDR_dqs_n),
        .DDR_dqs_p         (DDR_dqs_p),
        .DDR_odt           (DDR_odt),
        .DDR_ras_n         (DDR_ras_n),
        .DDR_reset_n       (DDR_reset_n),
        .DDR_we_n          (DDR_we_n),
        .FIXED_IO_ddr_vrn  (FIXED_IO_ddr_vrn),
        .FIXED_IO_ddr_vrp  (FIXED_IO_ddr_vrp),
        .FIXED_IO_mio      (FIXED_IO_mio),
        .FIXED_IO_ps_clk   (FIXED_IO_ps_clk),
        .FIXED_IO_ps_porb  (FIXED_IO_ps_porb),
        .FIXED_IO_ps_srstb (FIXED_IO_ps_srstb),
        .M_AXI_GP0_ACLK_0  (1'b0),           // không dùng AXI GP PL->PS
        .uart_rx_emio      (uart_pl_to_ps),  // PL TX -> PS RX
        .uart_tx_emio      (uart_ps_to_pl)   // PS TX -> PL RX
    );

    // ---- Custom RTL: AES demo + UART + FSM + monitors ----
    top_security_demo u_top (
        .clk_p        (clk_p),
        .clk_n        (clk_n),
        .rst_n        (rst_n),
        .uart_rx_emio (uart_ps_to_pl),   // PS TX -> PL RX
        .uart_tx_emio (uart_pl_to_ps),   // PL TX -> PS RX
        .led          (led)
    );

endmodule

`default_nettype wire

//======================================================================
// EOF top_system_wrapper.v
//======================================================================
