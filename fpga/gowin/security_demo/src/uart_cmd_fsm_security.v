//---------------------------------------------------------------
// uart_cmd_fsm_security.v
// Command FSM for the raw-vs-protected AES security demo.
// Matches the protocol implemented by fpga/host/demo_cli.py.
//
// PC -> FPGA (36 bytes):
//   [0]     : 0xA5 (request preamble)
//   [1]     : 0x01 (AES_COMMAND)
//   [2]     : seq
//   [3:18]  : 16 bytes key
//   [19:34] : 16 bytes plaintext
//   [35]    : checksum (XOR of bytes 0..34)
//
// FPGA -> PC (37 bytes):
//   [0]     : 0x5A (response preamble)
//   [1]     : seq (echoed)
//   [2]     : flags
//   [3]     : sec_status
//   [4:19]  : 16 bytes raw_out
//   [20:35] : 16 bytes protected_out
//   [36]    : checksum (XOR of bytes 0..35)
//
// Flags: bit0=RAW_VALID bit1=PROTECTED_VALID bit2=ALARM
//        bit3=PROTECTED_BLOCKED
//---------------------------------------------------------------
`default_nettype none

module uart_cmd_fsm_security (
    input  wire        clk,
    input  wire        rst_n,

    // UART interface
    input  wire [7:0]  rx_data,
    input  wire        rx_valid,
    output reg  [7:0]  tx_data,
    output reg         tx_valid,
    input  wire        tx_ready,

    // Raw AES core control (aes_core_tapped direct interface)
    output reg          raw_init,
    output reg          raw_next,
    input  wire         raw_ready,
    output reg [127:0]  raw_key,
    output reg [127:0]  raw_block,
    input  wire [127:0] raw_result,

    // Protected path control (aegis_aes_top interface)
    output reg          prot_key_valid,
    output reg          prot_data_valid,
    input  wire         prot_busy,
    output reg [127:0]  prot_key,
    output reg [127:0]  prot_block,
    input  wire [127:0] prot_result_latched,
    input  wire         prot_result_seen,
    input  wire         prot_sec_alarm,
    input  wire [7:0]   prot_sec_status
);

    localparam ST_IDLE           = 5'd0;
    localparam ST_RECV_CMD       = 5'd1;
    localparam ST_RAW_INIT       = 5'd2;
    localparam ST_RAW_WAIT_READY = 5'd3;
    localparam ST_RAW_EXEC_ACK   = 5'd4;
    localparam ST_RAW_EXEC       = 5'd5;
    localparam ST_PROT_KEY_ACK   = 5'd6;
    localparam ST_PROT_KEY_WAIT  = 5'd7;
    localparam ST_PROT_DATA_ACK  = 5'd8;
    localparam ST_PROT_DATA_WAIT = 5'd9;
    localparam ST_PROT_SETTLE    = 5'd11;
    localparam ST_SEND_RESP      = 5'd10;

    reg [4:0] state;
    reg [5:0] rx_count;
    reg [7:0] rx_buf [0:35];
    reg [7:0] chksum;

    reg [5:0] tx_count;
    reg [7:0] tx_buf [0:36];
    reg       tx_phase;

    // sec_alarm/sec_status lag a couple of extra clock cycles behind
    // `busy` dropping: TRU only latches them after its own NORMAL ->
    // LOCKDOWN transition, which itself happens one cycle after
    // klg_alarm becomes visible. Wait a generous margin before
    // sampling them so we never read the pre-alarm value.
    reg [3:0] settle_cnt;

    reg       raw_result_valid_seen;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= ST_IDLE;
            rx_count        <= 6'd0;
            chksum          <= 8'd0;
            raw_init        <= 1'b0;
            raw_next        <= 1'b0;
            prot_key_valid  <= 1'b0;
            prot_data_valid <= 1'b0;
            tx_valid        <= 1'b0;
            tx_phase        <= 1'b0;
            raw_result_valid_seen <= 1'b0;
            settle_cnt      <= 4'd0;
        end else begin
            raw_init        <= 1'b0;
            raw_next        <= 1'b0;
            prot_key_valid  <= 1'b0;
            prot_data_valid <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (rx_valid && rx_data == 8'hA5) begin
                        rx_buf[0] <= rx_data;
                        rx_count  <= 6'd1;
                        chksum    <= rx_data;
                        state     <= ST_RECV_CMD;
                    end
                end

                ST_RECV_CMD: begin
                    if (rx_valid) begin
                        rx_buf[rx_count] <= rx_data;
                        if (rx_count < 6'd35)
                            chksum <= chksum ^ rx_data;
                        rx_count <= rx_count + 1'b1;

                        if (rx_count == 6'd35) begin
                            if (chksum == rx_data) begin
                                // Key bytes [3:18] -> 128 bits, MSB first
                                raw_key[127:120] <= rx_buf[3];
                                raw_key[119:112] <= rx_buf[4];
                                raw_key[111:104] <= rx_buf[5];
                                raw_key[103:96]  <= rx_buf[6];
                                raw_key[95:88]   <= rx_buf[7];
                                raw_key[87:80]   <= rx_buf[8];
                                raw_key[79:72]   <= rx_buf[9];
                                raw_key[71:64]   <= rx_buf[10];
                                raw_key[63:56]   <= rx_buf[11];
                                raw_key[55:48]   <= rx_buf[12];
                                raw_key[47:40]   <= rx_buf[13];
                                raw_key[39:32]   <= rx_buf[14];
                                raw_key[31:24]   <= rx_buf[15];
                                raw_key[23:16]   <= rx_buf[16];
                                raw_key[15:8]    <= rx_buf[17];
                                raw_key[7:0]     <= rx_buf[18];

                                // Plaintext bytes [19:34] -> 128 bits, MSB first
                                raw_block[127:120] <= rx_buf[19];
                                raw_block[119:112] <= rx_buf[20];
                                raw_block[111:104] <= rx_buf[21];
                                raw_block[103:96]  <= rx_buf[22];
                                raw_block[95:88]   <= rx_buf[23];
                                raw_block[87:80]   <= rx_buf[24];
                                raw_block[79:72]   <= rx_buf[25];
                                raw_block[71:64]   <= rx_buf[26];
                                raw_block[63:56]   <= rx_buf[27];
                                raw_block[55:48]   <= rx_buf[28];
                                raw_block[47:40]   <= rx_buf[29];
                                raw_block[39:32]   <= rx_buf[30];
                                raw_block[31:24]   <= rx_buf[31];
                                raw_block[23:16]   <= rx_buf[32];
                                raw_block[15:8]    <= rx_buf[33];
                                raw_block[7:0]     <= rx_buf[34];

                                raw_init <= 1'b1;
                                raw_result_valid_seen <= 1'b0;
                                state    <= ST_RAW_INIT;
                            end else begin
                                // Bad checksum: drop the frame silently and
                                // wait for the next one (matches the simple
                                // demo scope - the host scripts always send
                                // a valid checksum).
                                state <= ST_IDLE;
                            end
                        end
                    end
                end

                // ---- Raw path: direct aes_core_tapped handshake ----
                // Same drop-then-rise pattern proven in uart_cmd_fsm.v:
                // aes_core's ready register lags one cycle behind its own
                // combinational next-state logic, so a naive one-shot
                // check right after a control pulse reads a stale value.
                ST_RAW_INIT: begin
                    if (!raw_ready) begin
                        state <= ST_RAW_WAIT_READY;
                    end
                end

                ST_RAW_WAIT_READY: begin
                    if (raw_ready) begin
                        raw_next <= 1'b1;
                        state    <= ST_RAW_EXEC_ACK;
                    end
                end

                ST_RAW_EXEC_ACK: begin
                    if (!raw_ready) begin
                        state <= ST_RAW_EXEC;
                    end
                end

                ST_RAW_EXEC: begin
                    // raw_result becomes stable the same cycle raw_ready
                    // rises again (aes_core_tapped asserts result_valid
                    // and ready together when leaving CTRL_NEXT).
                    if (raw_ready) begin
                        raw_result_valid_seen <= 1'b1;

                        if (prot_sec_alarm) begin
                            // Already latched into LOCKDOWN from a
                            // previous transaction: TRU's zeroize holds
                            // aegis_aes_top's own core in reset forever,
                            // so its `busy` output is stuck high and will
                            // never drop again ("chi thoat LOCKDOWN bang
                            // reset cung" - by design). Driving a new
                            // key_valid/data_in_valid pulse here would
                            // just hang this FSM forever waiting for a
                            // busy-drop that can't happen. Skip straight
                            // to the response: protected output stays
                            // blocked, sec_alarm/sec_status are already
                            // sticky and correct to report as-is.
                            settle_cnt <= 4'd0;
                            state      <= ST_PROT_SETTLE;
                        end else begin
                            prot_key   <= raw_key;
                            prot_block <= raw_block;
                            prot_key_valid <= 1'b1;
                            state <= ST_PROT_KEY_ACK;
                        end
                    end
                end

                // ---- Protected path: aegis_aes_top handshake via `busy` ----
                ST_PROT_KEY_ACK: begin
                    if (prot_busy) begin
                        state <= ST_PROT_KEY_WAIT;
                    end
                end

                ST_PROT_KEY_WAIT: begin
                    if (!prot_busy) begin
                        prot_data_valid <= 1'b1;
                        state <= ST_PROT_DATA_ACK;
                    end
                end

                ST_PROT_DATA_ACK: begin
                    if (prot_busy) begin
                        state <= ST_PROT_DATA_WAIT;
                    end
                end

                ST_PROT_DATA_WAIT: begin
                    if (!prot_busy) begin
                        settle_cnt <= 4'd0;
                        state      <= ST_PROT_SETTLE;
                    end
                end

                ST_PROT_SETTLE: begin
                    if (settle_cnt == 4'd15) begin
                        // sec_alarm/sec_status have long since settled by
                        // now; raw_result/prot_result_latched were already
                        // stable held registers from the moment they were
                        // written.
                        tx_count <= 6'd0;
                        tx_phase <= 1'b0;

                        tx_buf[0] <= 8'h5A;
                        tx_buf[1] <= rx_buf[2]; // echo seq
                        tx_buf[2] <= {4'd0,
                                      ~prot_result_seen,     // bit3 PROTECTED_BLOCKED
                                      prot_sec_alarm,        // bit2 ALARM
                                      prot_result_seen,      // bit1 PROTECTED_VALID
                                      raw_result_valid_seen  // bit0 RAW_VALID
                                     };
                        tx_buf[3] <= prot_sec_status;

                        tx_buf[4]  <= raw_result[127:120];
                        tx_buf[5]  <= raw_result[119:112];
                        tx_buf[6]  <= raw_result[111:104];
                        tx_buf[7]  <= raw_result[103:96];
                        tx_buf[8]  <= raw_result[95:88];
                        tx_buf[9]  <= raw_result[87:80];
                        tx_buf[10] <= raw_result[79:72];
                        tx_buf[11] <= raw_result[71:64];
                        tx_buf[12] <= raw_result[63:56];
                        tx_buf[13] <= raw_result[55:48];
                        tx_buf[14] <= raw_result[47:40];
                        tx_buf[15] <= raw_result[39:32];
                        tx_buf[16] <= raw_result[31:24];
                        tx_buf[17] <= raw_result[23:16];
                        tx_buf[18] <= raw_result[15:8];
                        tx_buf[19] <= raw_result[7:0];

                        tx_buf[20] <= prot_result_seen ? prot_result_latched[127:120] : 8'd0;
                        tx_buf[21] <= prot_result_seen ? prot_result_latched[119:112] : 8'd0;
                        tx_buf[22] <= prot_result_seen ? prot_result_latched[111:104] : 8'd0;
                        tx_buf[23] <= prot_result_seen ? prot_result_latched[103:96]  : 8'd0;
                        tx_buf[24] <= prot_result_seen ? prot_result_latched[95:88]   : 8'd0;
                        tx_buf[25] <= prot_result_seen ? prot_result_latched[87:80]   : 8'd0;
                        tx_buf[26] <= prot_result_seen ? prot_result_latched[79:72]   : 8'd0;
                        tx_buf[27] <= prot_result_seen ? prot_result_latched[71:64]   : 8'd0;
                        tx_buf[28] <= prot_result_seen ? prot_result_latched[63:56]   : 8'd0;
                        tx_buf[29] <= prot_result_seen ? prot_result_latched[55:48]   : 8'd0;
                        tx_buf[30] <= prot_result_seen ? prot_result_latched[47:40]   : 8'd0;
                        tx_buf[31] <= prot_result_seen ? prot_result_latched[39:32]   : 8'd0;
                        tx_buf[32] <= prot_result_seen ? prot_result_latched[31:24]   : 8'd0;
                        tx_buf[33] <= prot_result_seen ? prot_result_latched[23:16]   : 8'd0;
                        tx_buf[34] <= prot_result_seen ? prot_result_latched[15:8]    : 8'd0;
                        tx_buf[35] <= prot_result_seen ? prot_result_latched[7:0]     : 8'd0;

                        state <= ST_SEND_RESP;
                    end else begin
                        settle_cnt <= settle_cnt + 1'b1;
                    end
                end

                ST_SEND_RESP: begin
                    if (tx_count == 6'd0 && tx_phase == 1'b0) begin
                        tx_buf[36] <= tx_buf[0]  ^ tx_buf[1]  ^ tx_buf[2]  ^ tx_buf[3]  ^
                                      tx_buf[4]  ^ tx_buf[5]  ^ tx_buf[6]  ^ tx_buf[7]  ^
                                      tx_buf[8]  ^ tx_buf[9]  ^ tx_buf[10] ^ tx_buf[11] ^
                                      tx_buf[12] ^ tx_buf[13] ^ tx_buf[14] ^ tx_buf[15] ^
                                      tx_buf[16] ^ tx_buf[17] ^ tx_buf[18] ^ tx_buf[19] ^
                                      tx_buf[20] ^ tx_buf[21] ^ tx_buf[22] ^ tx_buf[23] ^
                                      tx_buf[24] ^ tx_buf[25] ^ tx_buf[26] ^ tx_buf[27] ^
                                      tx_buf[28] ^ tx_buf[29] ^ tx_buf[30] ^ tx_buf[31] ^
                                      tx_buf[32] ^ tx_buf[33] ^ tx_buf[34] ^ tx_buf[35];
                    end

                    if (tx_phase == 1'b0) begin
                        if (tx_ready) begin
                            tx_data  <= tx_buf[tx_count];
                            tx_valid <= 1'b1;
                            tx_phase <= 1'b1;
                        end
                    end else begin
                        tx_valid <= 1'b0;

                        if (!tx_ready) begin
                            tx_phase <= 1'b0;

                            if (tx_count == 6'd36) begin
                                state    <= ST_IDLE;
                                tx_count <= 6'd0;
                            end else begin
                                tx_count <= tx_count + 1'b1;
                            end
                        end
                    end
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule

//======================================================================
// EOF uart_cmd_fsm_security.v
//======================================================================
