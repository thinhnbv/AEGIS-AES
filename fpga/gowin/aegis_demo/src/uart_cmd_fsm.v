//---------------------------------------------------------------
// uart_cmd_fsm.v
// Command FSM for PC-FPGA protocol
//---------------------------------------------------------------
`default_nettype none

module uart_cmd_fsm (
    input  wire       clk,
    input  wire       rst_n,

    // UART interface
    input  wire [7:0] rx_data,
    input  wire       rx_valid,
    output reg        rx_ready,

    // TX interface
    output reg  [7:0] tx_data,
    output reg        tx_valid,
    input  wire       tx_ready,

    // AES control
    output reg        cmd_start,
    output reg        cmd_init,       // Key init signal
    input  wire       cmd_done,
    input  wire       aes_ready,      // AES core ready
    output reg        cmd_is_encrypt, // 1=encrypt, 0=decrypt

    // Key
    output reg  [127:0] key,
    output reg        key_valid,

    // Block (plaintext/ciphertext)
    output reg  [127:0] block,

    // Result
    input  wire [127:0] result,
    output reg          result_ready
);

    // Protocol:
    // PC -> FPGA (36 bytes):
    //   [0]     : 0x01 (cmd marker)
    //   [1]     : 0x00=decrypt, 0x01=encrypt
    //   [2:17]  : 16 bytes key
    //   [18:33] : 16 bytes block data
    //   [34]    : checksum (XOR of bytes 0..33)
    //   [35]    : 0xAA (end marker)
    //
    // FPGA -> PC (37 bytes):
    //   [0]     : 0x02 (response marker)
    //   [1]     : status (0=OK, 1=checksum error, 2=busy)
    //   [2:17]  : 16 bytes result
    //   [18:33] : echoed block
    //   [34]    : checksum
    //   [35]    : 0xBB (end marker)
    //   [36]    : round counter value (muxed_round_nr)

    localparam ST_IDLE          = 4'd0;
    localparam ST_RECV_CMD      = 4'd1;
    localparam ST_INIT_KEY      = 4'd2;
    localparam ST_WAIT_READY     = 4'd3;
    localparam ST_EXEC          = 4'd4;
    localparam ST_SEND_RESP     = 4'd5;
    localparam ST_ERR_CHKSUM    = 4'd6;
    localparam ST_EXEC_ACK      = 4'd7;

    reg [3:0] state;
    reg [5:0] rx_count;
    reg [7:0] rx_buf [0:35];
    reg [7:0] chksum;

    reg [5:0] tx_count;
    reg [7:0] tx_buf [0:36];
    reg       tx_phase; // 0 = waiting to push next byte, 1 = waiting for uart_tx to accept it

    // Input FSM
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= ST_IDLE;
            rx_count     <= 6'd0;
            rx_ready     <= 1'b1;
            chksum       <= 8'd0;
            cmd_start    <= 1'b0;
            cmd_init     <= 1'b0;
            key_valid    <= 1'b0;
            result_ready <= 1'b0;
            tx_phase     <= 1'b0;
        end else begin
            cmd_start    <= 1'b0;
            cmd_init     <= 1'b0;
            result_ready <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (rx_valid && rx_ready) begin
                        if (rx_data == 8'h01) begin
                            // Store the marker itself at rx_buf[0] and start
                            // counting from 1, so every later byte lands at
                            // its documented protocol index. Previously the
                            // marker was consumed without being stored/counted,
                            // shifting every subsequent byte's index by one and
                            // making the FSM wait for a 37th byte that never
                            // arrives (permanent hang in ST_RECV_CMD).
                            rx_buf[0] <= rx_data;
                            rx_count  <= 6'd1;
                            rx_ready  <= 1'b0;
                            state     <= ST_RECV_CMD;
                            chksum    <= rx_data;
                        end
                    end
                end

                ST_RECV_CMD: begin
                    if (rx_valid) begin
                        rx_buf[rx_count] <= rx_data;
                        if (rx_count < 6'd34)
                            chksum <= chksum ^ rx_data;
                        rx_count <= rx_count + 1'b1;

                        if (rx_count == 6'd35) begin
                            rx_ready <= 1'b1;

                            // Check checksum and end marker
                            // chksum now = XOR(bytes 0-33), rx_buf[34] = host checksum byte
                            if ((chksum == rx_buf[34]) && (rx_data == 8'hAA)) begin
                                // Parse command
                                cmd_is_encrypt <= rx_buf[1][0];

                                // Key bytes [2:17] -> key[127:0]
                                key[127:120] <= rx_buf[2];
                                key[119:112] <= rx_buf[3];
                                key[111:104] <= rx_buf[4];
                                key[103:96]  <= rx_buf[5];
                                key[95:88]   <= rx_buf[6];
                                key[87:80]   <= rx_buf[7];
                                key[79:72]   <= rx_buf[8];
                                key[71:64]   <= rx_buf[9];
                                key[63:56]   <= rx_buf[10];
                                key[55:48]   <= rx_buf[11];
                                key[47:40]   <= rx_buf[12];
                                key[39:32]   <= rx_buf[13];
                                key[31:24]   <= rx_buf[14];
                                key[23:16]   <= rx_buf[15];
                                key[15:8]    <= rx_buf[16];
                                key[7:0]     <= rx_buf[17];

                                // Block bytes [18:33] -> block[127:0]
                                block[127:120] <= rx_buf[18];
                                block[119:112] <= rx_buf[19];
                                block[111:104] <= rx_buf[20];
                                block[103:96]  <= rx_buf[21];
                                block[95:88]   <= rx_buf[22];
                                block[87:80]   <= rx_buf[23];
                                block[79:72]   <= rx_buf[24];
                                block[71:64]   <= rx_buf[25];
                                block[63:56]   <= rx_buf[26];
                                block[55:48]   <= rx_buf[27];
                                block[47:40]   <= rx_buf[28];
                                block[39:32]   <= rx_buf[29];
                                block[31:24]   <= rx_buf[30];
                                block[23:16]   <= rx_buf[31];
                                block[15:8]    <= rx_buf[32];
                                block[7:0]     <= rx_buf[33];

                                key_valid <= 1'b1;
                                cmd_init  <= 1'b1;
                                state     <= ST_INIT_KEY;
                            end else begin
                                state <= ST_ERR_CHKSUM;
                            end
                        end
                    end
                end

                ST_INIT_KEY: begin
                    // Wait for aes_core to actually register cmd_init and drop
                    // aes_ready before trusting it - right after the init pulse,
                    // aes_ready still reads its stale (old) value for one cycle
                    // because aes_core's ready_reg update lags one clock behind
                    // its combinational next-state logic.
                    key_valid <= 1'b0;
                    if (!aes_ready) begin
                        state <= ST_WAIT_READY;
                    end
                end

                ST_WAIT_READY: begin
                    if (aes_ready) begin
                        cmd_start <= 1'b1;
                        state     <= ST_EXEC_ACK;
                    end
                end

                ST_EXEC_ACK: begin
                    // Same stale-read hazard as ST_INIT_KEY, but for cmd_start:
                    // wait for aes_ready to actually drop before trusting
                    // cmd_done, otherwise a result_valid left over (held high)
                    // from a previous transaction can be misread as "done"
                    // before the new operation has even started.
                    if (!aes_ready) begin
                        state <= ST_EXEC;
                    end
                end

                ST_EXEC: begin
                    if (cmd_done) begin
                        state <= ST_SEND_RESP;
                        tx_count <= 6'd0;
                        tx_phase <= 1'b0;

                        // Build response buffer
                        tx_buf[0] <= 8'h02;  // marker
                        tx_buf[1] <= 8'h00;  // status OK

                        // Result [2:17]
                        tx_buf[2]  <= result[127:120];
                        tx_buf[3]  <= result[119:112];
                        tx_buf[4]  <= result[111:104];
                        tx_buf[5]  <= result[103:96];
                        tx_buf[6]  <= result[95:88];
                        tx_buf[7]  <= result[87:80];
                        tx_buf[8]  <= result[79:72];
                        tx_buf[9]  <= result[71:64];
                        tx_buf[10] <= result[63:56];
                        tx_buf[11] <= result[55:48];
                        tx_buf[12] <= result[47:40];
                        tx_buf[13] <= result[39:32];
                        tx_buf[14] <= result[31:24];
                        tx_buf[15] <= result[23:16];
                        tx_buf[16] <= result[15:8];
                        tx_buf[17] <= result[7:0];

                        // Echoed block [18:33]
                        tx_buf[18] <= block[127:120];
                        tx_buf[19] <= block[119:112];
                        tx_buf[20] <= block[111:104];
                        tx_buf[21] <= block[103:96];
                        tx_buf[22] <= block[95:88];
                        tx_buf[23] <= block[87:80];
                        tx_buf[24] <= block[79:72];
                        tx_buf[25] <= block[71:64];
                        tx_buf[26] <= block[63:56];
                        tx_buf[27] <= block[55:48];
                        tx_buf[28] <= block[47:40];
                        tx_buf[29] <= block[39:32];
                        tx_buf[30] <= block[31:24];
                        tx_buf[31] <= block[23:16];
                        tx_buf[32] <= block[15:8];
                        tx_buf[33] <= block[7:0];

                        tx_buf[35] <= 8'hBB;  // end marker
                        tx_buf[36] <= 8'h00;  // round counter placeholder
                    end
                end

                ST_SEND_RESP: begin
                    if (tx_count == 6'd0 && tx_phase == 1'b0) begin
                        // Compute checksum for bytes 0..33
                        tx_buf[34] <= tx_buf[0] ^ tx_buf[1] ^ tx_buf[2] ^ tx_buf[3] ^
                                      tx_buf[4] ^ tx_buf[5] ^ tx_buf[6] ^ tx_buf[7] ^
                                      tx_buf[8] ^ tx_buf[9] ^ tx_buf[10] ^ tx_buf[11] ^
                                      tx_buf[12] ^ tx_buf[13] ^ tx_buf[14] ^ tx_buf[15] ^
                                      tx_buf[16] ^ tx_buf[17] ^ tx_buf[18] ^ tx_buf[19] ^
                                      tx_buf[20] ^ tx_buf[21] ^ tx_buf[22] ^ tx_buf[23] ^
                                      tx_buf[24] ^ tx_buf[25] ^ tx_buf[26] ^ tx_buf[27] ^
                                      tx_buf[28] ^ tx_buf[29] ^ tx_buf[30] ^ tx_buf[31] ^
                                      tx_buf[32] ^ tx_buf[33];
                    end

                    if (tx_phase == 1'b0) begin
                        // Request phase: push the next byte once uart_tx is idle.
                        if (tx_ready) begin
                            tx_data  <= tx_buf[tx_count];
                            tx_valid <= 1'b1;
                            tx_phase <= 1'b1;
                        end
                    end else begin
                        // Accept phase: wait for uart_tx to latch the byte and go busy
                        // (tx_ready deasserts) before advancing tx_count. This avoids
                        // pushing a second byte while tx_ready is still stale-high.
                        tx_valid <= 1'b0;

                        if (!tx_ready) begin
                            tx_phase <= 1'b0;

                            if (tx_count == 6'd36) begin
                                result_ready <= 1'b1;
                                state        <= ST_IDLE;
                                tx_count     <= 6'd0;
                            end else begin
                                tx_count <= tx_count + 1'b1;
                            end
                        end
                    end
                end

                ST_ERR_CHKSUM: begin
                    // Send error response
                    if (tx_ready) begin
                        tx_data  <= 8'h02;
                        tx_valid <= 1'b1;
                        tx_count <= tx_count + 1'b1;

                        if (tx_count == 6'd0) begin
                            tx_buf[1] <= 8'h01;  // checksum error
                        end

                        if (tx_count >= 6'd35) begin
                            tx_valid <= 1'b0;
                            state    <= ST_IDLE;
                            tx_count <= 6'd0;
                            rx_ready <= 1'b1;
                        end
                    end else begin
                        tx_valid <= 1'b0;
                    end
                end
            endcase
        end
    end

endmodule

//======================================================================
// EOF uart_cmd_fsm.v
//======================================================================
