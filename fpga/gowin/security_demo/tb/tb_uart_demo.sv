`timescale 1ns/1ps
//----------------------------------------------------------------
// tb_uart_demo.sv  (one compile per case, selected by -DT0N)
//
// Proves the UART command protocol end-to-end at the byte level for
// each Trojan case, driving the REAL uart_cmd_fsm_security (with its
// T05 watchdog) + the per-case aes_core_tapped (raw path) + the real
// aegis_aes_top (protected path). The UART IP itself is not modeled:
// we drive rx_data/rx_valid and capture tx_data/tx_valid/tx_ready,
// which is exactly the byte interface the IP exposes to the FSM.
//
// Compile per case with -DT01 .. -DT05 (1 = T01 .. 5 = T05). The
// infected raw core file is supplied by the Makefile target; the -DT0N
// flag picks the matching body below.
//
// Per-case checks:
//   - a valid 37-byte response is emitted   (the T05 unlock - without
//     the raw watchdog, no response ever comes back on a DoS frame)
//   - response byte[0] == 0x5A
//   - sec_status == the case's expected mask
//   - the RAW_VALID flag == expected
//
// T02 note: to avoid streaming 2^16 frames in simulation, the per-case
// counter is preloaded one step below the trigger threshold (the same
// technique tb_security.sv uses), so the leak starts immediately and
// KLG's 6-result window fills over the next few frames. The design
// itself keeps its spec threshold (2^16).
//----------------------------------------------------------------
// Case selection: the Makefile passes one of -DT01 .. -DT05 (and the
// per-case infected core file). Each `ifdef T0N block below is the
// body for that case.
`include "aegis_defs.vh"

module tb_uart_demo;

    localparam integer PERIOD = 20;      // 50 MHz

    reg clk, rst_n;
    always #(PERIOD/2) clk = ~clk;

    // ---- UART-FSM byte interface (the IP boundary) ----
    reg  [7:0]  rx_data;
    reg         rx_valid;
    reg  [7:0]  tx_data;
    reg         tx_valid;
    reg         tx_ready;

    // ---- Raw path: the per-case infected core ----
    wire         raw_init, raw_next, raw_ready, raw_result_valid;
    wire [127:0] raw_result;
    reg  [127:0] raw_key, raw_block;

// T04's infected core has two extra outputs (debug_valid/debug_data)
    // that are not part of the raw hand-off; connect them only when
    // building that case.
    aes_core_tapped u_raw_core (
        .clk              (clk),
        .reset_n          (rst_n),
        .encdec           (1'b1),
        .init             (raw_init),
        .next             (raw_next),
        .ready            (raw_ready),
        .key              ({raw_key, 128'd0}),
        .keylen           (1'b0),
        .block            (raw_block),
        .result           (raw_result),
        .result_valid     (raw_result_valid),
        .round_keys_flat  (),
        .muxed_round_nr   (),
        .state_before_final(),
        .fsm_state        ()
    );

    // ---- Protected path: full AEGIS wrapper around the same core ----
    wire         prot_key_valid, prot_data_valid, prot_busy;
    wire [127:0] prot_key, prot_block;
    wire [127:0] prot_data_out;
    wire         prot_data_out_valid, prot_sec_alarm;
    wire [7:0]   prot_sec_status;

    aegis_aes_top #(.EN_ORC(1)) u_protected (
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
        .sec_warning    (),
        .sec_status     (prot_sec_status)
    );

    // Catch-and-hold the protected result (single-cycle window), as
    // top_security_demo.v does on the board.
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

    // ---- The command FSM under test. Short watchdog timeouts so a
    //      T05 (DoS) transaction completes in sim in a few hundred
    //      us instead of waiting the default 65536-cycle window. ----
    localparam RAW_TIMEOUT  = 16'd6000;
    localparam PROT_TIMEOUT = 16'd6000;

    // Per-byte guard for get_response: must outlast the longest FSM
    // escape path (watchdog 6000 + settle 15 + a full 37-byte send).
    localparam integer GUARD_CYCLES = 60000;

    uart_cmd_fsm_security #(
        .RAW_TIMEOUT (RAW_TIMEOUT),
        .PROT_TIMEOUT(PROT_TIMEOUT)
    ) u_cmd (
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

    // ---- Frame construction / capture ----
    reg  [7:0] frame [0:35];
    reg  [7:0] resp [0:36];

    // Send a 36-byte request: [0]=0xA5 [1]=0x01 [2]=seq [3:18]=key
    // [19:34]=pt [35]=XOR(0..34).
    //
    // Wire byte order is MSB-first (matches demo_cli.py, which
    // transmits FIPS_KEY as 0x2b first, and uart_cmd_fsm_security,
    // which maps wire byte 3 -> key[127:120]).
    task automatic send_frame(input integer seq,
                              input reg [127:0] key,
                              input reg [127:0] pt);
        integer i;
        reg [7:0] cks;
        begin
            frame[0]  = 8'hA5;
            frame[1]  = 8'h01;
            frame[2]  = seq[7:0];
            for (i = 0; i < 16; i = i + 1)
                frame[3  + i] = key[(15-i)*8 +: 8];
            for (i = 0; i < 16; i = i + 1)
                frame[19 + i] = pt [(15-i)*8 +: 8];
            cks = 8'd0;
            for (i = 0; i < 35; i = i + 1)
                cks = cks ^ frame[i];
            frame[35] = cks;

            for (i = 0; i < 36; i = i + 1) begin
                rx_data  <= frame[i];
                rx_valid <= 1'b1;
                @(posedge clk);
                rx_valid <= 1'b0;
            end
        end
    endtask

    // Capture one 37-byte response. ok=0 means "no response within the
    // per-byte guard" - the exact T05 failure mode the watchdog is
    // meant to remove.
    //
    // Handshake (matches uart_tx.v / ST_SEND_RESP): holding tx_ready
    // high loads the next byte onto tx_data and tx_valid pulses for
    // exactly one cycle; dropping tx_ready for one cycle advances.
    //
    // tx_valid is sampled on the NEGEDGE, not the posedge: the pulse
    // is high for a full cycle, so a mid-cycle sample is race-free on
    // both Icarus and Verilator (a posedge sample races the FSM's
    // nonblocking update and can miss the byte, so the FSM finishes
    // the whole response while the TB is still waiting). On timeout
    // we print where the FSM is so we can tell "slow" from "stuck".
    task automatic get_response(output integer ok);
        integer b, guard;
        begin
            ok    = 1;
            guard = 0;
            b = 0;
            while (b < 37 && ok) begin
                tx_ready = 1'b1;
                while (tx_valid !== 1'b1 && guard < GUARD_CYCLES) begin
                    @(negedge clk);
                    guard = guard + 1;
                end
                if (guard >= GUARD_CYCLES) begin
                    ok = 0;
                    $display("  [diag] stuck at byte %0d: fsm=%0d raw_ready=%0b prot_busy=%0b prot_alarm=%0b",
                             b, u_cmd.state, raw_ready, prot_busy, prot_sec_alarm);
                end else begin
                    resp[b] = tx_data;
                    tx_ready = 1'b0;
                    // Wait for the byte pulse to actually clear before
                    // the next byte, otherwise a stale tx_valid from the
                    // just-advanced byte can be re-sampled and desync
                    // the whole capture. This keeps the handshake
                    // edge-safe on both Icarus and Verilator.
                    while (tx_valid === 1'b1 && b < 37)
                        @(negedge clk);
                    guard = 0;
                    b = b + 1;
                end
            end
            // ---- Inter-frame gap (the real UART one) ----
            // After the 37th byte the FSM is still in ST_SEND_RESP for
            // one more cycle before it drops to ST_IDLE; and only in
            // ST_IDLE does it accept the next 0xA5 preamble. A real
            // serial link has ~1 ms idle between frames, so waiting
            // for the FSM to be ready again is a faithful model.
            // Without this, back-to-back frames in sim are lost.
            while (u_cmd.state !== 5'd0)
                @(posedge clk);
            @(posedge clk);
        end
    endtask

    reg  [127:0] KEY = 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c;
    integer      failures = 0;
    integer      i, ok;

    task automatic check(input [400:0] tag, input integer got_ok,
                         input reg [7:0] status, input reg rv);
        reg [3:0] got_flags;
        begin
            got_flags = {resp[2][3], resp[2][2], resp[2][1], resp[2][0]};
            if (!got_ok) begin
                $display("  [FAIL] %s: NO RESPONSE (watchdog did not recover)", tag);
                failures = failures + 1;
            end else begin
                if (resp[0] !== 8'h5A) begin
                    $display("  [FAIL] %s: byte[0]=%02h (want 5A)", tag, resp[0]);
                    failures = failures + 1;
                end
                // Contract semantics: every expected bit must be set
                // (extras are allowed - e.g. RED also flags a rare
                // 0xFF frame in T05, matching make-security checks).
                if ((resp[3] & status) !== status) begin
                    $display("  [FAIL] %s: sec_status=%02h (must contain %02h)",
                             tag, resp[3], status);
                    failures = failures + 1;
                end else
                    $display("  [ok] %s: sec_status=%02h (contains %02h)",
                             tag, resp[3], status);
                if (got_flags[0] !== rv) begin
                    $display("  [FAIL] %s: RAW_VALID=%0b (want %0b)", tag, got_flags[0], rv);
                    failures = failures + 1;
                end else
                    $display("  [ok] %s: flags rv=%0b pv=%0b alm=%0b blk=%0b", tag,
                             got_flags[0], got_flags[1], got_flags[2], got_flags[3]);
            end
        end
    endtask

    //----------------------------------------------------------
    // Per-case bodies, selected by -DT01 .. -DT05.
    //----------------------------------------------------------
    initial begin
        $display("==================================================");
        $display("UART DEMO PROOF");
        $display("==================================================");
        rst_n    = 1'b0;
        rx_valid = 1'b0;
        tx_ready = 1'b0;
        repeat (5) @(posedge clk);
        rst_n = 1'b1;
        repeat (5) @(posedge clk);

`ifdef T01
        $display("[T01] key-dump trigger, 1 frame");
        send_frame(1, KEY, 128'hDEADBEEF_CAFEBABE_00000000_00000000);
        get_response(ok);
        check("T01", ok, 8'h01, 1'b1);   // KLG; raw returns the key
`endif

`ifdef T02
`ifndef VERILATOR
        // Preload the encryption counter one step below the trigger
        // threshold on BOTH cores (Icarus-only trick - DUT-internal
        // value assignment, like tb_security does), then the next
        // few frames leak key[7:0] and KLG's window fills.
        @(negedge clk);
        u_raw_core.encrypt_counter =
            u_raw_core.T02_TRIGGER_COUNT - 16'd1;
        u_protected.u_core.encrypt_counter =
            u_protected.u_core.T02_TRIGGER_COUNT - 16'd1;
        #1;
        $display("[T02] slow-leak: counter preloaded to %0d (threshold %0d)",
                 u_raw_core.encrypt_counter, u_raw_core.T02_TRIGGER_COUNT);
`else
        // Compiled-simulator build: DUT-internal counter preload is
        // not reachable (same limitation the `make security` flow
        // documents), so the Trojan must genuinely accumulate 2^16
        // encryptions.
        // 65544 = 65535 threshold + 9 confirmation margin.
        $display("[T02] slow-leak: sending 65544 frames (2^16 accumulation)");
`endif
        begin
            integer j, nok, t02_fail;
            reg [127:0] pt = 128'h00112233_44556677_8899aabb_ccddeeff;
            integer t02_total;
            t02_fail = 0;
`ifdef VERILATOR
            t02_total = 65544;
`else
            t02_total = 6;
`endif
            for (j = 0; j < t02_total; j = j + 1) begin
                send_frame(j, KEY, pt);
                get_response(nok);
                if (!nok) begin
                    $display("  [FAIL] T02 frame %0d: no response", j);
                    failures = failures + 1;
                    t02_fail = 1;
                end else if ((j % 10000) == 0)
                    $display("  [i] T02 frame %0d/%0d: sec_status=%02h rv=%0b",
                             j, t02_total, resp[3], resp[2][0]);
            end
            if (!t02_fail) begin
                if ((resp[3] & 8'h11) !== 8'h11) begin
                    $display("  [FAIL] T02: sec_status=%02h (must contain 11 = KLG+ORC)",
                             resp[3]);
                    failures = failures + 1;
                end else
                    $display("  [ok] T02: sec_status=%02h contains 11 (KLG+ORC)", resp[3]);
            end
        end
`endif

`ifdef T03
        $display("[T03] skip-MixColumns trigger, 1 frame");
        send_frame(1, KEY, 128'h12345678_9ABCDEF0_00000000_00000001);
        get_response(ok);
        check("T03", ok, 8'h14, 1'b1);   // RCM+ORC
`endif

`ifdef T04
        // 3-frame sequence A5 -> 5A -> FF; the Trojan fires on the
        // third frame.
        $display("[T04] debug-port trigger, 3-frame sequence A5->5A->FF");
        begin
            integer nok;
            send_frame(1, KEY, 128'hA5A5A5A5_A5A5A5A5_A5A5A5A5_A5A5A5A5);
            get_response(nok);
            $display("  [i] T04 f1: ok=%0b sec_status=%02h", nok, resp[3]);
            send_frame(2, KEY, 128'h5A5A5A5A_5A5A5A5A_5A5A5A5A_5A5A5A5A);
            get_response(nok);
            $display("  [i] T04 f2: ok=%0b sec_status=%02h", nok, resp[3]);
            send_frame(3, KEY, 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
            get_response(nok);
            check("T04-f3", nok, 8'h0A, 1'b1);   // FIC+RED
        end
`endif

`ifdef T05
        $display("[T05] DoS trigger - raw core hangs, watchdog must recover");
        send_frame(1, KEY, 128'hFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF);
        get_response(ok);
        check("T05", ok, 8'h04, 1'b0);   // RCM; raw NOT valid
        // A post-lockdown frame must also return a response (the
        // protected TRU holds the protected core in reset - handled by
        // the FSM's lockdown path, not a hang).
        $display("[T05] post-lockdown frame");
        send_frame(2, KEY, 128'h00112233_44556677_8899aabb_ccddeeff);
        get_response(ok);
        if (!ok) begin
            $display("  [FAIL] T05 post-lockdown: no response");
            failures = failures + 1;
        end else
            $display("  [ok] T05 post-lockdown response received (sec_status=%02h)",
                     resp[3]);
`endif


        $display("==================================================");
        if (failures == 0)
            $display("[PASS] UART DEMO PROOF");
        else begin
            $display("[FAIL] UART DEMO PROOF (%0d failures)", failures);
            $fatal(1, "UART DEMO PROOF failed");
        end
        $display("==================================================");
        $finish;
    end

`ifdef PROBE
    // Debug monitor (compile with -DPROBE): log every command-FSM
    // state transition plus the byte handshake (tx_count/tx_phase/
    // tx_valid) and the security signals, so a stuck or skipped
    // response can be read against the FSM timeline.
    integer probe_cycle;
    reg [4:0] probe_prev_state;
    always @(posedge clk) begin
        probe_cycle = probe_cycle + 1;
        if (u_cmd.state !== probe_prev_state || u_cmd.tx_valid) begin
            $display(
                "[PROBE] c=%0d st=%0d->%0d settle=%0d txc=%0d txph=%0b tval=%0b rxn=%0d alm=%0b status=%02h ralm=%0b prot_busy=%0b pseen=%0b",
                probe_cycle, probe_prev_state, u_cmd.state,
                u_cmd.settle_cnt, u_cmd.tx_count, u_cmd.tx_phase,
                u_cmd.tx_valid, u_cmd.rx_count,
                u_cmd.prot_sec_alarm, u_cmd.prot_sec_status,
                u_protected.klg_alarm, prot_busy, prot_result_seen);
            probe_prev_state = u_cmd.state;
        end
        if (probe_cycle > 500000)
            $display("[PROBE] monitor stopped at %0d", probe_cycle);
    end
`endif

    // Hard watchdog on the TB itself so a deadlock can't hang forever.
    // T02 (compiled-sim, no counter preload) streams ~65544 frames,
    // each up to a few thousand cycles, so it needs a much larger
    // budget than the other cases.
    integer tb_cycle = 0;
`ifdef T02
`ifdef VERILATOR
    localparam integer TB_TIMEOUT = 130_000_000;   // ~65544 x ~2000
`else
    localparam integer TB_TIMEOUT = 3_000_000;      // preloaded: ~6 frames
`endif
`else
    localparam integer TB_TIMEOUT = 3_000_000;
`endif
    always @(posedge clk) begin
        tb_cycle = tb_cycle + 1;
        if (tb_cycle == TB_TIMEOUT + 1) begin
            $display("[FAIL] TB global timeout (%0d cycles)", tb_cycle);
            $finish;
        end
    end

endmodule
