//---------------------------------------------------------------
// rcm_round_monitor.v
//
// Round Consistency Monitor (RCM)
//
// Checks:
//   1) Request/response liveness.
//   2) Monotonic round progression.
//   3) No round jumps.
//   4) Result appears only at the legal terminal round.
//   5) Each normal AES main round occupies the expected minimum
//      number of clocks.
//
// T03:
//   The exact P3 payload skips the round-5 MAIN/MixColumns stage.
//   That makes round 5 one clock shorter. RCM records this timing
//   inconsistency and raises the hard alarm when the result arrives,
//   allowing ORC and RCM to latch together before TRU zeroization.
//
// T05:
//   Start/operation timeout remains a hard liveness alarm.
//
// rcm_alarm is sticky until reset.
//---------------------------------------------------------------

`default_nettype none
`include "aegis_defs.vh"

module rcm_round_monitor #(
    parameter integer NUM_ROUNDS     = 10,
    parameter integer START_TIMEOUT  = 16,
    parameter integer OP_TIMEOUT     = 256,

    // With the iterative Secworks datapath, after a round number is
    // first observed it remains stable for four additional RCM
    // samples before the next legal round number appears.
    parameter integer MIN_ROUND_HOLD = 4
) (
    input  wire       clk,
    input  wire       rst_n,

    input  wire       init,
    input  wire       next,
    input  wire       ready,

    input  wire       result_valid,
    input  wire [3:0] round_nr,

    output reg        rcm_alarm,
    output reg [3:0]  rcm_code
);


  //----------------------------------------------------------------
  // States.
  //----------------------------------------------------------------
  localparam [2:0] RCM_IDLE       = 3'd0;
  localparam [2:0] RCM_WAIT_START = 3'd1;
  localparam [2:0] RCM_ACTIVE     = 3'd2;
  localparam [2:0] RCM_DONE       = 3'd3;
  localparam [2:0] RCM_ERROR      = 3'd4;

  reg [2:0] state;


  //----------------------------------------------------------------
  // Round/liveness tracking.
  //----------------------------------------------------------------
  reg [3:0] prev_round_nr;
  reg       first_round_seen;

  reg [7:0] round_hold_count;

  reg [15:0] start_wait_count;
  reg [15:0] active_count;

  reg timing_fault_pending;


  //----------------------------------------------------------------
  // Secworks can expose NUM_ROUNDS+1 at completion.
  //----------------------------------------------------------------
  localparam [3:0] MAX_TERMINAL_ROUND =
      NUM_ROUNDS + 1;


  //----------------------------------------------------------------
  // Main monitor.
  //----------------------------------------------------------------
  always @(posedge clk or negedge rst_n)
    begin

      if (!rst_n)
        begin

          state                <= RCM_IDLE;

          prev_round_nr        <= 4'd0;
          first_round_seen     <= 1'b0;
          round_hold_count     <= 8'd0;

          start_wait_count     <= 16'd0;
          active_count         <= 16'd0;

          timing_fault_pending <= 1'b0;

          rcm_alarm            <= 1'b0;
          rcm_code             <= 4'd0;

        end
      else
        begin

          case (state)

            //---------------------------------------------------
            // IDLE
            //---------------------------------------------------
            RCM_IDLE:
              begin

                start_wait_count     <= 16'd0;
                active_count         <= 16'd0;

                first_round_seen     <= 1'b0;
                round_hold_count     <= 8'd0;
                timing_fault_pending <= 1'b0;

                if (next)
                  begin

                    state            <= RCM_WAIT_START;

                    start_wait_count <= 16'd0;
                    active_count     <= 16'd0;

                    prev_round_nr    <= round_nr;

                  end

              end


            //---------------------------------------------------
            // WAIT_START
            //
            // A valid request must drive the AES core into the
            // active/busy phase.
            //---------------------------------------------------
            RCM_WAIT_START:
              begin

                if (!ready && !result_valid)
                  begin

                    state                <= RCM_ACTIVE;

                    active_count         <= 16'd0;
                    first_round_seen     <= 1'b0;
                    round_hold_count     <= 8'd0;
                    timing_fault_pending <= 1'b0;

                    prev_round_nr        <= round_nr;

                  end
                else if (start_wait_count >=
                         (START_TIMEOUT - 1))
                  begin

                    rcm_alarm <= 1'b1;
                    rcm_code  <= 4'd5;
                    state     <= RCM_ERROR;

                  end
                else
                  begin

                    start_wait_count <=
                        start_wait_count + 16'd1;

                  end

              end


            //---------------------------------------------------
            // ACTIVE
            //---------------------------------------------------
            RCM_ACTIVE:
              begin

                //------------------------------------------------
                // Overall liveness timeout.
                //------------------------------------------------
                if (!result_valid &&
                    (active_count >= (OP_TIMEOUT - 1)))
                  begin

                    rcm_alarm <= 1'b1;
                    rcm_code  <= 4'd6;
                    state     <= RCM_ERROR;

                  end


                //------------------------------------------------
                // Result handling.
                //------------------------------------------------
                else if (result_valid)
                  begin

                    if (round_nr < NUM_ROUNDS)
                      begin

                        rcm_alarm <= 1'b1;
                        rcm_code  <= 4'd4;
                        state     <= RCM_ERROR;

                      end
                    else if (timing_fault_pending)
                      begin

                        //------------------------------------------------
                        // Code 7: round-stage timing inconsistency.
                        //
                        // T03 reaches here because round 5 skipped the
                        // normal CTRL_MAIN/MixColumns clock.
                        //------------------------------------------------
                        rcm_alarm <= 1'b1;
                        rcm_code  <= 4'd7;
                        state     <= RCM_ERROR;

                      end
                    else
                      begin

                        state <= RCM_DONE;

                      end

                  end


                //------------------------------------------------
                // Structural round checks.
                //------------------------------------------------
                else if (first_round_seen &&
                         (round_nr < prev_round_nr))
                  begin

                    rcm_alarm <= 1'b1;
                    rcm_code  <= 4'd1;
                    state     <= RCM_ERROR;

                  end
                else if (first_round_seen &&
                         (round_nr >
                          (prev_round_nr + 4'd1)))
                  begin

                    rcm_alarm <= 1'b1;
                    rcm_code  <= 4'd3;
                    state     <= RCM_ERROR;

                  end
                else if (round_nr > MAX_TERMINAL_ROUND)
                  begin

                    rcm_alarm <= 1'b1;
                    rcm_code  <= 4'd2;
                    state     <= RCM_ERROR;

                  end
                else
                  begin

                    active_count <=
                        active_count + 16'd1;


                    //--------------------------------------------
                    // First non-zero AES round.
                    //--------------------------------------------
                    if (!first_round_seen)
                      begin

                        if (round_nr != 4'd0)
                          begin

                            first_round_seen <= 1'b1;
                            prev_round_nr    <= round_nr;
                            round_hold_count <= 8'd0;

                          end

                      end


                    //--------------------------------------------
                    // Round number changed by exactly +1.
                    //--------------------------------------------
                    else if (round_nr != prev_round_nr)
                      begin

                        //------------------------------------------
                        // A normal main round must not complete
                        // earlier than MIN_ROUND_HOLD samples.
                        //
                        // Do not apply this rule to round 0 or the
                        // terminal/final transition.
                        //------------------------------------------
                        if ((prev_round_nr >= 4'd1) &&
                            (prev_round_nr < NUM_ROUNDS) &&
                            (round_hold_count <
                             MIN_ROUND_HOLD))
                          begin

                            timing_fault_pending <=
                                1'b1;

                          end

                        prev_round_nr <=
                            round_nr;

                        round_hold_count <=
                            8'd0;

                      end


                    //--------------------------------------------
                    // Same round: count residence time.
                    //--------------------------------------------
                    else if (round_hold_count != 8'hff)
                      begin

                        round_hold_count <=
                            round_hold_count + 8'd1;

                      end

                  end

              end


            //---------------------------------------------------
            // DONE
            //---------------------------------------------------
            RCM_DONE:
              begin

                if (next)
                  begin

                    state                <= RCM_WAIT_START;

                    start_wait_count     <= 16'd0;
                    active_count         <= 16'd0;

                    prev_round_nr        <= round_nr;
                    first_round_seen     <= 1'b0;
                    round_hold_count     <= 8'd0;
                    timing_fault_pending <= 1'b0;

                  end
                else if (init)
                  begin

                    state                <= RCM_IDLE;

                    start_wait_count     <= 16'd0;
                    active_count         <= 16'd0;

                    prev_round_nr        <= 4'd0;
                    first_round_seen     <= 1'b0;
                    round_hold_count     <= 8'd0;
                    timing_fault_pending <= 1'b0;

                  end

              end


            //---------------------------------------------------
            // ERROR
            //---------------------------------------------------
            RCM_ERROR:
              begin

                rcm_alarm <= 1'b1;

              end


            //---------------------------------------------------
            // Fail secure.
            //---------------------------------------------------
            default:
              begin

                rcm_alarm <= 1'b1;
                rcm_code  <= 4'd15;
                state     <= RCM_ERROR;

              end

          endcase

        end

    end


endmodule

`default_nettype wire
