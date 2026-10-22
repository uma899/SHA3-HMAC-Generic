`timescale 1ns / 1ps
// ---------------------------------------------------------------------------
// SHA3-224 / 256 / 384 / 512 core for PRE-PADDED input, 32-bit stream interface
// (minimum-area version for use behind a 32-bit processor)
//
//   The caller (processor / software) applies SHA3 padding itself, so the
//   message it streams is a whole number of blocks:
//        block size (words): SHA3-224 = 36, -256 = 34, -384 = 26, -512 = 18
//   padding = 0x06 byte right after the message, zeros, 0x80 in the last byte
//   of the last block (i.e. 0x80000000 in the final little-endian word; if the
//   message ends 1 byte short of a block boundary, that byte is 0x86).
//
//   Handshake: in_valid/in_ready on 32-bit words, little-endian byte order.
//   in_last = 1 on the very last word of the very last block. Then the digest
//   is streamed on out_valid/out_ready/out_data (out_last on final word):
//        words: SHA3-224 = 7, -256 = 8, -384 = 12, -512 = 16
//   `mode` (0=224, 1=256, 2=384, 3=512) must be stable from the first word
//   until in_last has been accepted.
//
//   Hardware savings vs. the general core (sha3_core.v):
//     * no byte masking / delimiter / 0x80 logic / last-bytes port / pad FSM
//     * the 36 rate words form ONE rotating ring (single 32-bit XOR at the
//       head instead of 36 x 32 XOR + enables); every block is full, so the
//       ring is always realigned after a block: no latency penalty at all
//     * first block overwrites the rate words instead of XORing, so words
//       0..17 (always rate) need no state clear
//     * digest read from a fixed word while the ring shifts: no output mux
// ---------------------------------------------------------------------------
module sha3_core (
    input  wire        clk,
    input  wire        rst_n,

    input  wire [1:0]  mode,

    input  wire        in_valid,
    output wire        in_ready,
    input  wire [31:0] in_data,
    input  wire        in_last,      // last word of last block

    output wire        out_valid,
    input  wire        out_ready,
    output wire [31:0] out_data,
    output wire        out_last
);
    localparam [2:0] S_CLR  = 3'd0,   // zero capacity words (also entered from reset)
                     S_IDLE = 3'd1,   // waiting for first word of a message
                     S_ABS  = 3'd2,   // absorbing words
                     S_PERM = 3'd3,   // 24 rounds
                     S_OUT  = 3'd4;   // stream digest

    reg [2:0]    state;
    reg          fin;            // after the permutation go to S_OUT (last block)
    reg          first;          // first block of the message: overwrite, don't XOR
    reg [5:0]    cnt;            // word index in block (ABS), round (PERM), digest word (OUT)
    reg [1:0]    mode_q;
    reg [1599:0] st;             // the one and only Keccak state

    // ---- per-mode constants ------------------------------------------------
    wire [1:0] mode_c = (state == S_IDLE) ? mode : mode_q;

    reg [5:0] last_w;            // block words - 1
    reg [3:0] dig_last;          // digest words - 1
    always @(*) begin
        case (mode_c)
            2'd0:    begin last_w = 6'd35; dig_last = 4'd6;  end
            2'd1:    begin last_w = 6'd33; dig_last = 4'd7;  end
            2'd2:    begin last_w = 6'd25; dig_last = 4'd11; end
            default: begin last_w = 6'd17; dig_last = 4'd15; end
        endcase
    end

    assign in_ready = (state == S_IDLE) | (state == S_ABS);
    wire   in_fire  = in_valid & in_ready;
    wire   at_last  = (cnt == last_w);

    // ---- state register + round -------------------------------------------
    wire clr     = (state == S_CLR);
    wire perm_en = (state == S_PERM);
    wire rot_en  = in_fire | ((state == S_OUT) & out_ready);
    wire [1599:0] rnd;

    keccak_round u_round (.state_in(st), .round(cnt[4:0]), .state_out(rnd));

    // word entering the ring head: old word 0 (dropped on the first block) ^ input.
    // (in S_OUT the value is don't-care: the state is cleared / overwritten later)
    wire [31:0] head_in = (st[31:0] & {32{~first}}) ^ in_data;

    genvar w;
    generate
        for (w = 0; w < 50; w = w + 1) begin : g_st
            if (w < 36) begin : g_rate
                wire is_head = (last_w == w);
                wire in_ring = (w <= last_w);                  // constant 1 for w < 18
                wire [31:0] rot_val = is_head ? head_in
                                    : st[32*((w+1) % 50) +: 32];
                if (w < 18) begin : g_nclr                     // always rate: no clear needed
                    always @(posedge clk)
                        if      (perm_en)            st[32*w +: 32] <= rnd[32*w +: 32];
                        else if (rot_en && in_ring)  st[32*w +: 32] <= rot_val;
                end else begin : g_clr
                    always @(posedge clk)
                        if      (clr)                st[32*w +: 32] <= 32'd0;
                        else if (perm_en)            st[32*w +: 32] <= rnd[32*w +: 32];
                        else if (rot_en && in_ring)  st[32*w +: 32] <= rot_val;
                end
            end else begin : g_cap                // capacity-only words
                always @(posedge clk)
                    if      (clr)       st[32*w +: 32] <= 32'd0;
                    else if (perm_en)   st[32*w +: 32] <= rnd[32*w +: 32];
            end
        end
    endgenerate

    // ---- output (word 0 of the shifting ring) ------------------------------
    assign out_valid = (state == S_OUT);
    assign out_data  = st[31:0];
    assign out_last  = (cnt[3:0] == dig_last);

    // ---- control FSM -------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state  <= S_CLR;
            fin    <= 1'b0;
            first  <= 1'b1;
            cnt    <= 6'd0;
            mode_q <= 2'd0;
        end else begin
            case (state)
                S_CLR: begin
                    cnt   <= 6'd0;
                    first <= 1'b1;
                    state <= S_IDLE;
                end

                S_IDLE, S_ABS: if (in_valid) begin
                    if (state == S_IDLE) mode_q <= mode;
                    state <= S_ABS;
                    if (at_last) begin
                        fin   <= in_last;
                        first <= 1'b0;
                        state <= S_PERM;
                        cnt   <= 6'd0;
                    end else begin
                        cnt <= cnt + 6'd1;
                    end
                end

                S_PERM: begin
                    if (cnt == 6'd23) begin
                        cnt   <= 6'd0;
                        state <= fin ? S_OUT : S_ABS;
                    end else begin
                        cnt <= cnt + 6'd1;
                    end
                end

                S_OUT: if (out_ready) begin
                    if (out_last) state <= S_CLR;
                    else          cnt   <= cnt + 6'd1;
                end

                default: state <= S_CLR;
            endcase
        end
    end
endmodule
