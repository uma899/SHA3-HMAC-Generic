`timescale 1ns / 1ps
// ---------------------------------------------------------------------------
// HMAC-SHA3-224/256/384/512 for a 32-bit processor, on top of the pre-padded
// sha3_core (sha3_core_pd.v). Minimum-area version.
//
//   HMAC(K, m) = H( (K' ^ opad) || H( (K' ^ ipad) || m ) )
//
//   What the processor (software) does:
//     * keys longer than the block size are hashed first with the SHA3 core
//       itself (plain SHA3, digest used as the key); the key given here must
//       be <= block size: SHA3-224 36 words, -256 34, -384 26, -512 18
//     * the key is streamed as 32-bit little-endian words, final partial word
//       zero-padded; key_last on the final word; an empty key = one 0 word
//     * the message is SHA3-padded by software (0x06 ... 0x80) into whole
//       blocks, exactly as for sha3_core_pd.v; msg_last on the very last word
//     * the KEY IS SENT TWICE: once before the message and once after it
//       (the wrapper XORs ipad / opad on the fly and zero-fills the block),
//       so no key buffer is needed in hardware
//
//   Sequence:  start(mode) -> key words (key_last) -> message words (msg_last)
//              -> key words again (key_last) -> MAC on out_*.
//   key_ready / msg_ready say when each stream is being accepted; `ready` = idle.
//
//   mode: 0 = SHA3-224, 1 = SHA3-256, 2 = SHA3-384, 3 = SHA3-512.
//   The wrapper itself generates the padding of the outer hash input
//   (inner digest || 0x06 || zeros || 0x80..), and holds only a 16 x 32-bit
//   buffer for the inner digest.
// ---------------------------------------------------------------------------
module hmac_sha3 (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        start,          // 1-cycle pulse, only honoured when ready=1
    input  wire [1:0]  mode,
    output wire        ready,

    input  wire        key_valid,      // key stream (sent twice)
    output wire        key_ready,
    input  wire [31:0] key_data,
    input  wire        key_last,

    input  wire        msg_valid,      // pre-padded message stream
    output wire        msg_ready,
    input  wire [31:0] msg_data,
    input  wire        msg_last,

    output wire        out_valid,
    input  wire        out_ready,
    output wire [31:0] out_data,
    output wire        out_last
);
    localparam [2:0] S_IDLE  = 3'd0,
                     S_KEY   = 3'd1,   // key block (ipad or opad), zero-filled to block size
                     S_MSG   = 3'd2,   // message passthrough
                     S_IHASH = 3'd3,   // capture inner digest
                     S_OMSG  = 3'd4,   // inner digest + generated padding
                     S_OUT   = 3'd5;   // MAC

    reg [2:0]  state;
    reg [1:0]  mode_r;
    reg        ph;                     // 0 = inner (ipad), 1 = outer (opad)
    reg        kdone;                  // key_last seen, now zero-filling
    reg [5:0]  widx;                   // word index inside the block being fed
    reg [3:0]  oidx;                   // inner-digest capture index
    reg [31:0] ibuf [0:15];            // inner digest

    reg [5:0] rate_last;               // block words - 1
    reg [3:0] dig_last;                // digest words - 1
    always @(*) begin
        case (mode_r)
            2'd0:    begin rate_last = 6'd35; dig_last = 4'd6;  end
            2'd1:    begin rate_last = 6'd33; dig_last = 4'd7;  end
            2'd2:    begin rate_last = 6'd25; dig_last = 4'd11; end
            default: begin rate_last = 6'd17; dig_last = 4'd15; end
        endcase
    end

    // ---- sha3_core ----------------------------------------------------------
    reg         c_in_valid, c_in_last, c_out_ready;
    reg  [31:0] c_in_data;
    wire        c_in_ready, c_out_valid, c_out_last;
    wire [31:0] c_out_data;

    sha3_core u_sha3 (
        .clk(clk), .rst_n(rst_n), .mode(mode_r),
        .in_valid(c_in_valid), .in_ready(c_in_ready), .in_data(c_in_data),
        .in_last(c_in_last),
        .out_valid(c_out_valid), .out_ready(c_out_ready),
        .out_data(c_out_data),   .out_last(c_out_last)
    );

    wire [31:0] pad_w = ph ? 32'h5c5c_5c5c : 32'h3636_3636;
    wire [5:0]  dig_w = {2'b00, dig_last} + 6'd1;   // digest words

    always @(*) begin
        c_in_valid  = 1'b0;
        c_in_data   = 32'd0;
        c_in_last   = 1'b0;
        c_out_ready = 1'b0;
        case (state)
            S_KEY: begin
                c_in_valid = kdone | key_valid;
                c_in_data  = (kdone ? 32'd0 : key_data) ^ pad_w;
            end
            S_MSG: begin
                c_in_valid = msg_valid;
                c_in_data  = msg_data;
                c_in_last  = msg_last;
            end
            S_OMSG: begin
                c_in_valid = 1'b1;
                c_in_last  = (widx == rate_last);
                if (widx < dig_w)
                    c_in_data = ibuf[widx[3:0]];          // inner digest words
                else if (widx == dig_w)
                    c_in_data = 32'h0000_0006;            // delimiter right after digest
                else if (widx == rate_last)
                    c_in_data = 32'h8000_0000;            // final pad bit
                else
                    c_in_data = 32'd0;
            end
            S_IHASH: c_out_ready = 1'b1;
            S_OUT:   c_out_ready = out_ready;
            default: ;
        endcase
    end

    assign ready     = (state == S_IDLE);
    assign key_ready = (state == S_KEY) & ~kdone & c_in_ready;
    assign msg_ready = (state == S_MSG) & c_in_ready;
    assign out_valid = (state == S_OUT) & c_out_valid;
    assign out_data  = c_out_data;
    assign out_last  = (state == S_OUT) & c_out_last;

    always @(posedge clk)
        if (state == S_IHASH && c_out_valid) ibuf[oidx] <= c_out_data;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state  <= S_IDLE;
            mode_r <= 2'd0;
            ph     <= 1'b0;
            kdone  <= 1'b0;
            widx   <= 6'd0;
            oidx   <= 4'd0;
        end else begin
            case (state)
                S_IDLE: if (start) begin
                    mode_r <= mode;
                    ph     <= 1'b0;
                    kdone  <= 1'b0;
                    widx   <= 6'd0;
                    oidx   <= 4'd0;
                    state  <= S_KEY;
                end

                S_KEY: if (c_in_valid & c_in_ready) begin
                    if (widx == rate_last) begin            // block complete
                        widx  <= 6'd0;
                        kdone <= 1'b0;
                        state <= ph ? S_OMSG : S_MSG;
                    end else begin
                        widx <= widx + 6'd1;
                        if (!kdone & key_last) kdone <= 1'b1;
                    end
                end

                S_MSG: if (msg_valid & c_in_ready & msg_last) begin
                    ph    <= 1'b1;
                    state <= S_IHASH;
                end

                S_IHASH: if (c_out_valid) begin
                    if (c_out_last) begin
                        oidx  <= 4'd0;
                        state <= S_KEY;
                    end else
                        oidx <= oidx + 4'd1;
                end

                S_OMSG: if (c_in_ready) begin
                    if (widx == rate_last) begin
                        widx  <= 6'd0;
                        state <= S_OUT;
                    end else
                        widx <= widx + 6'd1;
                end

                S_OUT: if (out_valid & out_ready & out_last)
                    state <= S_IDLE;

                default: state <= S_IDLE;
            endcase
        end
    end
endmodule
