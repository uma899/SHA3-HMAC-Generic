`timescale 1ns / 1ps
// ---------------------------------------------------------------------------
// One Keccak-f[1600] round (theta, rho, pi, chi, iota) - purely combinational.
// Lane (x,y) is state[64*(x+5*y) +: 64].
// ---------------------------------------------------------------------------
module keccak_round (
    input  wire [1599:0] state_in,
    input  wire [4:0]    round,
    output wire [1599:0] state_out
);
    // rho rotation offsets, indexed by lane = x + 5*y
    function integer rho;
        input integer lane;
        begin
            case (lane)
                 0: rho =  0;  1: rho =  1;  2: rho = 62;  3: rho = 28;  4: rho = 27;
                 5: rho = 36;  6: rho = 44;  7: rho =  6;  8: rho = 55;  9: rho = 20;
                10: rho =  3; 11: rho = 10; 12: rho = 43; 13: rho = 25; 14: rho = 39;
                15: rho = 41; 16: rho = 45; 17: rho = 15; 18: rho = 21; 19: rho =  8;
                20: rho = 18; 21: rho =  2; 22: rho = 61; 23: rho = 56; 24: rho = 14;
                default: rho = 0;
            endcase
        end
    endfunction

    genvar x, y;

    // ---- theta ------------------------------------------------------------
    wire [319:0] C, D;
    generate
        for (x = 0; x < 5; x = x + 1) begin : g_c
            assign C[64*x +: 64] = state_in[64*(x     ) +: 64]
                                 ^ state_in[64*(x +  5) +: 64]
                                 ^ state_in[64*(x + 10) +: 64]
                                 ^ state_in[64*(x + 15) +: 64]
                                 ^ state_in[64*(x + 20) +: 64];
        end
        for (x = 0; x < 5; x = x + 1) begin : g_d
            wire [63:0] cn = C[64*((x+1)%5) +: 64];
            assign D[64*x +: 64] = C[64*((x+4)%5) +: 64] ^ {cn[62:0], cn[63]};
        end
    endgenerate

    // ---- rho + pi  (theta's  A ^ D  folded in) ----------------------------
    wire [1599:0] B;
    generate
        for (x = 0; x < 5; x = x + 1) begin : g_x
            for (y = 0; y < 5; y = y + 1) begin : g_y
                localparam integer R = rho(x + 5*y);
                wire [63:0] a  = state_in[64*(x + 5*y) +: 64] ^ D[64*x +: 64];
                wire [63:0] ro = (a << R) | (a >> (64 - R));
                assign B[64*(y + 5*((2*x + 3*y) % 5)) +: 64] = ro;
            end
        end
    endgenerate

    // ---- chi --------------------------------------------------------------
    wire [1599:0] X;
    generate
        for (x = 0; x < 5; x = x + 1) begin : g_cx
            for (y = 0; y < 5; y = y + 1) begin : g_cy
                assign X[64*(x + 5*y) +: 64] =
                       B[64*(x + 5*y) +: 64]
                     ^ (~B[64*(((x+1)%5) + 5*y) +: 64] & B[64*(((x+2)%5) + 5*y) +: 64]);
            end
        end
    endgenerate

    // ---- iota -------------------------------------------------------------
    wire [63:0] RC;
    round_constant u_rc (.round(round), .RC(RC));

    assign state_out = {X[1599:64], X[63:0] ^ RC};
endmodule
