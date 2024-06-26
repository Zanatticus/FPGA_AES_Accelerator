// ==============================================================
// RTL generated by Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
// Version: 2022.1
// Copyright (C) Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// 
// ===========================================================

`timescale 1 ns / 1 ps 

module aes_aes_round (
        ap_clk,
        ap_rst,
        ap_start,
        ap_done,
        ap_idle,
        ap_ready,
        state_address0,
        state_ce0,
        state_we0,
        state_d0,
        state_q0,
        state_address1,
        state_ce1,
        state_we1,
        state_d1,
        state_q1,
        roundKey_address0,
        roundKey_ce0,
        roundKey_q0,
        grp_galois_multiplication_fu_626_p_din1,
        grp_galois_multiplication_fu_626_p_din2,
        grp_galois_multiplication_fu_626_p_dout0,
        grp_galois_multiplication_fu_626_p_ready,
        grp_galois_multiplication_fu_631_p_din1,
        grp_galois_multiplication_fu_631_p_din2,
        grp_galois_multiplication_fu_631_p_dout0,
        grp_galois_multiplication_fu_631_p_ready,
        grp_galois_multiplication_fu_636_p_din1,
        grp_galois_multiplication_fu_636_p_din2,
        grp_galois_multiplication_fu_636_p_dout0,
        grp_galois_multiplication_fu_636_p_ready
);

parameter    ap_ST_fsm_state1 = 10'd1;
parameter    ap_ST_fsm_state2 = 10'd2;
parameter    ap_ST_fsm_state3 = 10'd4;
parameter    ap_ST_fsm_state4 = 10'd8;
parameter    ap_ST_fsm_state5 = 10'd16;
parameter    ap_ST_fsm_state6 = 10'd32;
parameter    ap_ST_fsm_state7 = 10'd64;
parameter    ap_ST_fsm_state8 = 10'd128;
parameter    ap_ST_fsm_state9 = 10'd256;
parameter    ap_ST_fsm_state10 = 10'd512;

input   ap_clk;
input   ap_rst;
input   ap_start;
output   ap_done;
output   ap_idle;
output   ap_ready;
output  [3:0] state_address0;
output   state_ce0;
output   state_we0;
output  [7:0] state_d0;
input  [7:0] state_q0;
output  [3:0] state_address1;
output   state_ce1;
output   state_we1;
output  [7:0] state_d1;
input  [7:0] state_q1;
output  [3:0] roundKey_address0;
output   roundKey_ce0;
input  [7:0] roundKey_q0;
output  [7:0] grp_galois_multiplication_fu_626_p_din1;
output  [3:0] grp_galois_multiplication_fu_626_p_din2;
input  [7:0] grp_galois_multiplication_fu_626_p_dout0;
input   grp_galois_multiplication_fu_626_p_ready;
output  [7:0] grp_galois_multiplication_fu_631_p_din1;
output  [3:0] grp_galois_multiplication_fu_631_p_din2;
input  [7:0] grp_galois_multiplication_fu_631_p_dout0;
input   grp_galois_multiplication_fu_631_p_ready;
output  [7:0] grp_galois_multiplication_fu_636_p_din1;
output  [3:0] grp_galois_multiplication_fu_636_p_din2;
input  [7:0] grp_galois_multiplication_fu_636_p_dout0;
input   grp_galois_multiplication_fu_636_p_ready;

reg ap_done;
reg ap_idle;
reg ap_ready;
reg[3:0] state_address0;
reg state_ce0;
reg state_we0;
reg[7:0] state_d0;
reg[3:0] state_address1;
reg state_ce1;
reg state_we1;
reg[7:0] state_d1;

(* fsm_encoding = "none" *) reg   [9:0] ap_CS_fsm;
wire    ap_CS_fsm_state1;
wire   [2:0] i_5_fu_194_p2;
reg   [2:0] i_5_reg_286;
wire    ap_CS_fsm_state3;
wire   [3:0] shl_ln_fu_204_p3;
reg   [3:0] shl_ln_reg_291;
wire   [0:0] icmp_ln285_fu_188_p2;
reg   [3:0] state_addr_1_reg_297;
wire   [0:0] icmp_ln296_fu_217_p2;
reg   [0:0] icmp_ln296_reg_302;
reg   [3:0] state_addr_reg_306;
reg   [3:0] state_addr_4_reg_311;
wire    ap_CS_fsm_state4;
reg   [3:0] state_addr_5_reg_316;
reg   [7:0] state_load_4_reg_321;
reg   [7:0] state_load_reg_326;
wire    ap_CS_fsm_state5;
wire   [1:0] add_ln296_fu_263_p2;
wire    ap_CS_fsm_state6;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_done;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_idle;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_ready;
wire   [3:0] grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address0;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce0;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_we0;
wire   [7:0] grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_d0;
wire   [3:0] grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address1;
wire    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce1;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_done;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_idle;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_ready;
wire   [3:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address0;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce0;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we0;
wire   [7:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d0;
wire   [3:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address1;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce1;
wire    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we1;
wire   [7:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d1;
wire   [7:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din1;
wire   [3:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din2;
wire   [7:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din1;
wire   [3:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din2;
wire   [7:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din1;
wire   [3:0] grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din2;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_idle;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_ready;
wire   [3:0] grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address0;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce0;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_we0;
wire   [7:0] grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_d0;
wire   [3:0] grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address1;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce1;
wire   [3:0] grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_address0;
wire    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_ce0;
reg   [1:0] i_3_reg_99;
wire   [0:0] icmp_ln296_1_fu_258_p2;
reg   [7:0] empty_40_reg_110;
reg   [7:0] empty_41_reg_121;
reg   [7:0] empty_42_reg_133;
reg   [7:0] tmp_reg_145;
reg    grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg;
wire    ap_CS_fsm_state2;
reg    grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg;
wire    ap_CS_fsm_state8;
reg    grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg;
wire    ap_CS_fsm_state9;
wire    ap_CS_fsm_state10;
wire   [63:0] zext_ln287_fu_212_p1;
wire   [63:0] zext_ln300_fu_229_p1;
wire   [63:0] add_ptr_i_sum2015_cast_fu_239_p1;
wire   [63:0] add_ptr_i_sum2216_cast_fu_249_p1;
reg   [2:0] i_1_fu_54;
wire    ap_CS_fsm_state7;
wire   [1:0] trunc_ln287_fu_200_p1;
wire   [3:0] or_ln300_fu_223_p2;
wire   [3:0] add_ptr_i_sum2015_fu_234_p2;
wire   [3:0] add_ptr_i_sum2216_fu_244_p2;
wire   [2:0] zext_ln296_fu_254_p1;
reg   [9:0] ap_NS_fsm;
reg    ap_ST_fsm_state1_blk;
reg    ap_ST_fsm_state2_blk;
wire    ap_ST_fsm_state3_blk;
wire    ap_ST_fsm_state4_blk;
wire    ap_ST_fsm_state5_blk;
wire    ap_ST_fsm_state6_blk;
wire    ap_ST_fsm_state7_blk;
reg    ap_ST_fsm_state8_blk;
wire    ap_ST_fsm_state9_blk;
reg    ap_ST_fsm_state10_blk;
wire    ap_ce_reg;

// power-on initialization
initial begin
#0 ap_CS_fsm = 10'd1;
#0 grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg = 1'b0;
#0 grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg = 1'b0;
#0 grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg = 1'b0;
end

aes_aes_round_Pipeline_VITIS_LOOP_276_1 grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst),
    .ap_start(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start),
    .ap_done(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_done),
    .ap_idle(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_idle),
    .ap_ready(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_ready),
    .state_address0(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address0),
    .state_ce0(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce0),
    .state_we0(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_we0),
    .state_d0(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_d0),
    .state_address1(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address1),
    .state_ce1(grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce1),
    .state_q1(state_q1)
);

aes_aes_round_Pipeline_mixColumnsLoop grp_aes_round_Pipeline_mixColumnsLoop_fu_166(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst),
    .ap_start(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start),
    .ap_done(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_done),
    .ap_idle(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_idle),
    .ap_ready(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_ready),
    .state_address0(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address0),
    .state_ce0(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce0),
    .state_we0(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we0),
    .state_d0(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d0),
    .state_q0(state_q0),
    .state_address1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address1),
    .state_ce1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce1),
    .state_we1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we1),
    .state_d1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d1),
    .state_q1(state_q1),
    .grp_galois_multiplication_fu_349_p_din1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din1),
    .grp_galois_multiplication_fu_349_p_din2(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din2),
    .grp_galois_multiplication_fu_349_p_dout0(grp_galois_multiplication_fu_626_p_dout0),
    .grp_galois_multiplication_fu_349_p_ready(grp_galois_multiplication_fu_626_p_ready),
    .grp_galois_multiplication_fu_354_p_din1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din1),
    .grp_galois_multiplication_fu_354_p_din2(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din2),
    .grp_galois_multiplication_fu_354_p_dout0(grp_galois_multiplication_fu_631_p_dout0),
    .grp_galois_multiplication_fu_354_p_ready(grp_galois_multiplication_fu_631_p_ready),
    .grp_galois_multiplication_fu_359_p_din1(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din1),
    .grp_galois_multiplication_fu_359_p_din2(grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din2),
    .grp_galois_multiplication_fu_359_p_dout0(grp_galois_multiplication_fu_636_p_dout0),
    .grp_galois_multiplication_fu_359_p_ready(grp_galois_multiplication_fu_636_p_ready)
);

aes_aes_round_Pipeline_VITIS_LOOP_308_1 grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst),
    .ap_start(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start),
    .ap_done(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done),
    .ap_idle(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_idle),
    .ap_ready(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_ready),
    .state_address0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address0),
    .state_ce0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce0),
    .state_we0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_we0),
    .state_d0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_d0),
    .state_address1(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address1),
    .state_ce1(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce1),
    .state_q1(state_q1),
    .roundKey_address0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_address0),
    .roundKey_ce0(grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_ce0),
    .roundKey_q0(roundKey_q0)
);

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_CS_fsm <= ap_ST_fsm_state1;
    end else begin
        ap_CS_fsm <= ap_NS_fsm;
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg <= 1'b0;
    end else begin
        if (((1'b1 == ap_CS_fsm_state1) & (ap_start == 1'b1))) begin
            grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg <= 1'b1;
        end else if ((grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_ready == 1'b1)) begin
            grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg <= 1'b0;
        end
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg <= 1'b0;
    end else begin
        if ((1'b1 == ap_CS_fsm_state9)) begin
            grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg <= 1'b1;
        end else if ((grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_ready == 1'b1)) begin
            grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg <= 1'b0;
        end
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg <= 1'b0;
    end else begin
        if (((icmp_ln285_fu_188_p2 == 1'd1) & (1'b1 == ap_CS_fsm_state3))) begin
            grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg <= 1'b1;
        end else if ((grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_ready == 1'b1)) begin
            grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg <= 1'b0;
        end
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state5)) begin
        empty_40_reg_110 <= state_q0;
    end else if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
        empty_40_reg_110 <= tmp_reg_145;
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state5)) begin
        empty_41_reg_121 <= state_q1;
    end else if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
        empty_41_reg_121 <= empty_40_reg_110;
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state5)) begin
        empty_42_reg_133 <= state_load_reg_326;
    end else if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
        empty_42_reg_133 <= empty_41_reg_121;
    end
end

always @ (posedge ap_clk) begin
    if (((1'b1 == ap_CS_fsm_state1) & (ap_start == 1'b1))) begin
        i_1_fu_54 <= 3'd0;
    end else if ((1'b1 == ap_CS_fsm_state7)) begin
        i_1_fu_54 <= i_5_reg_286;
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state5)) begin
        i_3_reg_99 <= 2'd0;
    end else if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
        i_3_reg_99 <= add_ln296_fu_263_p2;
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state5)) begin
        tmp_reg_145 <= state_load_4_reg_321;
    end else if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
        tmp_reg_145 <= empty_42_reg_133;
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state3)) begin
        i_5_reg_286 <= i_5_fu_194_p2;
    end
end

always @ (posedge ap_clk) begin
    if (((icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
        icmp_ln296_reg_302 <= icmp_ln296_fu_217_p2;
        shl_ln_reg_291[3 : 2] <= shl_ln_fu_204_p3[3 : 2];
        state_addr_1_reg_297[3 : 2] <= zext_ln287_fu_212_p1[3 : 2];
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_CS_fsm_state4)) begin
        state_addr_4_reg_311[3 : 2] <= add_ptr_i_sum2015_cast_fu_239_p1[3 : 2];
        state_addr_5_reg_316[3 : 2] <= add_ptr_i_sum2216_cast_fu_249_p1[3 : 2];
        state_load_4_reg_321 <= state_q1;
        state_load_reg_326 <= state_q0;
    end
end

always @ (posedge ap_clk) begin
    if (((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
        state_addr_reg_306[3 : 2] <= zext_ln300_fu_229_p1[3 : 2];
    end
end

always @ (*) begin
    if ((grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done == 1'b0)) begin
        ap_ST_fsm_state10_blk = 1'b1;
    end else begin
        ap_ST_fsm_state10_blk = 1'b0;
    end
end

always @ (*) begin
    if ((ap_start == 1'b0)) begin
        ap_ST_fsm_state1_blk = 1'b1;
    end else begin
        ap_ST_fsm_state1_blk = 1'b0;
    end
end

always @ (*) begin
    if ((grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_done == 1'b0)) begin
        ap_ST_fsm_state2_blk = 1'b1;
    end else begin
        ap_ST_fsm_state2_blk = 1'b0;
    end
end

assign ap_ST_fsm_state3_blk = 1'b0;

assign ap_ST_fsm_state4_blk = 1'b0;

assign ap_ST_fsm_state5_blk = 1'b0;

assign ap_ST_fsm_state6_blk = 1'b0;

assign ap_ST_fsm_state7_blk = 1'b0;

always @ (*) begin
    if ((grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_done == 1'b0)) begin
        ap_ST_fsm_state8_blk = 1'b1;
    end else begin
        ap_ST_fsm_state8_blk = 1'b0;
    end
end

assign ap_ST_fsm_state9_blk = 1'b0;

always @ (*) begin
    if ((((1'b1 == ap_CS_fsm_state1) & (ap_start == 1'b0)) | ((1'b1 == ap_CS_fsm_state10) & (grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done == 1'b1)))) begin
        ap_done = 1'b1;
    end else begin
        ap_done = 1'b0;
    end
end

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state1) & (ap_start == 1'b0))) begin
        ap_idle = 1'b1;
    end else begin
        ap_idle = 1'b0;
    end
end

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state10) & (grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done == 1'b1))) begin
        ap_ready = 1'b1;
    end else begin
        ap_ready = 1'b0;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state7)) begin
        state_address0 = state_addr_5_reg_316;
    end else if ((1'b1 == ap_CS_fsm_state6)) begin
        state_address0 = state_addr_reg_306;
    end else if ((1'b1 == ap_CS_fsm_state4)) begin
        state_address0 = add_ptr_i_sum2216_cast_fu_249_p1;
    end else if (((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
        state_address0 = zext_ln300_fu_229_p1;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_address0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address0;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_address0 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address0;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_address0 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address0;
    end else begin
        state_address0 = 'bx;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state7)) begin
        state_address1 = state_addr_4_reg_311;
    end else if ((1'b1 == ap_CS_fsm_state6)) begin
        state_address1 = state_addr_1_reg_297;
    end else if ((1'b1 == ap_CS_fsm_state4)) begin
        state_address1 = add_ptr_i_sum2015_cast_fu_239_p1;
    end else if (((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
        state_address1 = zext_ln287_fu_212_p1;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_address1 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_address1;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_address1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_address1;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_address1 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_address1;
    end else begin
        state_address1 = 'bx;
    end
end

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state6) | (1'b1 == ap_CS_fsm_state4) | (1'b1 == ap_CS_fsm_state7) | ((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3)))) begin
        state_ce0 = 1'b1;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_ce0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce0;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_ce0 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce0;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_ce0 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce0;
    end else begin
        state_ce0 = 1'b0;
    end
end

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state6) | (1'b1 == ap_CS_fsm_state4) | (1'b1 == ap_CS_fsm_state7) | ((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3)))) begin
        state_ce1 = 1'b1;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_ce1 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_ce1;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_ce1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_ce1;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_ce1 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_ce1;
    end else begin
        state_ce1 = 1'b0;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state7)) begin
        state_d0 = empty_40_reg_110;
    end else if ((1'b1 == ap_CS_fsm_state6)) begin
        state_d0 = empty_42_reg_133;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_d0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_d0;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_d0 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d0;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_d0 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_d0;
    end else begin
        state_d0 = 'bx;
    end
end

always @ (*) begin
    if ((1'b1 == ap_CS_fsm_state7)) begin
        state_d1 = empty_41_reg_121;
    end else if ((1'b1 == ap_CS_fsm_state6)) begin
        state_d1 = tmp_reg_145;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_d1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_d1;
    end else begin
        state_d1 = 'bx;
    end
end

always @ (*) begin
    if ((((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd1)) | ((icmp_ln296_reg_302 == 1'd0) & (1'b1 == ap_CS_fsm_state7)))) begin
        state_we0 = 1'b1;
    end else if ((1'b1 == ap_CS_fsm_state10)) begin
        state_we0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_state_we0;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_we0 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we0;
    end else if ((1'b1 == ap_CS_fsm_state2)) begin
        state_we0 = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_state_we0;
    end else begin
        state_we0 = 1'b0;
    end
end

always @ (*) begin
    if ((((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd1)) | ((icmp_ln296_reg_302 == 1'd0) & (1'b1 == ap_CS_fsm_state7)))) begin
        state_we1 = 1'b1;
    end else if ((1'b1 == ap_CS_fsm_state8)) begin
        state_we1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_state_we1;
    end else begin
        state_we1 = 1'b0;
    end
end

always @ (*) begin
    case (ap_CS_fsm)
        ap_ST_fsm_state1 : begin
            if (((1'b1 == ap_CS_fsm_state1) & (ap_start == 1'b1))) begin
                ap_NS_fsm = ap_ST_fsm_state2;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state1;
            end
        end
        ap_ST_fsm_state2 : begin
            if (((grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_done == 1'b1) & (1'b1 == ap_CS_fsm_state2))) begin
                ap_NS_fsm = ap_ST_fsm_state3;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state2;
            end
        end
        ap_ST_fsm_state3 : begin
            if (((icmp_ln296_fu_217_p2 == 1'd1) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
                ap_NS_fsm = ap_ST_fsm_state7;
            end else if (((icmp_ln296_fu_217_p2 == 1'd0) & (icmp_ln285_fu_188_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state3))) begin
                ap_NS_fsm = ap_ST_fsm_state4;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state8;
            end
        end
        ap_ST_fsm_state4 : begin
            ap_NS_fsm = ap_ST_fsm_state5;
        end
        ap_ST_fsm_state5 : begin
            ap_NS_fsm = ap_ST_fsm_state6;
        end
        ap_ST_fsm_state6 : begin
            if (((1'b1 == ap_CS_fsm_state6) & (icmp_ln296_1_fu_258_p2 == 1'd0))) begin
                ap_NS_fsm = ap_ST_fsm_state6;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state7;
            end
        end
        ap_ST_fsm_state7 : begin
            ap_NS_fsm = ap_ST_fsm_state3;
        end
        ap_ST_fsm_state8 : begin
            if (((1'b1 == ap_CS_fsm_state8) & (grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_done == 1'b1))) begin
                ap_NS_fsm = ap_ST_fsm_state9;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state8;
            end
        end
        ap_ST_fsm_state9 : begin
            ap_NS_fsm = ap_ST_fsm_state10;
        end
        ap_ST_fsm_state10 : begin
            if (((1'b1 == ap_CS_fsm_state10) & (grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_done == 1'b1))) begin
                ap_NS_fsm = ap_ST_fsm_state1;
            end else begin
                ap_NS_fsm = ap_ST_fsm_state10;
            end
        end
        default : begin
            ap_NS_fsm = 'bx;
        end
    endcase
end

assign add_ln296_fu_263_p2 = (i_3_reg_99 + 2'd1);

assign add_ptr_i_sum2015_cast_fu_239_p1 = add_ptr_i_sum2015_fu_234_p2;

assign add_ptr_i_sum2015_fu_234_p2 = (shl_ln_reg_291 | 4'd2);

assign add_ptr_i_sum2216_cast_fu_249_p1 = add_ptr_i_sum2216_fu_244_p2;

assign add_ptr_i_sum2216_fu_244_p2 = (shl_ln_reg_291 | 4'd3);

assign ap_CS_fsm_state1 = ap_CS_fsm[32'd0];

assign ap_CS_fsm_state10 = ap_CS_fsm[32'd9];

assign ap_CS_fsm_state2 = ap_CS_fsm[32'd1];

assign ap_CS_fsm_state3 = ap_CS_fsm[32'd2];

assign ap_CS_fsm_state4 = ap_CS_fsm[32'd3];

assign ap_CS_fsm_state5 = ap_CS_fsm[32'd4];

assign ap_CS_fsm_state6 = ap_CS_fsm[32'd5];

assign ap_CS_fsm_state7 = ap_CS_fsm[32'd6];

assign ap_CS_fsm_state8 = ap_CS_fsm[32'd7];

assign ap_CS_fsm_state9 = ap_CS_fsm[32'd8];

assign grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start = grp_aes_round_Pipeline_VITIS_LOOP_276_1_fu_158_ap_start_reg;

assign grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_ap_start_reg;

assign grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_ap_start_reg;

assign grp_galois_multiplication_fu_626_p_din1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din1;

assign grp_galois_multiplication_fu_626_p_din2 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_349_p_din2;

assign grp_galois_multiplication_fu_631_p_din1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din1;

assign grp_galois_multiplication_fu_631_p_din2 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_354_p_din2;

assign grp_galois_multiplication_fu_636_p_din1 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din1;

assign grp_galois_multiplication_fu_636_p_din2 = grp_aes_round_Pipeline_mixColumnsLoop_fu_166_grp_galois_multiplication_fu_359_p_din2;

assign i_5_fu_194_p2 = (i_1_fu_54 + 3'd1);

assign icmp_ln285_fu_188_p2 = ((i_1_fu_54 == 3'd4) ? 1'b1 : 1'b0);

assign icmp_ln296_1_fu_258_p2 = ((zext_ln296_fu_254_p1 == i_1_fu_54) ? 1'b1 : 1'b0);

assign icmp_ln296_fu_217_p2 = ((trunc_ln287_fu_200_p1 == 2'd0) ? 1'b1 : 1'b0);

assign or_ln300_fu_223_p2 = (shl_ln_fu_204_p3 | 4'd1);

assign roundKey_address0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_address0;

assign roundKey_ce0 = grp_aes_round_Pipeline_VITIS_LOOP_308_1_fu_172_roundKey_ce0;

assign shl_ln_fu_204_p3 = {{trunc_ln287_fu_200_p1}, {2'd0}};

assign trunc_ln287_fu_200_p1 = i_1_fu_54[1:0];

assign zext_ln287_fu_212_p1 = shl_ln_fu_204_p3;

assign zext_ln296_fu_254_p1 = i_3_reg_99;

assign zext_ln300_fu_229_p1 = or_ln300_fu_223_p2;

always @ (posedge ap_clk) begin
    shl_ln_reg_291[1:0] <= 2'b00;
    state_addr_1_reg_297[1:0] <= 2'b00;
    state_addr_reg_306[1:0] <= 2'b01;
    state_addr_4_reg_311[1:0] <= 2'b10;
    state_addr_5_reg_316[1:0] <= 2'b11;
end

endmodule //aes_aes_round
