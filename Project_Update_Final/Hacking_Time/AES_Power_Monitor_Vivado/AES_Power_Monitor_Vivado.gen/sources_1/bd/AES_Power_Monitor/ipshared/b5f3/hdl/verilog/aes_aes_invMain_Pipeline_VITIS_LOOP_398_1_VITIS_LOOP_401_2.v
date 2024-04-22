// ==============================================================
// RTL generated by Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
// Version: 2022.1
// Copyright (C) Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// 
// ===========================================================

`timescale 1 ns / 1 ps 

module aes_aes_invMain_Pipeline_VITIS_LOOP_398_1_VITIS_LOOP_401_2 (
        ap_clk,
        ap_rst,
        ap_start,
        ap_done,
        ap_idle,
        ap_ready,
        expandedKey_address0,
        expandedKey_ce0,
        expandedKey_q0,
        roundKey_address0,
        roundKey_ce0,
        roundKey_we0,
        roundKey_d0
);

parameter    ap_ST_fsm_pp0_stage0 = 1'd1;

input   ap_clk;
input   ap_rst;
input   ap_start;
output   ap_done;
output   ap_idle;
output   ap_ready;
output  [7:0] expandedKey_address0;
output   expandedKey_ce0;
input  [7:0] expandedKey_q0;
output  [3:0] roundKey_address0;
output   roundKey_ce0;
output   roundKey_we0;
output  [7:0] roundKey_d0;

reg ap_idle;
reg expandedKey_ce0;
reg roundKey_ce0;
reg roundKey_we0;

(* fsm_encoding = "none" *) reg   [0:0] ap_CS_fsm;
wire    ap_CS_fsm_pp0_stage0;
wire    ap_enable_reg_pp0_iter0;
reg    ap_enable_reg_pp0_iter1;
reg    ap_enable_reg_pp0_iter2;
reg    ap_idle_pp0;
wire    ap_block_state1_pp0_stage0_iter0;
wire    ap_block_state2_pp0_stage0_iter1;
wire    ap_block_state3_pp0_stage0_iter2;
wire    ap_block_pp0_stage0_subdone;
wire   [0:0] icmp_ln398_fu_99_p2;
reg    ap_condition_exit_pp0_iter0_stage0;
wire    ap_loop_exit_ready;
reg    ap_ready_int;
wire    ap_block_pp0_stage0_11001;
wire   [2:0] select_ln398_fu_123_p3;
reg   [2:0] select_ln398_reg_240;
wire   [2:0] select_ln398_2_fu_137_p3;
reg   [2:0] select_ln398_2_reg_245;
wire   [1:0] trunc_ln398_fu_145_p1;
reg   [1:0] trunc_ln398_reg_250;
wire   [1:0] trunc_ln402_fu_149_p1;
reg   [1:0] trunc_ln402_reg_255;
wire   [3:0] add_ln402_3_fu_205_p2;
reg   [3:0] add_ln402_3_reg_265;
wire   [63:0] zext_ln402_fu_193_p1;
wire    ap_block_pp0_stage0;
wire   [63:0] zext_ln402_3_fu_211_p1;
reg   [2:0] j_fu_42;
wire   [2:0] add_ln401_fu_153_p2;
wire    ap_loop_init;
reg   [2:0] ap_sig_allocacmp_j_load;
reg   [2:0] i_fu_46;
reg   [2:0] ap_sig_allocacmp_i_load;
reg   [4:0] indvar_flatten_fu_50;
wire   [4:0] add_ln398_fu_105_p2;
reg   [4:0] ap_sig_allocacmp_indvar_flatten_load;
wire   [0:0] icmp_ln401_fu_117_p2;
wire   [2:0] add_ln398_3_fu_131_p2;
wire   [3:0] j_4_cast_fu_184_p1;
wire   [3:0] p_mid2_fu_177_p3;
wire   [3:0] add_ln402_fu_187_p2;
wire   [3:0] shl_ln402_3_fu_198_p3;
wire   [3:0] zext_ln398_fu_174_p1;
reg    ap_done_reg;
wire    ap_continue_int;
reg    ap_done_int;
reg    ap_loop_exit_ready_pp0_iter1_reg;
reg   [0:0] ap_NS_fsm;
wire    ap_enable_pp0;
wire    ap_start_int;
wire    ap_ce_reg;

// power-on initialization
initial begin
#0 ap_CS_fsm = 1'd1;
#0 ap_enable_reg_pp0_iter1 = 1'b0;
#0 ap_enable_reg_pp0_iter2 = 1'b0;
#0 ap_done_reg = 1'b0;
end

aes_flow_control_loop_pipe_sequential_init flow_control_loop_pipe_sequential_init_U(
    .ap_clk(ap_clk),
    .ap_rst(ap_rst),
    .ap_start(ap_start),
    .ap_ready(ap_ready),
    .ap_done(ap_done),
    .ap_start_int(ap_start_int),
    .ap_loop_init(ap_loop_init),
    .ap_ready_int(ap_ready_int),
    .ap_loop_exit_ready(ap_condition_exit_pp0_iter0_stage0),
    .ap_loop_exit_done(ap_done_int),
    .ap_continue_int(ap_continue_int),
    .ap_done_int(ap_done_int)
);

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_CS_fsm <= ap_ST_fsm_pp0_stage0;
    end else begin
        ap_CS_fsm <= ap_NS_fsm;
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_done_reg <= 1'b0;
    end else begin
        if ((ap_continue_int == 1'b1)) begin
            ap_done_reg <= 1'b0;
        end else if (((1'b0 == ap_block_pp0_stage0_subdone) & (1'b1 == ap_CS_fsm_pp0_stage0) & (ap_loop_exit_ready_pp0_iter1_reg == 1'b1))) begin
            ap_done_reg <= 1'b1;
        end
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_enable_reg_pp0_iter1 <= 1'b0;
    end else begin
        if ((1'b1 == ap_condition_exit_pp0_iter0_stage0)) begin
            ap_enable_reg_pp0_iter1 <= 1'b0;
        end else if (((1'b0 == ap_block_pp0_stage0_subdone) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
            ap_enable_reg_pp0_iter1 <= ap_start_int;
        end
    end
end

always @ (posedge ap_clk) begin
    if (ap_rst == 1'b1) begin
        ap_enable_reg_pp0_iter2 <= 1'b0;
    end else begin
        if ((1'b0 == ap_block_pp0_stage0_subdone)) begin
            ap_enable_reg_pp0_iter2 <= ap_enable_reg_pp0_iter1;
        end
    end
end

always @ (posedge ap_clk) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        if (((icmp_ln398_fu_99_p2 == 1'd0) & (ap_enable_reg_pp0_iter0 == 1'b1))) begin
            i_fu_46 <= select_ln398_2_fu_137_p3;
        end else if ((ap_loop_init == 1'b1)) begin
            i_fu_46 <= 3'd0;
        end
    end
end

always @ (posedge ap_clk) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        if (((icmp_ln398_fu_99_p2 == 1'd0) & (ap_enable_reg_pp0_iter0 == 1'b1))) begin
            indvar_flatten_fu_50 <= add_ln398_fu_105_p2;
        end else if ((ap_loop_init == 1'b1)) begin
            indvar_flatten_fu_50 <= 5'd0;
        end
    end
end

always @ (posedge ap_clk) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        if (((icmp_ln398_fu_99_p2 == 1'd0) & (ap_enable_reg_pp0_iter0 == 1'b1))) begin
            j_fu_42 <= add_ln401_fu_153_p2;
        end else if ((ap_loop_init == 1'b1)) begin
            j_fu_42 <= 3'd0;
        end
    end
end

always @ (posedge ap_clk) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        add_ln402_3_reg_265 <= add_ln402_3_fu_205_p2;
        ap_loop_exit_ready_pp0_iter1_reg <= ap_loop_exit_ready;
    end
end

always @ (posedge ap_clk) begin
    if (((icmp_ln398_fu_99_p2 == 1'd0) & (1'b0 == ap_block_pp0_stage0_11001) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        select_ln398_2_reg_245 <= select_ln398_2_fu_137_p3;
        select_ln398_reg_240 <= select_ln398_fu_123_p3;
        trunc_ln398_reg_250 <= trunc_ln398_fu_145_p1;
        trunc_ln402_reg_255 <= trunc_ln402_fu_149_p1;
    end
end

always @ (*) begin
    if (((icmp_ln398_fu_99_p2 == 1'd1) & (1'b0 == ap_block_pp0_stage0_subdone) & (ap_enable_reg_pp0_iter0 == 1'b1) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_condition_exit_pp0_iter0_stage0 = 1'b1;
    end else begin
        ap_condition_exit_pp0_iter0_stage0 = 1'b0;
    end
end

always @ (*) begin
    if (((1'b0 == ap_block_pp0_stage0_subdone) & (1'b1 == ap_CS_fsm_pp0_stage0) & (ap_loop_exit_ready_pp0_iter1_reg == 1'b1))) begin
        ap_done_int = 1'b1;
    end else begin
        ap_done_int = ap_done_reg;
    end
end

always @ (*) begin
    if (((ap_idle_pp0 == 1'b1) & (ap_start_int == 1'b0) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_idle = 1'b1;
    end else begin
        ap_idle = 1'b0;
    end
end

always @ (*) begin
    if (((ap_enable_reg_pp0_iter2 == 1'b0) & (ap_enable_reg_pp0_iter1 == 1'b0) & (ap_enable_reg_pp0_iter0 == 1'b0))) begin
        ap_idle_pp0 = 1'b1;
    end else begin
        ap_idle_pp0 = 1'b0;
    end
end

always @ (*) begin
    if (((1'b0 == ap_block_pp0_stage0_subdone) & (ap_enable_reg_pp0_iter0 == 1'b1) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_ready_int = 1'b1;
    end else begin
        ap_ready_int = 1'b0;
    end
end

always @ (*) begin
    if (((ap_loop_init == 1'b1) & (1'b0 == ap_block_pp0_stage0) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_sig_allocacmp_i_load = 3'd0;
    end else begin
        ap_sig_allocacmp_i_load = i_fu_46;
    end
end

always @ (*) begin
    if (((ap_loop_init == 1'b1) & (1'b0 == ap_block_pp0_stage0) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_sig_allocacmp_indvar_flatten_load = 5'd0;
    end else begin
        ap_sig_allocacmp_indvar_flatten_load = indvar_flatten_fu_50;
    end
end

always @ (*) begin
    if (((ap_loop_init == 1'b1) & (1'b0 == ap_block_pp0_stage0) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        ap_sig_allocacmp_j_load = 3'd0;
    end else begin
        ap_sig_allocacmp_j_load = j_fu_42;
    end
end

always @ (*) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (ap_enable_reg_pp0_iter1 == 1'b1) & (1'b1 == ap_CS_fsm_pp0_stage0))) begin
        expandedKey_ce0 = 1'b1;
    end else begin
        expandedKey_ce0 = 1'b0;
    end
end

always @ (*) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (ap_enable_reg_pp0_iter2 == 1'b1))) begin
        roundKey_ce0 = 1'b1;
    end else begin
        roundKey_ce0 = 1'b0;
    end
end

always @ (*) begin
    if (((1'b0 == ap_block_pp0_stage0_11001) & (ap_enable_reg_pp0_iter2 == 1'b1))) begin
        roundKey_we0 = 1'b1;
    end else begin
        roundKey_we0 = 1'b0;
    end
end

always @ (*) begin
    case (ap_CS_fsm)
        ap_ST_fsm_pp0_stage0 : begin
            ap_NS_fsm = ap_ST_fsm_pp0_stage0;
        end
        default : begin
            ap_NS_fsm = 'bx;
        end
    endcase
end

assign add_ln398_3_fu_131_p2 = (ap_sig_allocacmp_i_load + 3'd1);

assign add_ln398_fu_105_p2 = (ap_sig_allocacmp_indvar_flatten_load + 5'd1);

assign add_ln401_fu_153_p2 = (select_ln398_fu_123_p3 + 3'd1);

assign add_ln402_3_fu_205_p2 = (shl_ln402_3_fu_198_p3 + zext_ln398_fu_174_p1);

assign add_ln402_fu_187_p2 = (j_4_cast_fu_184_p1 + p_mid2_fu_177_p3);

assign ap_CS_fsm_pp0_stage0 = ap_CS_fsm[32'd0];

assign ap_block_pp0_stage0 = ~(1'b1 == 1'b1);

assign ap_block_pp0_stage0_11001 = ~(1'b1 == 1'b1);

assign ap_block_pp0_stage0_subdone = ~(1'b1 == 1'b1);

assign ap_block_state1_pp0_stage0_iter0 = ~(1'b1 == 1'b1);

assign ap_block_state2_pp0_stage0_iter1 = ~(1'b1 == 1'b1);

assign ap_block_state3_pp0_stage0_iter2 = ~(1'b1 == 1'b1);

assign ap_enable_pp0 = (ap_idle_pp0 ^ 1'b1);

assign ap_enable_reg_pp0_iter0 = ap_start_int;

assign ap_loop_exit_ready = ap_condition_exit_pp0_iter0_stage0;

assign expandedKey_address0 = zext_ln402_fu_193_p1;

assign icmp_ln398_fu_99_p2 = ((ap_sig_allocacmp_indvar_flatten_load == 5'd16) ? 1'b1 : 1'b0);

assign icmp_ln401_fu_117_p2 = ((ap_sig_allocacmp_j_load == 3'd4) ? 1'b1 : 1'b0);

assign j_4_cast_fu_184_p1 = select_ln398_reg_240;

assign p_mid2_fu_177_p3 = {{trunc_ln398_reg_250}, {2'd0}};

assign roundKey_address0 = zext_ln402_3_fu_211_p1;

assign roundKey_d0 = expandedKey_q0;

assign select_ln398_2_fu_137_p3 = ((icmp_ln401_fu_117_p2[0:0] == 1'b1) ? add_ln398_3_fu_131_p2 : ap_sig_allocacmp_i_load);

assign select_ln398_fu_123_p3 = ((icmp_ln401_fu_117_p2[0:0] == 1'b1) ? 3'd0 : ap_sig_allocacmp_j_load);

assign shl_ln402_3_fu_198_p3 = {{trunc_ln402_reg_255}, {2'd0}};

assign trunc_ln398_fu_145_p1 = select_ln398_2_fu_137_p3[1:0];

assign trunc_ln402_fu_149_p1 = select_ln398_fu_123_p3[1:0];

assign zext_ln398_fu_174_p1 = select_ln398_2_reg_245;

assign zext_ln402_3_fu_211_p1 = add_ln402_3_reg_265;

assign zext_ln402_fu_193_p1 = add_ln402_fu_187_p2;

endmodule //aes_aes_invMain_Pipeline_VITIS_LOOP_398_1_VITIS_LOOP_401_2
