// ==============================================================
// RTL generated by Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
// Version: 2022.1
// Copyright (C) Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// 
// ===========================================================

`timescale 1 ns / 1 ps 

module aes_aes_Pipeline_VITIS_LOOP_70_2 (
        ap_clk,
        ap_rst,
        ap_start,
        ap_done,
        ap_idle,
        ap_ready,
        key_and_plaintext_TVALID,
        cipherkey_size,
        key_and_plaintext_TDATA,
        key_and_plaintext_TREADY,
        key_and_plaintext_TKEEP,
        key_and_plaintext_TSTRB,
        key_and_plaintext_TUSER,
        key_and_plaintext_TLAST,
        key_and_plaintext_TID,
        key_and_plaintext_TDEST,
        key_array,
        key_array128_address0,
        key_array128_ce0,
        key_array128_we0,
        key_array128_d0
);

parameter    ap_ST_fsm_state1 = 1'd1;

input   ap_clk;
input   ap_rst;
input   ap_start;
output   ap_done;
output   ap_idle;
output   ap_ready;
input   key_and_plaintext_TVALID;
input  [5:0] cipherkey_size;
input  [7:0] key_and_plaintext_TDATA;
output   key_and_plaintext_TREADY;
input  [0:0] key_and_plaintext_TKEEP;
input  [0:0] key_and_plaintext_TSTRB;
input  [0:0] key_and_plaintext_TUSER;
input  [0:0] key_and_plaintext_TLAST;
input  [0:0] key_and_plaintext_TID;
input  [0:0] key_and_plaintext_TDEST;
input  [10:0] key_array;
output  [10:0] key_array128_address0;
output   key_array128_ce0;
output   key_array128_we0;
output  [7:0] key_array128_d0;

reg ap_idle;
reg key_and_plaintext_TREADY;
reg key_array128_ce0;
reg key_array128_we0;

(* fsm_encoding = "none" *) reg   [0:0] ap_CS_fsm;
wire    ap_CS_fsm_state1;
wire   [0:0] icmp_ln70_fu_123_p2;
reg    ap_block_state1_pp0_stage0_iter0;
reg    ap_condition_exit_pp0_iter0_stage0;
wire    ap_loop_exit_ready;
reg    ap_ready_int;
reg    key_and_plaintext_TDATA_blk_n;
wire   [63:0] zext_ln72_fu_158_p1;
reg   [5:0] i_fu_68;
wire   [5:0] add_ln70_fu_129_p2;
wire    ap_loop_init;
reg   [5:0] ap_sig_allocacmp_i_31;
wire   [4:0] tmp_fu_140_p4;
wire   [10:0] add_ln_fu_150_p3;
reg    ap_done_reg;
wire    ap_continue_int;
reg    ap_done_int;
reg   [0:0] ap_NS_fsm;
reg    ap_ST_fsm_state1_blk;
wire    ap_start_int;
reg    ap_condition_132;
wire    ap_ce_reg;

// power-on initialization
initial begin
#0 ap_CS_fsm = 1'd1;
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
        ap_CS_fsm <= ap_ST_fsm_state1;
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
        end else if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (ap_loop_exit_ready == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
            ap_done_reg <= 1'b1;
        end
    end
end

always @ (posedge ap_clk) begin
    if ((1'b1 == ap_condition_132)) begin
        if ((icmp_ln70_fu_123_p2 == 1'd0)) begin
            i_fu_68 <= add_ln70_fu_129_p2;
        end else if ((ap_loop_init == 1'b1)) begin
            i_fu_68 <= 6'd0;
        end
    end
end

always @ (*) begin
    if (((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0)))) begin
        ap_ST_fsm_state1_blk = 1'b1;
    end else begin
        ap_ST_fsm_state1_blk = 1'b0;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (icmp_ln70_fu_123_p2 == 1'd1) & (1'b1 == ap_CS_fsm_state1))) begin
        ap_condition_exit_pp0_iter0_stage0 = 1'b1;
    end else begin
        ap_condition_exit_pp0_iter0_stage0 = 1'b0;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (ap_loop_exit_ready == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
        ap_done_int = 1'b1;
    end else begin
        ap_done_int = ap_done_reg;
    end
end

always @ (*) begin
    if (((1'b1 == ap_CS_fsm_state1) & (ap_start_int == 1'b0))) begin
        ap_idle = 1'b1;
    end else begin
        ap_idle = 1'b0;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (1'b1 == ap_CS_fsm_state1))) begin
        ap_ready_int = 1'b1;
    end else begin
        ap_ready_int = 1'b0;
    end
end

always @ (*) begin
    if (((ap_loop_init == 1'b1) & (1'b1 == ap_CS_fsm_state1))) begin
        ap_sig_allocacmp_i_31 = 6'd0;
    end else begin
        ap_sig_allocacmp_i_31 = i_fu_68;
    end
end

always @ (*) begin
    if (((icmp_ln70_fu_123_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state1) & (ap_start_int == 1'b1))) begin
        key_and_plaintext_TDATA_blk_n = key_and_plaintext_TVALID;
    end else begin
        key_and_plaintext_TDATA_blk_n = 1'b1;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (icmp_ln70_fu_123_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state1))) begin
        key_and_plaintext_TREADY = 1'b1;
    end else begin
        key_and_plaintext_TREADY = 1'b0;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (1'b1 == ap_CS_fsm_state1))) begin
        key_array128_ce0 = 1'b1;
    end else begin
        key_array128_ce0 = 1'b0;
    end
end

always @ (*) begin
    if ((~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (icmp_ln70_fu_123_p2 == 1'd0) & (1'b1 == ap_CS_fsm_state1))) begin
        key_array128_we0 = 1'b1;
    end else begin
        key_array128_we0 = 1'b0;
    end
end

always @ (*) begin
    case (ap_CS_fsm)
        ap_ST_fsm_state1 : begin
            ap_NS_fsm = ap_ST_fsm_state1;
        end
        default : begin
            ap_NS_fsm = 'bx;
        end
    endcase
end

assign add_ln70_fu_129_p2 = (ap_sig_allocacmp_i_31 + 6'd1);

assign add_ln_fu_150_p3 = {{tmp_fu_140_p4}, {ap_sig_allocacmp_i_31}};

assign ap_CS_fsm_state1 = ap_CS_fsm[32'd0];

always @ (*) begin
    ap_block_state1_pp0_stage0_iter0 = ((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0)));
end

always @ (*) begin
    ap_condition_132 = (~((ap_start_int == 1'b0) | ((icmp_ln70_fu_123_p2 == 1'd0) & (key_and_plaintext_TVALID == 1'b0))) & (1'b1 == ap_CS_fsm_state1));
end

assign ap_loop_exit_ready = ap_condition_exit_pp0_iter0_stage0;

assign icmp_ln70_fu_123_p2 = ((ap_sig_allocacmp_i_31 == cipherkey_size) ? 1'b1 : 1'b0);

assign key_array128_address0 = zext_ln72_fu_158_p1;

assign key_array128_d0 = key_and_plaintext_TDATA;

assign tmp_fu_140_p4 = {{key_array[10:6]}};

assign zext_ln72_fu_158_p1 = add_ln_fu_150_p3;

endmodule //aes_aes_Pipeline_VITIS_LOOP_70_2
