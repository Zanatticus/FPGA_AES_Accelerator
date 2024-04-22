-- ==============================================================
-- RTL generated by Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
-- Version: 2022.1
-- Copyright (C) Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
-- 
-- ===========================================================

library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.numeric_std.all;

entity aes_aes_Pipeline_VITIS_LOOP_665_1_VITIS_LOOP_668_2 is
port (
    ap_clk : IN STD_LOGIC;
    ap_rst : IN STD_LOGIC;
    ap_start : IN STD_LOGIC;
    ap_done : OUT STD_LOGIC;
    ap_idle : OUT STD_LOGIC;
    ap_ready : OUT STD_LOGIC;
    ciphertext_array_address0 : OUT STD_LOGIC_VECTOR (3 downto 0);
    ciphertext_array_ce0 : OUT STD_LOGIC;
    ciphertext_array_q0 : IN STD_LOGIC_VECTOR (7 downto 0);
    block_r_address0 : OUT STD_LOGIC_VECTOR (3 downto 0);
    block_r_ce0 : OUT STD_LOGIC;
    block_r_we0 : OUT STD_LOGIC;
    block_r_d0 : OUT STD_LOGIC_VECTOR (7 downto 0) );
end;


architecture behav of aes_aes_Pipeline_VITIS_LOOP_665_1_VITIS_LOOP_668_2 is 
    constant ap_const_logic_1 : STD_LOGIC := '1';
    constant ap_const_logic_0 : STD_LOGIC := '0';
    constant ap_ST_fsm_pp0_stage0 : STD_LOGIC_VECTOR (0 downto 0) := "1";
    constant ap_const_lv32_0 : STD_LOGIC_VECTOR (31 downto 0) := "00000000000000000000000000000000";
    constant ap_const_boolean_1 : BOOLEAN := true;
    constant ap_const_boolean_0 : BOOLEAN := false;
    constant ap_const_lv1_1 : STD_LOGIC_VECTOR (0 downto 0) := "1";
    constant ap_const_lv1_0 : STD_LOGIC_VECTOR (0 downto 0) := "0";
    constant ap_const_lv3_0 : STD_LOGIC_VECTOR (2 downto 0) := "000";
    constant ap_const_lv5_0 : STD_LOGIC_VECTOR (4 downto 0) := "00000";
    constant ap_const_lv5_10 : STD_LOGIC_VECTOR (4 downto 0) := "10000";
    constant ap_const_lv5_1 : STD_LOGIC_VECTOR (4 downto 0) := "00001";
    constant ap_const_lv3_4 : STD_LOGIC_VECTOR (2 downto 0) := "100";
    constant ap_const_lv3_1 : STD_LOGIC_VECTOR (2 downto 0) := "001";
    constant ap_const_lv2_0 : STD_LOGIC_VECTOR (1 downto 0) := "00";

attribute shreg_extract : string;
    signal ap_CS_fsm : STD_LOGIC_VECTOR (0 downto 0) := "1";
    attribute fsm_encoding : string;
    attribute fsm_encoding of ap_CS_fsm : signal is "none";
    signal ap_CS_fsm_pp0_stage0 : STD_LOGIC;
    attribute fsm_encoding of ap_CS_fsm_pp0_stage0 : signal is "none";
    signal ap_enable_reg_pp0_iter0 : STD_LOGIC;
    signal ap_enable_reg_pp0_iter1 : STD_LOGIC := '0';
    signal ap_idle_pp0 : STD_LOGIC;
    signal ap_block_state1_pp0_stage0_iter0 : BOOLEAN;
    signal ap_block_state2_pp0_stage0_iter1 : BOOLEAN;
    signal ap_block_pp0_stage0_subdone : BOOLEAN;
    signal icmp_ln665_fu_99_p2 : STD_LOGIC_VECTOR (0 downto 0);
    signal ap_condition_exit_pp0_iter0_stage0 : STD_LOGIC;
    signal ap_loop_exit_ready : STD_LOGIC;
    signal ap_ready_int : STD_LOGIC;
    signal ap_block_pp0_stage0_11001 : BOOLEAN;
    signal add_ln669_1_fu_188_p2 : STD_LOGIC_VECTOR (3 downto 0);
    signal add_ln669_1_reg_248 : STD_LOGIC_VECTOR (3 downto 0);
    signal zext_ln669_fu_171_p1 : STD_LOGIC_VECTOR (63 downto 0);
    signal ap_block_pp0_stage0 : BOOLEAN;
    signal zext_ln669_1_fu_215_p1 : STD_LOGIC_VECTOR (63 downto 0);
    signal j_fu_42 : STD_LOGIC_VECTOR (2 downto 0);
    signal add_ln668_fu_194_p2 : STD_LOGIC_VECTOR (2 downto 0);
    signal ap_loop_init : STD_LOGIC;
    signal ap_sig_allocacmp_j_load : STD_LOGIC_VECTOR (2 downto 0);
    signal i_fu_46 : STD_LOGIC_VECTOR (2 downto 0);
    signal select_ln665_1_fu_137_p3 : STD_LOGIC_VECTOR (2 downto 0);
    signal ap_sig_allocacmp_i_load : STD_LOGIC_VECTOR (2 downto 0);
    signal indvar_flatten19_fu_50 : STD_LOGIC_VECTOR (4 downto 0);
    signal add_ln665_fu_105_p2 : STD_LOGIC_VECTOR (4 downto 0);
    signal ap_sig_allocacmp_indvar_flatten19_load : STD_LOGIC_VECTOR (4 downto 0);
    signal icmp_ln668_fu_117_p2 : STD_LOGIC_VECTOR (0 downto 0);
    signal add_ln665_1_fu_131_p2 : STD_LOGIC_VECTOR (2 downto 0);
    signal trunc_ln665_fu_149_p1 : STD_LOGIC_VECTOR (1 downto 0);
    signal select_ln665_fu_123_p3 : STD_LOGIC_VECTOR (2 downto 0);
    signal j_6_cast_fu_161_p1 : STD_LOGIC_VECTOR (3 downto 0);
    signal p_mid1_fu_153_p3 : STD_LOGIC_VECTOR (3 downto 0);
    signal add_ln669_fu_165_p2 : STD_LOGIC_VECTOR (3 downto 0);
    signal trunc_ln669_fu_176_p1 : STD_LOGIC_VECTOR (1 downto 0);
    signal shl_ln6_fu_180_p3 : STD_LOGIC_VECTOR (3 downto 0);
    signal zext_ln665_fu_145_p1 : STD_LOGIC_VECTOR (3 downto 0);
    signal ap_done_reg : STD_LOGIC := '0';
    signal ap_continue_int : STD_LOGIC;
    signal ap_done_int : STD_LOGIC;
    signal ap_NS_fsm : STD_LOGIC_VECTOR (0 downto 0);
    signal ap_enable_pp0 : STD_LOGIC;
    signal ap_start_int : STD_LOGIC;
    signal ap_ce_reg : STD_LOGIC;

    component aes_flow_control_loop_pipe_sequential_init IS
    port (
        ap_clk : IN STD_LOGIC;
        ap_rst : IN STD_LOGIC;
        ap_start : IN STD_LOGIC;
        ap_ready : OUT STD_LOGIC;
        ap_done : OUT STD_LOGIC;
        ap_start_int : OUT STD_LOGIC;
        ap_loop_init : OUT STD_LOGIC;
        ap_ready_int : IN STD_LOGIC;
        ap_loop_exit_ready : IN STD_LOGIC;
        ap_loop_exit_done : IN STD_LOGIC;
        ap_continue_int : OUT STD_LOGIC;
        ap_done_int : IN STD_LOGIC );
    end component;



begin
    flow_control_loop_pipe_sequential_init_U : component aes_flow_control_loop_pipe_sequential_init
    port map (
        ap_clk => ap_clk,
        ap_rst => ap_rst,
        ap_start => ap_start,
        ap_ready => ap_ready,
        ap_done => ap_done,
        ap_start_int => ap_start_int,
        ap_loop_init => ap_loop_init,
        ap_ready_int => ap_ready_int,
        ap_loop_exit_ready => ap_condition_exit_pp0_iter0_stage0,
        ap_loop_exit_done => ap_done_int,
        ap_continue_int => ap_continue_int,
        ap_done_int => ap_done_int);





    ap_CS_fsm_assign_proc : process(ap_clk)
    begin
        if (ap_clk'event and ap_clk =  '1') then
            if (ap_rst = '1') then
                ap_CS_fsm <= ap_ST_fsm_pp0_stage0;
            else
                ap_CS_fsm <= ap_NS_fsm;
            end if;
        end if;
    end process;


    ap_done_reg_assign_proc : process(ap_clk)
    begin
        if (ap_clk'event and ap_clk =  '1') then
            if (ap_rst = '1') then
                ap_done_reg <= ap_const_logic_0;
            else
                if ((ap_continue_int = ap_const_logic_1)) then 
                    ap_done_reg <= ap_const_logic_0;
                elsif (((ap_loop_exit_ready = ap_const_logic_1) and (ap_const_boolean_0 = ap_block_pp0_stage0_subdone) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
                    ap_done_reg <= ap_const_logic_1;
                end if; 
            end if;
        end if;
    end process;


    ap_enable_reg_pp0_iter1_assign_proc : process(ap_clk)
    begin
        if (ap_clk'event and ap_clk =  '1') then
            if (ap_rst = '1') then
                ap_enable_reg_pp0_iter1 <= ap_const_logic_0;
            else
                if ((ap_const_logic_1 = ap_condition_exit_pp0_iter0_stage0)) then 
                    ap_enable_reg_pp0_iter1 <= ap_const_logic_0;
                elsif (((ap_const_boolean_0 = ap_block_pp0_stage0_subdone) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
                    ap_enable_reg_pp0_iter1 <= ap_start_int;
                end if; 
            end if;
        end if;
    end process;


    i_fu_46_assign_proc : process (ap_clk)
    begin
        if (ap_clk'event and ap_clk = '1') then
            if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then
                if (((icmp_ln665_fu_99_p2 = ap_const_lv1_0) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1))) then 
                    i_fu_46 <= select_ln665_1_fu_137_p3;
                elsif ((ap_loop_init = ap_const_logic_1)) then 
                    i_fu_46 <= ap_const_lv3_0;
                end if;
            end if; 
        end if;
    end process;

    indvar_flatten19_fu_50_assign_proc : process (ap_clk)
    begin
        if (ap_clk'event and ap_clk = '1') then
            if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then
                if (((icmp_ln665_fu_99_p2 = ap_const_lv1_0) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1))) then 
                    indvar_flatten19_fu_50 <= add_ln665_fu_105_p2;
                elsif ((ap_loop_init = ap_const_logic_1)) then 
                    indvar_flatten19_fu_50 <= ap_const_lv5_0;
                end if;
            end if; 
        end if;
    end process;

    j_fu_42_assign_proc : process (ap_clk)
    begin
        if (ap_clk'event and ap_clk = '1') then
            if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then
                if (((icmp_ln665_fu_99_p2 = ap_const_lv1_0) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1))) then 
                    j_fu_42 <= add_ln668_fu_194_p2;
                elsif ((ap_loop_init = ap_const_logic_1)) then 
                    j_fu_42 <= ap_const_lv3_0;
                end if;
            end if; 
        end if;
    end process;
    process (ap_clk)
    begin
        if (ap_clk'event and ap_clk = '1') then
            if (((icmp_ln665_fu_99_p2 = ap_const_lv1_0) and (ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then
                add_ln669_1_reg_248 <= add_ln669_1_fu_188_p2;
            end if;
        end if;
    end process;

    ap_NS_fsm_assign_proc : process (ap_CS_fsm)
    begin
        case ap_CS_fsm is
            when ap_ST_fsm_pp0_stage0 => 
                ap_NS_fsm <= ap_ST_fsm_pp0_stage0;
            when others =>  
                ap_NS_fsm <= "X";
        end case;
    end process;
    add_ln665_1_fu_131_p2 <= std_logic_vector(unsigned(ap_sig_allocacmp_i_load) + unsigned(ap_const_lv3_1));
    add_ln665_fu_105_p2 <= std_logic_vector(unsigned(ap_sig_allocacmp_indvar_flatten19_load) + unsigned(ap_const_lv5_1));
    add_ln668_fu_194_p2 <= std_logic_vector(unsigned(select_ln665_fu_123_p3) + unsigned(ap_const_lv3_1));
    add_ln669_1_fu_188_p2 <= std_logic_vector(unsigned(shl_ln6_fu_180_p3) + unsigned(zext_ln665_fu_145_p1));
    add_ln669_fu_165_p2 <= std_logic_vector(unsigned(j_6_cast_fu_161_p1) + unsigned(p_mid1_fu_153_p3));
    ap_CS_fsm_pp0_stage0 <= ap_CS_fsm(0);
        ap_block_pp0_stage0 <= not((ap_const_boolean_1 = ap_const_boolean_1));
        ap_block_pp0_stage0_11001 <= not((ap_const_boolean_1 = ap_const_boolean_1));
        ap_block_pp0_stage0_subdone <= not((ap_const_boolean_1 = ap_const_boolean_1));
        ap_block_state1_pp0_stage0_iter0 <= not((ap_const_boolean_1 = ap_const_boolean_1));
        ap_block_state2_pp0_stage0_iter1 <= not((ap_const_boolean_1 = ap_const_boolean_1));

    ap_condition_exit_pp0_iter0_stage0_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_enable_reg_pp0_iter0, ap_block_pp0_stage0_subdone, icmp_ln665_fu_99_p2)
    begin
        if (((icmp_ln665_fu_99_p2 = ap_const_lv1_1) and (ap_const_boolean_0 = ap_block_pp0_stage0_subdone) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_condition_exit_pp0_iter0_stage0 <= ap_const_logic_1;
        else 
            ap_condition_exit_pp0_iter0_stage0 <= ap_const_logic_0;
        end if; 
    end process;


    ap_done_int_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_block_pp0_stage0_subdone, ap_loop_exit_ready, ap_done_reg)
    begin
        if (((ap_loop_exit_ready = ap_const_logic_1) and (ap_const_boolean_0 = ap_block_pp0_stage0_subdone) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_done_int <= ap_const_logic_1;
        else 
            ap_done_int <= ap_done_reg;
        end if; 
    end process;

    ap_enable_pp0 <= (ap_idle_pp0 xor ap_const_logic_1);
    ap_enable_reg_pp0_iter0 <= ap_start_int;

    ap_idle_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_idle_pp0, ap_start_int)
    begin
        if (((ap_idle_pp0 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0) and (ap_start_int = ap_const_logic_0))) then 
            ap_idle <= ap_const_logic_1;
        else 
            ap_idle <= ap_const_logic_0;
        end if; 
    end process;


    ap_idle_pp0_assign_proc : process(ap_enable_reg_pp0_iter0, ap_enable_reg_pp0_iter1)
    begin
        if (((ap_enable_reg_pp0_iter1 = ap_const_logic_0) and (ap_enable_reg_pp0_iter0 = ap_const_logic_0))) then 
            ap_idle_pp0 <= ap_const_logic_1;
        else 
            ap_idle_pp0 <= ap_const_logic_0;
        end if; 
    end process;

    ap_loop_exit_ready <= ap_condition_exit_pp0_iter0_stage0;

    ap_ready_int_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_enable_reg_pp0_iter0, ap_block_pp0_stage0_subdone)
    begin
        if (((ap_const_boolean_0 = ap_block_pp0_stage0_subdone) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_ready_int <= ap_const_logic_1;
        else 
            ap_ready_int <= ap_const_logic_0;
        end if; 
    end process;


    ap_sig_allocacmp_i_load_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_block_pp0_stage0, ap_loop_init, i_fu_46)
    begin
        if (((ap_loop_init = ap_const_logic_1) and (ap_const_boolean_0 = ap_block_pp0_stage0) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_sig_allocacmp_i_load <= ap_const_lv3_0;
        else 
            ap_sig_allocacmp_i_load <= i_fu_46;
        end if; 
    end process;


    ap_sig_allocacmp_indvar_flatten19_load_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_block_pp0_stage0, ap_loop_init, indvar_flatten19_fu_50)
    begin
        if (((ap_loop_init = ap_const_logic_1) and (ap_const_boolean_0 = ap_block_pp0_stage0) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_sig_allocacmp_indvar_flatten19_load <= ap_const_lv5_0;
        else 
            ap_sig_allocacmp_indvar_flatten19_load <= indvar_flatten19_fu_50;
        end if; 
    end process;


    ap_sig_allocacmp_j_load_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_block_pp0_stage0, j_fu_42, ap_loop_init)
    begin
        if (((ap_loop_init = ap_const_logic_1) and (ap_const_boolean_0 = ap_block_pp0_stage0) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ap_sig_allocacmp_j_load <= ap_const_lv3_0;
        else 
            ap_sig_allocacmp_j_load <= j_fu_42;
        end if; 
    end process;

    block_r_address0 <= zext_ln669_1_fu_215_p1(4 - 1 downto 0);

    block_r_ce0_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_enable_reg_pp0_iter1, ap_block_pp0_stage0_11001)
    begin
        if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_enable_reg_pp0_iter1 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            block_r_ce0 <= ap_const_logic_1;
        else 
            block_r_ce0 <= ap_const_logic_0;
        end if; 
    end process;

    block_r_d0 <= ciphertext_array_q0;

    block_r_we0_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_enable_reg_pp0_iter1, ap_block_pp0_stage0_11001)
    begin
        if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_enable_reg_pp0_iter1 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            block_r_we0 <= ap_const_logic_1;
        else 
            block_r_we0 <= ap_const_logic_0;
        end if; 
    end process;

    ciphertext_array_address0 <= zext_ln669_fu_171_p1(4 - 1 downto 0);

    ciphertext_array_ce0_assign_proc : process(ap_CS_fsm_pp0_stage0, ap_enable_reg_pp0_iter0, ap_block_pp0_stage0_11001)
    begin
        if (((ap_const_boolean_0 = ap_block_pp0_stage0_11001) and (ap_enable_reg_pp0_iter0 = ap_const_logic_1) and (ap_const_logic_1 = ap_CS_fsm_pp0_stage0))) then 
            ciphertext_array_ce0 <= ap_const_logic_1;
        else 
            ciphertext_array_ce0 <= ap_const_logic_0;
        end if; 
    end process;

    icmp_ln665_fu_99_p2 <= "1" when (ap_sig_allocacmp_indvar_flatten19_load = ap_const_lv5_10) else "0";
    icmp_ln668_fu_117_p2 <= "1" when (ap_sig_allocacmp_j_load = ap_const_lv3_4) else "0";
    j_6_cast_fu_161_p1 <= std_logic_vector(IEEE.numeric_std.resize(unsigned(select_ln665_fu_123_p3),4));
    p_mid1_fu_153_p3 <= (trunc_ln665_fu_149_p1 & ap_const_lv2_0);
    select_ln665_1_fu_137_p3 <= 
        add_ln665_1_fu_131_p2 when (icmp_ln668_fu_117_p2(0) = '1') else 
        ap_sig_allocacmp_i_load;
    select_ln665_fu_123_p3 <= 
        ap_const_lv3_0 when (icmp_ln668_fu_117_p2(0) = '1') else 
        ap_sig_allocacmp_j_load;
    shl_ln6_fu_180_p3 <= (trunc_ln669_fu_176_p1 & ap_const_lv2_0);
    trunc_ln665_fu_149_p1 <= select_ln665_1_fu_137_p3(2 - 1 downto 0);
    trunc_ln669_fu_176_p1 <= select_ln665_fu_123_p3(2 - 1 downto 0);
    zext_ln665_fu_145_p1 <= std_logic_vector(IEEE.numeric_std.resize(unsigned(select_ln665_1_fu_137_p3),4));
    zext_ln669_1_fu_215_p1 <= std_logic_vector(IEEE.numeric_std.resize(unsigned(add_ln669_1_reg_248),64));
    zext_ln669_fu_171_p1 <= std_logic_vector(IEEE.numeric_std.resize(unsigned(add_ln669_fu_165_p2),64));
end behav;
