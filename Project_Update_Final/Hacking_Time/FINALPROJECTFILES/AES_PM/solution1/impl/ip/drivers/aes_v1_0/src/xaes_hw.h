// ==============================================================
// Vitis HLS - High-Level Synthesis from C, C++ and OpenCL v2022.1 (64-bit)
// Tool Version Limit: 2022.04
// Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
// ==============================================================
// control
// 0x00 : reserved
// 0x04 : reserved
// 0x08 : reserved
// 0x0c : reserved
// 0x10 : Data signal of mode
//        bit 31~0 - mode[31:0] (Read/Write)
// 0x14 : reserved
// 0x18 : Data signal of enable_out
//        bit 7~0 - enable_out[7:0] (Read/Write)
//        others  - reserved
// 0x1c : reserved
// 0x20 : Data signal of power_reading_in
//        bit 31~0 - power_reading_in[31:0] (Read/Write)
// 0x24 : reserved
// (SC = Self Clear, COR = Clear on Read, TOW = Toggle on Write, COH = Clear on Handshake)

#define XAES_CONTROL_ADDR_MODE_DATA             0x10
#define XAES_CONTROL_BITS_MODE_DATA             32
#define XAES_CONTROL_ADDR_ENABLE_OUT_DATA       0x18
#define XAES_CONTROL_BITS_ENABLE_OUT_DATA       8
#define XAES_CONTROL_ADDR_POWER_READING_IN_DATA 0x20
#define XAES_CONTROL_BITS_POWER_READING_IN_DATA 32

// CTRL_BUS
// 0x00 : Control signals
//        bit 0  - ap_start (Read/Write/COH)
//        bit 1  - ap_done (Read/COR)
//        bit 2  - ap_idle (Read)
//        bit 3  - ap_ready (Read/COR)
//        bit 7  - auto_restart (Read/Write)
//        bit 9  - interrupt (Read)
//        others - reserved
// 0x04 : Global Interrupt Enable Register
//        bit 0  - Global Interrupt Enable (Read/Write)
//        others - reserved
// 0x08 : IP Interrupt Enable Register (Read/Write)
//        bit 0 - enable ap_done interrupt (Read/Write)
//        bit 1 - enable ap_ready interrupt (Read/Write)
//        others - reserved
// 0x0c : IP Interrupt Status Register (Read/COR)
//        bit 0 - ap_done (Read/COR)
//        bit 1 - ap_ready (Read/COR)
//        others - reserved
// 0x10 : Data signal of enable_in
//        bit 7~0 - enable_in[7:0] (Read/Write)
//        others  - reserved
// 0x14 : reserved
// 0x18 : Data signal of power_reading_out
//        bit 31~0 - power_reading_out[31:0] (Read/Write)
// 0x1c : reserved
// (SC = Self Clear, COR = Clear on Read, TOW = Toggle on Write, COH = Clear on Handshake)

#define XAES_CTRL_BUS_ADDR_AP_CTRL                0x00
#define XAES_CTRL_BUS_ADDR_GIE                    0x04
#define XAES_CTRL_BUS_ADDR_IER                    0x08
#define XAES_CTRL_BUS_ADDR_ISR                    0x0c
#define XAES_CTRL_BUS_ADDR_ENABLE_IN_DATA         0x10
#define XAES_CTRL_BUS_BITS_ENABLE_IN_DATA         8
#define XAES_CTRL_BUS_ADDR_POWER_READING_OUT_DATA 0x18
#define XAES_CTRL_BUS_BITS_POWER_READING_OUT_DATA 32

