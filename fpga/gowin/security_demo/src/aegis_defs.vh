// rtl/aegis/aegis_defs.vh
`ifndef AEGIS_DEFS_VH
`define AEGIS_DEFS_VH

  // So round key cua AES-128 (round 0..10)
  `define AEGIS_NUM_RKEY   11

  // Ma nguyen nhan trong sec_status
  `define AEGIS_ST_KLG     0
  `define AEGIS_ST_FIC     1
  `define AEGIS_ST_RCM     2
  `define AEGIS_ST_RED     3
  `define AEGIS_ST_ORC     4

  // Trang thai cua Tamper Response Unit
  `define AEGIS_NORMAL     2'd0
  `define AEGIS_SUSPECT    2'd1
  `define AEGIS_LOCKDOWN   2'd2

`endif
