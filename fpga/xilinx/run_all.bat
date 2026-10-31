@echo off
rem -----------------------------------------------------------------
rem run_all.bat - 5 ca Trojan tren ZC702 (Windows/VMWare, chay TRUOC
rem bat file cua Vivado 2024.1). Moi ca: 1 project + bitstream +
rem reports. Moi ca ~5-15 phut, toan bo ~1 gio.
rem
rem Cai dat (khop voi layout VM C:\VM_Xilinx\zynq-aegis):
rem   zynq-aegis\src\             - toan bo source closure (17 file .v
rem                                 + aegis_defs.vh + top_security_demo.v)
rem   zynq-aegis\build_zynq.tcl   - script nay
rem   zynq-aegis\zc702.xdc        - pin map
rem (bat file o ngay thuc cha cua src\ - dung %~dp0 chi dinh duong)
rem -----------------------------------------------------------------
setlocal

set CASES=T01_p1_key_dump T02_p2_slow_leak T03_p3_skip_mixcol T04_p4_debug_port T05_dos_trojan

for %%C in (%CASES%) do (
  echo ============================================================
  echo  AEGIS-AES / ZC702 - ca %%C
  echo ============================================================
  vivado -mode batch -nolog -nojournal -source "%~dp0build_zynq.tcl" -tclargs %%C
  if errorlevel 1 (
    echo [run_all] %%C THAT BAI - tiep tuc ca tiep theo.
  )
)

echo.
echo reports   : %~dp0reports\ theo ten ca {util,timing,timing_min,methodology,clock_util}.rpt
echo bitstream : %~dp0aegis_<CASE>\impl_1\*.bit
echo chi tiet  : chay doc mot ca:  vivado -mode batch -nolog -nojournal -source %~dp0build_zynq.tcl -tclargs T03_p3_skip_mixcol
endlocal
