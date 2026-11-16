@echo off
rem -----------------------------------------------------------------
rem sync_sources.bat - ban Windows cua sync_sources.sh (chen VM co
rem git, khong can WSL). Doc RTL vao fpga\xilinx\src\ theo mot ca:
rem
rem   fpga\xilinx\sync_sources.bat [CASE]
rem
rem   CASE (mac dinh T01_p1_key_dump):
rem     T01_p1_key_dump | T02_p2_slow_leak | T03_p3_skip_mixcol
rem     T04_p4_debug_port | T05_dos_trojan
rem
rem Ngau nhien sau do mo GUI Vivado: add fpga\xilinx\src\*.v +
rem aegis_defs.vh + fpga\xilinx\zc702.xdc, top = top_security_demo.
rem -----------------------------------------------------------------
setlocal

if "%~1"=="" (set CASE=T01_p1_key_dump) else (set CASE=%~1)

rem %~dp0 = thuc mu chua bat file (fpga\xilinx\)
set HERE=%~dp0
rem goc repo = 2 cap len tren fpga\xilinx\ (canonical, khong chua "..")
for /f "tokens=* delims=" %%R in ('cd "%HERE%..\.." & cd /d') do set REPO=%%R
set DEST=%HERE%src

if not exist "%REPO%\rtl\infected\%CASE%\aes_core_tapped.v" (
  echo [sync] Loai: khong thay %REPO%\rtl\infected\%CASE%\aes_core_tapped.v
  exit /b 1
)

rem Dong nguon voi sync_sources.sh: xoa src, doc lai toan bo
if exist "%DEST%" rmdir /s /q "%DEST%"
mkdir "%DEST%"

rem 1) protected path: master rtl/aegis
copy /y "%REPO%\rtl\aegis\aegis_aes_top.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\aegis_defs.vh" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\aes_encipher_block.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\aes_key_mem_tapped.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\klg_key_leak_guard.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\fic_fsm_integrity.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\rcm_round_monitor.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\orc_output_checker.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\red_rare_event.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aegis\tru_tamper_response.v" "%DEST%" >nul

rem 2) sbox/inv_sbox/decipher tu golden
copy /y "%REPO%\rtl\aes_golden\aes_sbox.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aes_golden\aes_inv_sbox.v" "%DEST%" >nul
copy /y "%REPO%\rtl\aes_golden\aes_decipher_block.v" "%DEST%" >nul

rem 3) core nhiem cua ca
copy /y "%REPO%\rtl\infected\%CASE%\aes_core_tapped.v" "%DEST%" >nul

rem 4) UART + FSM (co watchdog T05) tu ban goc fpga/gowin
copy /y "%REPO%\fpga\gowin\security_demo\src\uart_rx.v" "%DEST%" >nul
copy /y "%REPO%\fpga\gowin\security_demo\src\uart_tx.v" "%DEST%" >nul
copy /y "%REPO%\fpga\gowin\security_demo\src\uart_cmd_fsm_security.v" "%DEST%" >nul

rem 5) top Zynq
copy /y "%HERE%top_security_demo.v" "%DEST%" >nul

rem 6) cores/ - 5 core trojan de swap khi chay GUI
if not exist "%DEST%\cores" mkdir "%DEST%\cores"
for %%C in (T01_p1_key_dump T02_p2_slow_leak T03_p3_skip_mixcol T04_p4_debug_port T05_dos_trojan) do (
  if exist "%REPO%\rtl\infected\%%C\aes_core_tapped.v" (
    copy /y "%REPO%\rtl\infected\%%C\aes_core_tapped.v" "%DEST%\cores\%%C_core.v" >nul
  )
)

echo [sync] %CASE% -^> %DEST%
dir /b "%DEST%"
endlocal
