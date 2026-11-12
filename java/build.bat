@echo off
javac com\dpi\*.java
if %ERRORLEVEL% EQU 0 (
    echo Java Packet Analyzer and DPI Engine built successfully!
) else (
    echo Build failed.
)

