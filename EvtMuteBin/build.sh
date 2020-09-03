python ConvertToShellcode.py ../EvtMute/x64/Release/EvtMuteHook.dll
mv ../EvtMute/x64/Release/EvtMuteHook.bin .
base64 -w 0 EvtMuteHook.bin > EvtMuteHook.b64
echo "Wrote base64 shellcode to: EvtMuteHook.b64"