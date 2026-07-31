# Builds the local test fixtures used by the end-to-end tests.
# Nothing produced here is committed - tests/fixtures/ is git-ignored.
$ErrorActionPreference = 'Stop'
$here = Join-Path $PSScriptRoot '..\tests\fixtures'
New-Item -ItemType Directory -Force -Path $here | Out-Null

# A real system DLL gives us a large, signed, resource-rich sample.
$system = Join-Path $env:SystemRoot 'System32\shlwapi.dll'
if (Test-Path $system) {
  Copy-Item $system (Join-Path $here 'shlwapi.dll') -Force
  Write-Host 'copied shlwapi.dll'
}

# A tiny native DLL with a matching PDB and MAP exercises the symbol readers.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
  Write-Host 'vswhere not found - skipping the native demo.dll fixture.'
  exit 0
}
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
  Write-Host 'No MSVC toolset found - skipping the native demo.dll fixture.'
  exit 0
}

$source = @'
#include <windows.h>
static int g_counter = 0;
namespace demo {
  class Widget {
  public:
    int Spin(int n) { g_counter += n; return g_counter; }
    static int Total() { return g_counter; }
  };
}
extern "C" __declspec(dllexport) int __stdcall AddNumbers(int a, int b) { return a + b + g_counter; }
extern "C" __declspec(dllexport) int __cdecl SpinWidget(int n) { demo::Widget w; return w.Spin(n); }
extern "C" __declspec(dllexport) const char* __cdecl GetGreeting(void) { return "hello from demo.dll"; }
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) { (void)h;(void)r; if (reason == DLL_PROCESS_ATTACH) g_counter = 7; return TRUE; }
'@
Set-Content -Path (Join-Path $here 'demo.cpp') -Value $source -Encoding ascii

$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
& $env:ComSpec /c "call `"$vcvars`" >nul && cd /d `"$here`" && cl /nologo /LD /Zi /Od demo.cpp /link /DEBUG /OUT:demo.dll /MAP:demo.map" | Out-Null
Write-Host 'built demo.dll + demo.pdb + demo.map'
