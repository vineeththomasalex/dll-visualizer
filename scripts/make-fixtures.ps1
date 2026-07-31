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

# Two builds of a tiny native DLL exercise the symbol readers and the compare view.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
  Write-Host 'vswhere not found - skipping the native demo.dll fixtures.'
  exit 0
}
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
  Write-Host 'No MSVC toolset found - skipping the native demo.dll fixtures.'
  exit 0
}
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'

$v1 = @'
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

# v2 deliberately adds exports, a new dependency (WININET) and more data so the
# compare view has something meaningful to show.
$v2 = @'
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
static int g_counter = 0;
static char g_scratch[8192] = { 0 };
namespace demo {
  class Widget {
  public:
    int Spin(int n) { g_counter += n; for (int i = 0; i < 32; i++) g_scratch[i % 8192] = (char)(n + i); return g_counter; }
    static int Total() { return g_counter; }
    int Wobble(int n) { return Spin(n) * 3 + (int)strlen(g_scratch); }
  };
}
extern "C" __declspec(dllexport) int __stdcall AddNumbers(int a, int b) { return a + b + g_counter; }
extern "C" __declspec(dllexport) int __cdecl SpinWidget(int n) { demo::Widget w; return w.Wobble(n); }
extern "C" __declspec(dllexport) const char* __cdecl GetGreeting(void) { return "hello from demo.dll v2"; }
extern "C" __declspec(dllexport) int __cdecl WobbleWidget(int n) { demo::Widget w; return w.Wobble(n * 2); }
extern "C" __declspec(dllexport) int __cdecl FetchSomething(const char* url) { HINTERNET h = InternetOpenA("demo", 0, 0, 0, 0); if (!h) return -1; InternetCloseHandle(h); return (int)strlen(url); }
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) { (void)h;(void)r; if (reason == DLL_PROCESS_ATTACH) { g_counter = 7; for (int i = 0; i < 4096; i++) g_scratch[i] = (char)(i & 0x7f); } return TRUE; }
'@

function Build([string]$source, [string]$stem, [string]$opt) {
  Set-Content -Path (Join-Path $here "$stem.cpp") -Value $source -Encoding ascii
  & $env:ComSpec /c "call `"$vcvars`" >nul && cd /d `"$here`" && cl /nologo /LD /Zi $opt $stem.cpp /link /DEBUG /OUT:$stem.dll /MAP:$stem.map" | Out-Null
  Write-Host "built $stem.dll + $stem.pdb + $stem.map"
}

Build $v1 'demo' '/Od'
Copy-Item (Join-Path $here 'demo.dll') (Join-Path $here 'demo_v1.dll') -Force
Build $v2 'demo_v2' '/O2'
