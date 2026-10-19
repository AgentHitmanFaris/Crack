# SeeMusic 27H + Zero-Watermark Pro Engine // Reverse Engineering Findings & Specification

**Author / Community:** -[]- NBS Community  
**Target Application:** SeeMusic (x64 Unity / IL2CPP)  
**Supported Versions:** 9.1.3, 9.1.1, and Adaptive Universal Profile Base  
**Patcher Version:** 3.1.0.1  

---

## 1. Executive Summary

This document details the reverse engineering findings, memory hook specifications, asset modifications, and binary architecture discovered in **SeeMusic** (64-bit Unity IL2CPP). 

The findings are implemented inside the direct in-place kernel patcher [`SeeMusic_Render_Patcher_GUI.au3`](SeeMusic_Render_Patcher_GUI.au3), enabling:
1. **Unlimited 27-Hour Video Renders (97,200.0s)** (Bypassing the standard 60-second trial restriction).
2. **100% Watermark Neutralization** (Zero-alpha textures and disabled rendering loops).
3. **Pro Export Modal Suppression** (Bypassing the *"Unlock SeeMusic Pro"* / *"Render Free with Watermark"* upsell modal, opening export settings directly).
4. **Universal Multi-Tier Version Detection** (Reading Unity `globalgamemanagers` metadata and Windows Registry).

---

## 2. Technical Findings & Architecture

### 2.1 Pro Export Modal Dialog Suppression

When free users click any export button in SeeMusic (Render Video, Alternate Format, Batch/Preset), the game checks an internal license byte in the render configuration object before displaying the export settings dialog.

#### Disassembly Analysis (`GameAssembly.dll` v9.1.3)
At three critical call sites, the instruction sequence tests `[rax + 0x8B8]`:

```x86asm
; Site 1: 0x014867BD / 0x014867C1
0x014867B4: mov     rax, qword ptr [rdi + 0x20]
0x014867B8: test    rax, rax
0x014867BB: je      0x14869B3
0x014867C1: cmp     byte ptr [rax + 0x8B8], 0     ; License check (0 = Free, 1 = Pro)
0x014867C8: mov     rbx, qword ptr [rdi + 0x288]  ; Pointer to Modal UI dialog
0x014867CF: jne     0x148686A                     ; Jumps to ExportSettingsDirectly
; Fall-through -> Calls modal popup dialog ("Unlock SeeMusic Pro" / "Render Free")

; Site 2: 0x01488B52 / 0x01488B64
0x01488B57: mov     rax, qword ptr [rdi + 0x20]
0x01488B5B: test    rax, rax
0x01488B5E: je      0x1488D4A
0x01488B64: cmp     byte ptr [rax + 0x8B8], 0     ; License check
0x01488B6B: mov     rbx, qword ptr [rdi + 0x288]  ; Modal dialog pointer
0x01488B72: jne     0x1488C01                     ; Jumps to ExportSettingsDirectly

; Site 3: 0x01489DB2 / 0x01489DC4
0x01489DB7: mov     rax, qword ptr [rdi + 0x20]
0x01489DBB: test    rax, rax
0x01489DBE: je      0x1489FAA
0x01489DC4: cmp     byte ptr [rax + 0x8B8], 0     ; License check
0x01489DCB: mov     rbx, qword ptr [rdi + 0x288]  ; Modal dialog pointer
0x01489DD2: jne     0x1489E61                     ; Jumps to ExportSettingsDirectly
```

#### The Fix
By replacing the conditional `jne` (`0F 85 rel32`) with an unconditional `jmp` (`E9 rel32 + NOP`), the application skips the modal UI invocation and routes directly into the official export parameters window:

* **Site 1 (`0x014867CF`):** `0F 85 95 00 00 00` &rarr; `E9 96 00 00 00 90` (`jmp 0x148686A`)
* **Site 2 (`0x01488B72`):** `0F 85 89 00 00 00` &rarr; `E9 8A 00 00 00 90` (`jmp 0x1488C01`)
* **Site 3 (`0x01489DD2`):** `0F 85 89 00 00 00` &rarr; `E9 8A 00 00 00 90` (`jmp 0x1489E61`)

---

### 2.2 27-Hour Render Duration Pipeline

SeeMusic enforces a 60-second render limit via multiple interdependent components:

1. **Floating-Point Padding Injection (`.rdata`):**
   * Two constant doubles/floats representing `97,200.0` seconds (27 hours) are written into zeroed padding in `.rdata`:
     * Float32 (`0x47BDD800`): Injected at `0x05FC8D00` (9.1.3) / `0x0585BB20` (9.1.1).
     * Float64 (`0x40F7BB0000000000`): Injected at `0x05FC8D08` (9.1.3) / `0x0585BB28` (9.1.1).
2. **`get_UsesFreeRender` Hook:**
   * Native method in `GameAssembly.dll` determines whether trial limits and watermark warnings apply.
   * **Hook:** Patched with `xor eax, eax; ret` (`31 C0 C3`), forcing the application to report as non-free.
3. **`SetFreeLimits` Neutralization:**
   * Native method at `0x1490AA0` clamps render timelines on start.
   * **Hook:** Patched with immediate `ret` (`C3`), suppressing runtime clamping.
4. **Audio Watchdog Deadline (`bcm.MoveNext`):**
   * Background audio export coroutine terminates jobs exceeding 60.0s.
   * **Hook:** Target displacement rewritten at `0x1A2D3D4` to point to the 27-hour Float64 constant.

---

### 2.3 Watermark Complete Neutralization (Dual Layer)

The watermark system consists of two elements: a repeating diagonal lattice and the SeeMusic Wordmark / 8th-note icon.

1. **Pipeline Layer (Code Bypasses in `GameAssembly.dll`):**
   * `get_UseNoteLockupWatermark`: Patched to `xor al, al; ret` (`32 C0 C3 + NOPs`).
   * 5 Watermark Call Sites (`0x13F6E45`, `0x13F6FB5`, `0x13F7125`, `0x13F7295`, `0x13F7405`):
     * Branch `jne` disabled (`NOP` / `90 90`) to prevent lattice trigger.
     * `SetActive(false)` forced on the wordmark GameObject via `xor edx, edx` (`31 D2 90 90`).
2. **Asset Layer (Zero-Alpha in `SeeMusic_Data`):**
   * **`resources.assets.resS`:**
     * SeeMusic Wordmark (336,000 bytes) at offset `0x05CB1E50` (9.1.3) &rarr; Zeroed to `0x00` (100% transparent).
     * 8th-Note Logo (21,872 bytes) at offset `0x00BAC730` (9.1.3) &rarr; Zeroed to `0x00` (100% transparent).
   * **`sharedassets0.assets`:**
     * 78 instances of diagonal watermark lattice alpha (`39 B4 C8 3E`, IEEE 754 float `0.392f`) &rarr; Replaced with `00 00 00 00` (`0.0f`).

---

## 3. Version Detection Architecture

Rather than relying purely on file size heuristics, version detection uses a multi-tier resolution strategy:

```mermaid
graph TD
    A["_DetectVersion($sDll)"] --> B{"1. Check globalgamemanagers<br/>PlayerSettings.bundleVersion"}
    B -->|Found version string| C["Version Resolved e.g. 9.1.3"]
    B -->|Not found / Error| D{"2. Check Windows Registry<br/>Uninstall DisplayVersion"}
    D -->|Found in Registry| C
    D -->|Not found| E{"3. Binary File Size Heuristics"}
    E -->|Size > 108MB| F["Assume 9.1.3"]
    E -->|Size > 98MB| G["Assume 9.1.1"]
    E -->|Other Size| H["Unknown Version"]
    C --> I{"Route Profile"}
    I -->|9.1.3| J["_LoadProfile_913() (24 Hooks)"]
    I -->|9.1.1| K["_LoadProfile_911() (27 Hooks)"]
    I -->|Other (e.g. 9.1.4, 9.2.0)| L["Adaptive Profile Base + Safe Pre-Check"]
```

---

## 4. Master Patch Hook Reference Table

### SeeMusic 9.1.3 (24 Hooks)

| Index | Offset | Patched Bytes | Original Bytes | Hook Identifier | Functional Description |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **0** | `0x05FC8D00` | `00D8BD4700000000` | `0000000000000000` | 27h Float32 Constant | Writes 97200.0f into .rdata padding |
| **1** | `0x05FC8D08` | `0000000000BBF740` | `0000000000000000` | 27h Float64 Constant | Writes 97200.0d into .rdata padding |
| **2** | `0x014900C0` | `31C0C3` | `4883EC` | get_UsesFreeRender Hook | `xor eax, eax; ret` -> Free/trial disabled |
| **3** | `0x01490AA0` | `C3` | `40` | SetFreeLimits Neutralize | `ret` -> Neutralizes render timeline clamp |
| **4** | `0x01A2D3D4` | `30C15904` | `00405603` | Audio Watchdog Timeout | Redirects audio deadline to 27h double |
| **5** | `0x013E8340` | `32C0C3909090...` | `80B9B40B0000...` | get_UseNoteLockup Hook | `xor al, al; ret` -> Neutralizes lattice |
| **6** | `0x013F6E4C` | `9090` | `7547` | WM Site 1 Lattice Branch 1 | NOP jne -> Disables lattice trigger |
| **7** | `0x013F6E62` | `9090` | `7531` | WM Site 1 Lattice Branch 2 | NOP jne -> Disables lattice trigger |
| **8** | `0x013F6E8F` | `31D29090` | `0FB65318` | WM Site 1 Wordmark Disable | `xor edx, edx` -> SetActive(false) on logo |
| **9** | `0x013F6FBC` | `9090` | `7547` | WM Site 2 Lattice Branch 1 | NOP jne -> Disables lattice trigger |
| **10** | `0x013F6FD2` | `9090` | `7531` | WM Site 2 Lattice Branch 2 | NOP jne -> Disables lattice trigger |
| **11** | `0x013F6FFF` | `31D29090` | `0FB65318` | WM Site 2 Wordmark Disable | `xor edx, edx` -> SetActive(false) on logo |
| **12** | `0x013F712C` | `9090` | `7547` | WM Site 3 Lattice Branch 1 | NOP jne -> Disables lattice trigger |
| **13** | `0x013F7142` | `9090` | `7531` | WM Site 3 Lattice Branch 2 | NOP jne -> Disables lattice trigger |
| **14** | `0x013F716F` | `31D29090` | `0FB65318` | WM Site 3 Wordmark Disable | `xor edx, edx` -> SetActive(false) on logo |
| **15** | `0x013F729C` | `9090` | `7547` | WM Site 4 Lattice Branch 1 | NOP jne -> Disables lattice trigger |
| **16** | `0x013F72B2` | `9090` | `7531` | WM Site 4 Lattice Branch 2 | NOP jne -> Disables lattice trigger |
| **17** | `0x013F72DF` | `31D29090` | `0FB65318` | WM Site 4 Wordmark Disable | `xor edx, edx` -> SetActive(false) on logo |
| **18** | `0x013F740C` | `9090` | `7547` | WM Site 5 Lattice Branch 1 | NOP jne -> Disables lattice trigger |
| **19** | `0x013F7422` | `9090` | `7531` | WM Site 5 Lattice Branch 2 | NOP jne -> Disables lattice trigger |
| **20** | `0x013F744F` | `31D29090` | `0FB65318` | WM Site 5 Wordmark Disable | `xor edx, edx` -> SetActive(false) on logo |
| **21** | `0x014867CF` | `E99600000090` | `0F8595000000` | Export Modal Bypass 1 | `jmp 0x148686A` -> Direct Export Settings |
| **22** | `0x01488B72` | `E98A00000090` | `0F8589000000` | Export Modal Bypass 2 | `jmp 0x1488C01` -> Direct Export Settings |
| **23** | `0x01489DD2` | `E98A00000090` | `0F8589000000` | Export Modal Bypass 3 | `jmp 0x1489E61` -> Direct Export Settings |

---

## 5. Asset Offsets Reference

| Asset Target | File Path | SeeMusic 9.1.3 Offset | SeeMusic 9.1.1 Offset | Action |
| :--- | :--- | :---: | :---: | :--- |
| **Wordmark Texture** | `SeeMusic_Data\resources.assets.resS` | `0x05CB1E50` (336 KB) | `0x05C89110` (336 KB) | Zeroed (`0x00`) |
| **8th-Note Icon** | `SeeMusic_Data\resources.assets.resS` | `0x00BAC730` (21.8 KB) | `0x00B98ED0` (21.8 KB) | Zeroed (`0x00`) |
| **Lattice Opacity** | `SeeMusic_Data\sharedassets0.assets` | 78 instances | 78 instances | Replaced `39B4C83E` &rarr; `00000000` |

---

## 6. How to Build & Run

### Prerequisites
* **AutoIt3** toolchain installed (`Aut2exe` and `Au3Check`).

### Compilation Command
```bat
"D:\Document\REA\AutoIt3\Aut2Exe\Aut2exe.exe" /in "SeeMusic_Render_Patcher_GUI.au3" /out "SeeMusicPatcher.exe" /icon "SeeMusic.ico" /x64
```

### Usage
1. Run `SeeMusicPatcher.exe` (requires Administrator elevation).
2. The target installation path is automatically resolved via Registry / filesystem detection.
3. Click **`[1] INJECT PATCH`** to apply memory hooks and clean textures.
4. Click **`[3] RUN PAID CHECK`** to execute a 3-phase verification pass.
5. Click **`[4] RUN SEEMUSIC`** to launch SeeMusic in full Pro mode.
