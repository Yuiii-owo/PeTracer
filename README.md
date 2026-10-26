# PeTracer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[GitHub repository](https://github.com/Yuiii-owo/PeTracer)

輕量化的 Windows 惡意程式行為沙箱：**Wine + bubblewrap + API Hook 引擎**，不需要 Windows ISO、不需要虛擬機，冷啟動約 1–2 秒。

```
 sample.exe ──► bwrap（namespaces + seccomp）──► Wine（PE loader / ntdll / kernel32）
                                                   │
                                   注入 petracer_agent.dll（INT3 + VEH hooks）
                                                   │
                         agent.jsonl ◄─────────────┘
                              │
   WINEDEBUG(+loaddll,+process) + 靜態 PE 分析 ──► 規則引擎 ──► report.json / report.md
```

## 為什麼不需要 Windows ISO

Wine 本身就是 PE 載入器與 Windows 系統 DLL 的開源重實作（`ntdll.dll`、`kernel32.dll`、`kernelbase.dll`、`ucrtbase.dll`…），並自帶一個可初始化的 `C:\Windows` 目錄結構。PeTracer 只需要：

1. 一次性建立 Wine prefix（`petracer init`，約 10 秒，之後快取）；
2. 每次執行時用 **overlayfs（tmpfs 上層）** 掛載該 prefix —— 樣本的所有寫入都留在記憶體，執行結束即消失；
3. 用 bubblewrap 的 user/mount/pid/net/ipc/uts namespaces 隔離，配合 seccomp-bpf 封鎖逃逸類 syscall。

## 功能總覽

| 層 | 技術 | 產出 |
|---|---|---|
| 隔離 | bwrap `--unshare-all`、唯讀 rootfs、tmpfs 遮蔽 `/home` `/root` `/run`、無網路、`--cap-drop ALL`、`--die-with-parent` | 一次性環境，逾時整組 SIGKILL |
| syscall 限制 | 純 Python 產生的 seccomp BPF denylist（ptrace/mount/bpf/module/keyctl/userns/io_uring…） | 違規呼叫得到 `EPERM` |
| Windows API Hook | `petracer_launch.exe` 以 `CREATE_SUSPENDED` 建立樣本，`CreateRemoteThread(LoadLibraryW)` 注入 `petracer_agent.dll`；agent 用 **INT3 + VEH + TF 單步** 對 ntdll 掛鉤 | `agent.jsonl`（每個呼叫一行 JSON） |
| Wine 追蹤 | `WINEDEBUG=+loaddll,+process`（`--wine-trace` 再加 `+file,+reg`，`--wine-syscall` 加 `+syscall`） | 模組載入、子程序建立、NT syscall 直方圖 |
| 終端追蹤 | IAT stub + ntdll hook，即時輸出 IMPORT/SYSCALL 順序 | 終端機 + `agent.jsonl` |
| 靜態分析 | 自寫 PE parser：machine/sections/imports/overlay/packer/`syscall` 位元組掃描 | `sample.info.json` |
| 檢測 | 18 條行為規則 + ATT&CK 對應 + 加權評分 | 判定 `clean / suspicious / malicious` |
| 產物 | 由 wrapper 在 Wine 結束後把 prefix 內新檔案複製出來 | `artifacts/` + SHA256 |

## 需求

- Linux x86_64（kernel ≥ 5.11 較佳），已啟用 unprivileged user namespaces
- `wine`（測試於 11.20）、`bubblewrap`、`python ≥ 3.10`
- `mingw-w64-gcc`（建置 agent / launcher；32-bit 樣本另需 `i686-w64-mingw32-gcc`）

Arch Linux：

```bash
sudo pacman -S wine bubblewrap mingw-w64-gcc python
```

確認 bwrap 可用：

```bash
bwrap --unshare-all --ro-bind / / true && echo ok
```

## 快速開始

```bash
cd PeTracer
python3 -m petracer init                 # 建立快取 prefix + 編譯 agent（各一次）
python3 -m petracer run -t 30 -o out /path/to/target.exe
python3 -m petracer run -t 30 -o out2 suspicious.exe --  # 樣本參數放在 -- 之後
python3 -m petracer selftest             # 編譯並跑內建測試樣本
```

> 選項請放在樣本路徑**之前**；樣本路徑之後的內容都會原樣傳給樣本。

輸出範例：

```
verdict : MALICIOUS  score=100/100
events  : 44  agent=yes  duration=2.32s  exit=0
findings:
  - [high] Executable memory in a remote process (T1055.002, +30)
  - [high] Run/RunOnce autostart registry write (T1547.001, +35)
  ...
report  : out2/report.md
```

常用參數：

| 參數 | 說明 |
|---|---|
| `-t/--timeout` | wall-clock 逾時（秒），到期 SIGKILL 整個 process group |
| `-o/--out` | 輸出目錄 |
| `--wine-trace` | 加開 `WINEDEBUG=+file,+reg`（量大，僅除錯用） |
| `--wine-syscall` | 加開 `WINEDEBUG=+syscall`：在 NT syscall 邊界統計/取樣（完整直方圖寫入 `report.json` 的 `stats.nt_syscalls`） |
| `--no-agent` | 只保留 WINEDEBUG 層（agent 建置失敗時的回退） |
| `--no-bwrap` | 不隔離直接跑（**僅除錯**，會使用真實 prefix） |
| `--no-seccomp` | 關閉 syscall denylist |
| `--fail-on-malicious` | 判定 malicious 時 exit 3（CI 用） |
| `--keep-work` | 保留暫存工作目錄 |

### 終端追蹤模式：`petracer <target.exe>`

直接在主控台印出**導入函數調用順序**與**NT 系統調用順序**：

```bash
./bin/petracer sample.exe
# 或 pip install -e . 之後：
petracer sample.exe

# 需要選項時用 trace 子命令（選項放在 target 之前）
./bin/petracer trace -t 10 --no-crt -o out sample.exe

# 讓 `petracer` 直接可用
export PATH="$PWD/bin:$PATH"
# 或 pip install -e .

```

輸出範例（hello）：

```text
[  0.000s] AGENT  ready hooks=29 imports=49 image=hello64.exe
[  0.000s] IMPORT  CreateFileW                  a1=0x140004068 a2=0x40000000 a3=0x0 a4=0x0
[  0.000s] SYSCALL NtCreateFile                 path=C:\sandbox_hello.txt access=0x40100080 disposition=5
[  0.000s] IMPORT  WriteFile                    a1=0x40 a2=0x140004092 a3=0x5 a4=0x21fe9c
[  0.000s] SYSCALL NtWriteFile                  path=C:\sandbox_hello.txt size=5
[  0.001s] IMPORT  CloseHandle                  a1=0x40
...
summary: imports=8 syscalls=6 events=15 exit=0 duration=1.22s
verdict: clean (0/100)
```

規則：

- **IMPORT**：agent 對樣本 main module 的 IAT 逐項掛 stub（不是 hook 系統 DLL），因此只記錄「樣本透過自己的 import table」發出的呼叫；x64 會顯示前 4 個 register 參數，x86 只顯示函數名。
- **SYSCALL**：來自 ntdll `Nt*` hook。Win32 呼叫會先印 IMPORT，再印它實際落入的 NT syscall（例如 `CreateFileW` → `NtCreateFile`）。
- **NET**：`connect`/`getaddrinfo`（ws2_32 hook）。
- `--imports-only` / `--syscalls-only`、`--no-crt`（隱藏 ucrt/msvcrt/libgcc）、`--limit N`、`--all`。
- 追蹤是即時的；完整事件仍寫入 `agent.jsonl`/`events.jsonl`，並照常產生 `report.md`。
- 完整輸出範例：[docs/trace-example.txt](docs/trace-example.txt)。

其他子命令：

```bash
python3 -m petracer report out/          # 由既有事件重生成報告
python3 -m petracer selftest             # 編譯 samples/ 並驗證每條規則
PETRACER_E2E=1 python3 -m unittest discover -s tests -v
```

安裝為命令（可選）：

```bash
pip install -e .
petracer run -t 30 -o out sample.exe
```

## 輸出目錄

```
out/
├── meta.json          執行參數、時間、exit code、雜湊、agent 狀態
├── sample.info.json   PE 靜態資訊（sections、imports、syscall 指令數、packer）
├── agent.jsonl        agent 原始事件（Windows API 呼叫）
├── events.jsonl       正規化後事件（agent + WINEDEBUG + sandbox 事件）
├── stdout.log         樣本 stdout
├── stderr.log         Wine / WINEDEBUG / agent 診斷輸出
├── artifacts/         樣本在 C: 新產生或修改的檔案（含 SHA256）
├── report.json        機器可讀判定與證據索引
└── report.md          人讀報告（判定、規則、時間線、IOC）
```

## Hook 清單（agent）

agent 以 `INT3` 改寫函式入口，VEH 還原原始位元組、設定 Trap Flag、記錄參數，單步後重新掛鉤。這種方式不需要搬移指令，能處理 Wine builtin 的任意函式序言。

檔案 / 註冊表：

`NtCreateFile`、`NtOpenFile`、`NtDeleteFile`、`NtWriteFile`、`NtSetInformationFile`、`NtCreateKey`、`NtOpenKey`、`NtOpenKeyEx`、`NtSetValueKey`、`NtDeleteKey`、`NtDeleteValueKey`

記憶體 / 執行緒 / 程序：

`NtAllocateVirtualMemory`、`NtProtectVirtualMemory`、`NtWriteVirtualMemory`、`NtMapViewOfSection`、`NtUnmapViewOfSection`、`NtCreateThread`、`NtCreateThreadEx`、`NtQueueApcThread`、`NtOpenProcess`、`NtCreateUserProcess`、`NtTerminateProcess`

偵測規避 / 網路：

`NtQueryInformationProcess`、`NtSetInformationThread`、`NtDelayExecution`、`NtLoadDriver`、`ws2_32!connect`、`ws2_32!WSAConnect`、`ws2_32!getaddrinfo`

事件包含：`ts / pid / tid / type / api / caller / origin`，以及 `path / handle / target_pid / base / size / protect / address / port…`。`origin=sample` 表示呼叫堆疊中含樣本映像，`system` 代表 Wine 內部間接呼叫。

檔案與登錄檔路徑來源：
- 建立/開啟時解析 `OBJECT_ATTRIBUTES.ObjectName`；
- 寫入/刪除/改名時對 handle 呼叫 `NtQueryObject(ObjectNameInformation)` / `NtQueryKey(KeyNameInformation)`，因此呼叫者堆疊已回收也能取得路徑；
- 程序 handle 以 `GetProcessId` 解析，能區分本程序與遠端程序。

## 檢測規則

| rule | 權重 | 技術 | 說明 |
|---|---:|---|---|
| `process_injection` | 55 | T1055 | 遠端配置 + 寫入 + 遠端執行緒（跨程序注入） |
| `remote_rwx` | 30 | T1055.002 | 遠端記憶體被設為可執行（RWX/RX） |
| `private_rwx` | 25 | T1055.009 | 本程序私有配置（64 B–64 KB）轉為可執行（shellcode staging） |
| `shellcode_execution` | 40 | T1055.009 | 私有 RWX 後緊接崩潰或子程序（載入器轉移控制流） |
| `execution_crash` | 10 | T1497.001 | Wine 回報 page fault/未處理例外（payload 執行跡象） |
| `persistence_run_key` | 35 | T1547.001 | `CurrentVersion\Run` / `RunOnce` |
| `persistence_service` | 35 | T1543.003 | `CurrentControlSet\Services` |
| `persistence_startup_folder` | 30 | T1547.001 | 啟動資料夾寫入 |
| `dropper` | 35 | T1105 | 可執行檔/腳本落地到使用者可寫路徑並執行 |
| `defense_tampering` | 40 | T1562.001 | Defender/防火牆/UAC/系統目錄遭修改 |
| `mass_file_modification` | 45 | T1486 | 大量改寫/改名或勒索副檔名 |
| `anti_debug` | 20 | T1622 | DebugPort/DebugObject/HideFromDebugger 或靜態反偵測 import |
| `long_sleep` | 10 | T1497.003 | 單次睡眠 ≥ 60 秒 |
| `network_activity` | 20 | T1071 | connect / DNS |
| `direct_syscall` | 30 | T1106 | 映像中含 inline `syscall`/`sysenter`/`int 2e` |
| `driver_load` | 60 | T1543.003 | `NtLoadDriver` |
| `self_delete` | 20 | T1070.004 | 刪除/改名自身映像 |
| `side_loaded_module` | 10 | T1129 | 從非系統路徑載入 DLL |

評分為規則權重和（上限 100）：`≥ 60 malicious`、`≥ 20 suspicious`、其餘 `clean`。

## 隔離模型

bwrap 實際參數（見 `petracer/sandbox.py`）：

```
--unshare-all --die-with-parent --new-session --cap-drop ALL
--ro-bind / /
--tmpfs /home --tmpfs /root --tmpfs /run
--proc /proc --dev /dev --tmpfs /tmp --tmpfs /dev/shm
--dir /tmp/prefix
--overlay-src <cache>/prefix --tmp-overlay /tmp/prefix
--bind <out> /tmp/petracer-out        # 唯一可寫的宿主目錄
--bind <work>/sample /tmp/sample      # 樣本 + agent（可寫但暫存）
--seccomp <fd>
--clearenv ...
```

- Wine 的 `Z:` 在沙箱內指向**沙箱 root**（不是宿主 `/`）：`/home`、`/root`、`/run` 已被 tmpfs 覆蓋，`/usr` 唯讀，`/tmp` 是新 tmpfs。
- 預設無網路（`--unshare-all`）；樣本仍會看到 `connect()` 失敗，但 hook 會先記錄目標。
- 逾時由宿主 `killpg(SIGKILL)`，bwrap `--die-with-parent` 會帶走 wineserver 與所有子程序；實測無殘留。
- seccomp 封鎖：`ptrace`、`mount/umount2/pivot_root/chroot`、`bpf`、`perf_event_open`、`kexec_*`、`init_module/finit_module/delete_module`、`keyctl/add_key`、`open_by_handle_at`、`unshare/setns`、`swapon/reboot/syslog/iopl`、`io_uring_*`、`seccomp` 等；違規回 `EPERM`（不直接殺程序，讓 Wine 走正常錯誤路徑）。

## 已知限制

- **使用者態隔離，不是硬體 VM**：抵禦的是樣本對宿主檔案/網路/其他程序的存取；核心提權（kernel exploit）不在防護範圍，請搭配 VM 或專用主機分析高風險樣本。
- **Wine 偵測**：樣本可用 `wine_get_version`、註冊表特徵、`ntdll` 位址等發現 Wine；PeTracer 目前不偽裝。
- **Direct syscall**：目前以靜態掃描映像中的 `syscall` 位元組偵測；繞過 ntdll 的執行期呼叫在 PE 側沒有事件（Wine 的 Syscall User Dispatch 會處理，但不會回報給 agent）。
- **多執行緒競態**：INT3 掛鉤在還原位元組到重新掛鉤之間有極短窗口，其他執行緒可能漏記一次呼叫；不影響判定方向。
- **GUI**：無 X/Wayland 時樣本可能建立視窗失敗；`--headless` 由 Wine 自行回退。
- **32-bit**：需 `i686-w64-mingw32-gcc`；agent/launcher 以 `-static` 連結，避免 Wine prefix 缺少 `libgcc_s_dw2-1.dll`。
- **Wine 版本**：hook 依賴 Wine builtin 的匯出函式；不同 Wine 版本可能少數函式缺失（agent 會跳過），但 `Nt*` 介面穩定。
- **事件遺失**：agent 對 `WriteFile` 的日誌本身也會觸發 hook，已用 TLS guard 防止遞迴；高頻樣本仍可能因 8 KB 事件緩衝截斷。
- **日誌可被樣本竄改**：`Z:\tmp\petracer-out` 對樣本可寫（agent 需要寫入）；高對抗樣本可以修改/刪除 `agent.jsonl`。需要防竄改時請把輸出改為 pipe、或在樣本執行後立即唯讀化。
- **IMPORT 行的範圍**：只涵蓋樣本 IAT；`GetProcAddress`/delay-load/自建 resolver（例如 shellcode 的 PEB walk）不會產生 IMPORT 行，但其 ntdll 呼叫仍可能出現在 SYSCALL 行。x64 只顯示前 4 個 register 參數。
- **`+syscall` 體積**：hello 一個樣本就會產生約 4 萬行 syscall 記錄；PeTracer 只保留高訊號 syscall 的取樣事件（每種 200 筆）並另外保存完整直方圖，原始輸出仍在 `stderr.log`。

## 設計取捨：為什麼不用 Frida

參考方案中的 Frida 附加在 Wine 上實測不可行：Frida 的注入 helper 不是目標程序的祖先，在 `kernel.yama.ptrace_scope=1` 下 `PTRACE_ATTACH` 被拒；放寬 yama 後，Wine 的 Syscall User Dispatch／執行環境也讓 foreign thread 注入不穩定。因此改為：

- 自製 `petracer_launch.exe`：`CreateProcessW(CREATE_SUSPENDED)` → `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryW)`；
- 以具名事件同步，確保 hook 全部裝好才 `ResumeThread`；
- agent 以 INT3 + VEH 實作，不依賴任何 Linux 注入或 root 權限。

WINEDEBUG 仍然保留為零侵入的第二層（模組載入、子程序），`+relay` 因體積過大未預設啟用。

## 專案結構

```
petracer/
  agent/petracer_agent.c    # 注入 DLL：29 個 hooks、JSONL 事件
  agent/petracer_launch.c   # suspended 啟動 + 注入 + 等 ready
  sandbox.py                # prefix、bwrap、逾時、事件收集
  seccomp.py                # 純 Python BPF 產生器
  events.py / winedebug.py  # 事件模型、WINEDEBUG 解析
  detect/rules.py           # 規則與評分
  report.py                 # JSON/Markdown
  trace.py                  # `petracer <target.exe>` 即時追蹤與輸出格式
  cli.py                    # init / run / trace / report / selftest
bin/petracer                # 不安裝套件時的直接執行 wrapper
samples/                    # 良性行為樣本（hello…probe）
tests/                      # unittest（PE、規則、parser、seccomp、e2e）
```

## 測試

```bash
python3 -m unittest discover -s tests -v     # 單元測試（不需 Wine）
python3 -m petracer selftest                 # 端到端：編譯 9 個樣本並驗證規則
PETRACER_E2E=1 python3 -m unittest tests.test_e2e -v
```

Selftest 目前涵蓋：`hello`（零告警）、`persist`、`dropper`、`inject`、`rwx`、`antidebug`、`netprobe`、`directsyscall`、`probe`。

## License

MIT，見 [LICENSE](LICENSE)。
