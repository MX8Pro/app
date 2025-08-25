// Shadow Core V99 | Mission: In-Game Cheat Overlay (Complete CT Replication)
// Target Process: GRW.exe
// Language: C# (.NET Framework, Windows Forms)
//
// IMPORTANT: You MUST compile this project with the Platform Target set to "x64".

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Globalization;
using System.ComponentModel;
using System.Text;

namespace ShadowCore // تأكد من أن هذا يطابق اسم مشروعك
{
    public class CheatMenu : Form
    {
        // --- Base Class for all Cheat Types ---
        public abstract class CheatItem
        {
            public string Name { get; protected set; }
            protected CheatItem(string name) { Name = name; }
        }

        // --- Class for Code Patches (On/Off Cheats) ---
        public class PatchCheat : CheatItem
        {
            public string[] Patterns { get; }
            public byte[] BytesOn { get; }
            public byte[] BytesOff { get; }
            public int Offset { get; }
            public IntPtr ResolvedAddress { get; set; }

            public PatchCheat(string name, string pattern, byte[] bytesOn, byte[] bytesOff, int offset = 0)
                : this(name, new[] { pattern }, bytesOn, bytesOff, offset) { }

            public PatchCheat(string name, string[] patterns, byte[] bytesOn, byte[] bytesOff, int offset = 0) : base(name)
            {
                Patterns = patterns;
                BytesOn = bytesOn;
                BytesOff = bytesOff;
                Offset = offset;
                ResolvedAddress = IntPtr.Zero;
            }
        }

        // --- Class for Pointer-based Values (e.g., Skill Points) ---
        public class PointerCheat : CheatItem
        {
            public string[] Patterns { get; }
            public int PointerInstructionOffset { get; }
            public int[] Offsets { get; }
            public IntPtr ResolvedAddress { get; set; }
            public Type DataType { get; } // e.g., typeof(int), typeof(byte)

            public PointerCheat(string name, string pattern, int pointerInstructionOffset, int[] offsets, Type dataType)
                : this(name, new[] { pattern }, pointerInstructionOffset, offsets, dataType) { }

            public PointerCheat(string name, string[] patterns, int pointerInstructionOffset, int[] offsets, Type dataType) : base(name)
            {
                Patterns = patterns;
                PointerInstructionOffset = pointerInstructionOffset;
                Offsets = offsets;
                ResolvedAddress = IntPtr.Zero;
                DataType = dataType;
            }
        }

        // --- All Cheat Definitions from GRW.CT ---
        private static readonly List<CheatItem> Cheats = new List<CheatItem>
        {
            // --- Patch Cheats ---
            new PatchCheat("وضع الخلود", "48 89 5C 24 10 48 89 6C 24 18", new byte[] { 0xC3 }, new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x10 }),
            new PatchCheat("خلود المركبة", "48 89 5C 24 08 48 89 6C 24 10", new byte[] { 0xC3 }, new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x08 }),
            new PatchCheat("حصانة / إخفاء", "0F B6 41 78 C3", new byte[] { 0xB0, 0x01, 0xC3 }, new byte[] { 0x0F, 0xB6, 0x41, 0x78, 0xC3 }),
            new PatchCheat("ذخيرة لانهائية", "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 06 80 78 30 00 75 ?? 48 8B 81", new byte[] { 0x90, 0x90 }, new byte[] { 0x75, 0xE1 }, 10),
            new PatchCheat("بدون إعادة تلقيم", "48 89 5C 24 ?? 57 48 83 EC 20", new byte[] { 0xC3 }, new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x10 }),
            new PatchCheat("بدون ارتداد", "48 89 E0 F3 0F 11 48 10", new byte[] { 0xC3 }, new byte[] { 0x48, 0x89, 0xE0, 0xF3, 0x0F, 0x11, 0x48, 0x10 }),
            new PatchCheat("دقة فائقة", "80 BB F4 00 00 00 00", new byte[] { 0xC6, 0x83, 0xF4, 0x00, 0x00, 0x00, 0x01 }, new byte[] { 0x80, 0xBB, 0xF4, 0x00, 0x00, 0x00, 0x00 }),
            new PatchCheat("بطارية طائرة بدون طيار لانهائية", "0F 28 F0 74 ?? 48 C7 87 ?? ?? ?? ?? FF FF FF FF EB", new byte[] { 0x90, 0x90 }, new byte[] { 0x74, 0x0D }, 2),
            new PatchCheat("مدى طائرة بدون طيار لانهائي", "48 8B 8E ?? ?? ?? ?? 48 85 C9 74 ?? E8", new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, new byte[] { 0x48, 0x8B, 0x8E, 0xB8, 0x01, 0x00, 0x00 }),
            new PatchCheat("إزالة تباطؤ التصويب المتزامن", "48 89 5C 24 08 48 89 74 24 10 57", new byte[] { 0xC3 }, new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x08 }),
            new PatchCheat("إزالة تباطؤ دعم المتمردين", "53 48 83 EC 30 48 89 CB 8B 49 20", new byte[] { 0xEB, 0x04 }, new byte[] { 0x0F, 0x84 }, 84),
            new PatchCheat("وصول سريع للمستوى الأعلى", "44 01 F8 41 89 C7 45 29 F7 45 85 FF", new byte[] { 0x41, 0x8B, 0xC6 }, new byte[] { 0x44, 0x01, 0xF8 }),
            new PatchCheat("مستوى أقصى فوري", "48 8B 14 19 3B 42 10 0F", new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, new byte[] { 0x3B, 0x42, 0x10, 0x0F }, 2),

            // --- Pointer Cheats ---
            new PointerCheat("نقاط المهارة", "53 48 83 EC 20 8B 51 18 48 89 CB 48 8B 0D ?? ?? ?? ?? E8", 11, new int[] { 0x1C }, typeof(int)),
            new PointerCheat("المستوى", "89 87 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 89 D9 E8", 6, new int[] { 0x40, 0x0 }, typeof(int)) // Simplified to get the base for level struct
        };

        // --- WinAPI Imports ---
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, int cb);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, int nSize);

        // --- Constants & State ---
        private const uint PROCESS_PERMISSIONS = 0x0010 | 0x0020 | 0x0008 | 0x0400; // VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION
        private const uint LIST_MODULES_ALL = 0x03;
        private const int MAX_READ_RETRIES = 3;
        private IntPtr processHandle;
        private Process? targetProcess;
        private bool isAttached = false;
        private IntPtr baseAddress;
        private long moduleSize;
        private readonly SemaphoreSlim processSemaphore = new SemaphoreSlim(1, 1);
        private int scanChunkSize = 0x10000; // Adjustable chunk size
        public int ScanChunkSize { get => scanChunkSize; set => scanChunkSize = value < 0x1000 ? 0x1000 : value; }

        // --- UI Elements ---
        private Label lblStatus = null!;
        private System.Windows.Forms.Timer statusTimer = null!;
        private Panel titleBar = null!;
        private Label lblTitle = null!;
        private Button btnClose = null!;
        private Point lastPoint;
        private Panel cheatPanel = null!;
        private Dictionary<string, CheckBox> patchCheckBoxes = new Dictionary<string, CheckBox>();
        private Dictionary<string, (Label lbl, TextBox txt, Button btn)> pointerControls = new Dictionary<string, (Label, TextBox, Button)>();

        public CheatMenu()
        {
            InitializeComponent();
            this.TopMost = true;
        }

        private void InitializeComponent()
        {
            this.Name = "CheatMenu";
            this.Text = "SHΔDØW CORE V99";
            this.Size = new Size(360, 650);
            this.FormBorderStyle = FormBorderStyle.None;
            this.BackColor = Color.FromArgb(20, 20, 20);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.RightToLeft = RightToLeft.Yes;
            this.RightToLeftLayout = true;

            titleBar = new Panel { BackColor = Color.FromArgb(45, 45, 48), Dock = DockStyle.Top, Height = 30 };
            titleBar.MouseDown += (s, e) => lastPoint = new Point(e.X, e.Y);
            titleBar.MouseMove += (s, e) => { if (e.Button == MouseButtons.Left) { this.Left += e.X - lastPoint.X; this.Top += e.Y - lastPoint.Y; } };
            lblTitle = new Label { Text = "GRW | شادو كور", ForeColor = Color.FromArgb(255, 0, 0), Location = new Point(5, 5), Font = new Font("Tahoma", 10, FontStyle.Bold), AutoSize = true };
            btnClose = new Button { Text = "X", ForeColor = Color.White, BackColor = Color.FromArgb(45, 45, 48), FlatStyle = FlatStyle.Flat, Location = new Point(0, 0), Size = new Size(30, 30) };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();
            titleBar.Controls.Add(lblTitle);
            titleBar.Controls.Add(btnClose);
            this.Controls.Add(titleBar);

            lblStatus = new Label { Text = "الحالة: في انتظار عملية الهدف (GRW.exe)...", ForeColor = Color.Red, Location = new Point(10, 40), Font = new Font("Tahoma", 9), AutoSize = true };
            this.Controls.Add(lblStatus);

            cheatPanel = new Panel { Location = new Point(10, 70), Size = new Size(this.Width - 20, this.Height - 80), AutoScroll = true };
            this.Controls.Add(cheatPanel);
            
            int topPosition = 10;

            foreach (var cheat in Cheats.OfType<PatchCheat>())
            {
                var chk = new CheckBox { Text = cheat.Name, ForeColor = Color.White, Location = new Point(15, topPosition), AutoSize = true, Font = new Font("Tahoma", 10, FontStyle.Bold), Enabled = false };
                chk.CheckedChanged += (s, e) => TogglePatch(cheat, chk.Checked);
                cheatPanel.Controls.Add(chk);
                patchCheckBoxes[cheat.Name] = chk;
                topPosition += 30;
            }

            var separator = new Label { Text = "--- بيانات اللاعب ---", ForeColor = Color.DimGray, Location = new Point(15, topPosition), AutoSize = true, Font = new Font("Tahoma", 10, FontStyle.Bold) };
            cheatPanel.Controls.Add(separator);
            topPosition += 30;

            foreach (var cheat in Cheats.OfType<PointerCheat>())
            {
                var lbl = new Label { Text = cheat.Name, ForeColor = Color.White, Location = new Point(150, topPosition + 3), AutoSize = true, Font = new Font("Tahoma", 9) };
                var txt = new TextBox { Location = new Point(70, topPosition), Width = 70, Enabled = false, TextAlign = HorizontalAlignment.Center };
                var btn = new Button { Text = "تطبيق", Location = new Point(15, topPosition), Enabled = false, Size = new Size(50, 23) };
                btn.Click += (s, e) => WritePointerValue(cheat, txt.Text);
                
                cheatPanel.Controls.Add(lbl);
                cheatPanel.Controls.Add(txt);
                cheatPanel.Controls.Add(btn);
                pointerControls[cheat.Name] = (lbl, txt, btn);
                topPosition += 30;
            }

            statusTimer = new System.Windows.Forms.Timer { Interval = 1500 };
            statusTimer.Tick += StatusTimer_Tick;
            statusTimer.Start();
        }

        private void StatusTimer_Tick(object? sender, EventArgs e)
        {
            if (!processSemaphore.Wait(0)) return;
            try
            {
                var processes = Process.GetProcessesByName("GRW");
                if (processes.Length > 0)
                {
                    if (!isAttached)
                    {
                        try
                        {
                            targetProcess = processes[0];
                            processHandle = OpenProcess(PROCESS_PERMISSIONS, false, targetProcess.Id);
                            if (processHandle != IntPtr.Zero && targetProcess != null)
                            {
                                try
                                {
                                    var module = targetProcess.MainModule;
                                    if (module != null)
                                    {
                                        baseAddress = module.BaseAddress;
                                        moduleSize = module.ModuleMemorySize;
                                        isAttached = true;
                                        lblStatus.Text = $"الحالة: متصل بـ GRW.exe (PID: {targetProcess.Id})";
                                        lblStatus.ForeColor = Color.LimeGreen;
                                        SetControlsEnabled(true);
                                    }
                                }
                                catch (Win32Exception)
                                {
                                    CloseHandle(processHandle);
                                }
                            }
                        }
                        catch { }
                    }
                    if (isAttached)
                    {
                        foreach (var cheat in Cheats.OfType<PointerCheat>())
                        {
                            ReadPointerValue(cheat);
                        }
                    }
                }
                else if (isAttached)
                {
                    CloseHandle(processHandle);
                    isAttached = false;
                    targetProcess = null;
                    baseAddress = IntPtr.Zero;
                    moduleSize = 0;
                    lblStatus.Text = "الحالة: فقدت عملية الهدف. في انتظار GRW.exe...";
                    lblStatus.ForeColor = Color.Red;
                    SetControlsEnabled(false);
                    foreach (var chk in patchCheckBoxes.Values) chk.Checked = false;
                }
            }
            finally
            {
                processSemaphore.Release();
            }
        }

        private void ReadPointerValue(PointerCheat cheat)
        {
            if (cheat.ResolvedAddress == IntPtr.Zero)
            {
                cheat.ResolvedAddress = ResolvePointer(cheat);
            }
            if (cheat.ResolvedAddress != IntPtr.Zero)
            {
                int size = Marshal.SizeOf(cheat.DataType);
                byte[] buffer = new byte[size];
                if (ReadProcessMemory(processHandle, cheat.ResolvedAddress, buffer, buffer.Length, out _))
                {
                    object value = 0;
                    if (cheat.DataType == typeof(int)) value = BitConverter.ToInt32(buffer, 0);
                    else if (cheat.DataType == typeof(byte)) value = buffer[0];

                    if (pointerControls.TryGetValue(cheat.Name, out var controls))
                    {
                        controls.txt.Text = value.ToString();
                    }
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();
                    Log($"Failed to read pointer value for '{cheat.Name}' at 0x{cheat.ResolvedAddress.ToInt64():X} (err {err})");
                }
            }
        }

        private void WritePointerValue(PointerCheat cheat, string valueStr)
        {
            if (isAttached && cheat.ResolvedAddress != IntPtr.Zero && long.TryParse(valueStr, out long value))
            {
                processSemaphore.Wait();
                try
                {
                    byte[] buffer;
                    if (cheat.DataType == typeof(int))
                    {
                        if (value < int.MinValue || value > int.MaxValue)
                        {
                            Log($"Value {value} out of range for int");
                            return;
                        }
                        buffer = BitConverter.GetBytes((int)value);
                    }
                    else if (cheat.DataType == typeof(byte))
                    {
                        if (value < byte.MinValue || value > byte.MaxValue)
                        {
                            Log($"Value {value} out of range for byte");
                            return;
                        }
                        buffer = new byte[] { (byte)value };
                    }
                    else return;

                    if (!WriteProcessMemory(processHandle, cheat.ResolvedAddress, buffer, buffer.Length, out _))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Log($"WriteProcessMemory failed for '{cheat.Name}' at 0x{cheat.ResolvedAddress.ToInt64():X} (err {err})");
                    }
                }
                finally
                {
                    processSemaphore.Release();
                }
            }
        }

        private IntPtr ResolvePointer(PointerCheat cheat)
        {
            try
            {
                IntPtr basePtrAddr = FindPattern(cheat.Patterns);
                if (basePtrAddr == IntPtr.Zero)
                {
                    Log($"Pointer '{cheat.Name}': base pattern not found");
                    return IntPtr.Zero;
                }

                byte[] buffer = new byte[4];
                if (!ReadProcessMemory(processHandle, IntPtr.Add(basePtrAddr, cheat.PointerInstructionOffset + 3), buffer, 4, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    Log($"Pointer '{cheat.Name}': failed to read instruction (err {err})");
                    return IntPtr.Zero;
                }
                int relativeOffset = BitConverter.ToInt32(buffer, 0);
                IntPtr pointerBase = IntPtr.Add(basePtrAddr, cheat.PointerInstructionOffset + 7 + relativeOffset);

                IntPtr currentAddr = pointerBase;
                byte[] addrBuffer = new byte[8];
                for (int i = 0; i < cheat.Offsets.Length; i++)
                {
                    if (!ReadProcessMemory(processHandle, currentAddr, addrBuffer, 8, out _))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Log($"Pointer '{cheat.Name}': failed reading level {i} at 0x{currentAddr.ToInt64():X} (err {err})");
                        return IntPtr.Zero;
                    }
                    currentAddr = (IntPtr)BitConverter.ToInt64(addrBuffer, 0);
                    if (currentAddr == IntPtr.Zero)
                    {
                        Log($"Pointer '{cheat.Name}': null pointer at level {i}");
                        return IntPtr.Zero;
                    }
                    if (i < cheat.Offsets.Length -1)
                    {
                         currentAddr = IntPtr.Add(currentAddr, cheat.Offsets[i]);
                    }
                }
                return IntPtr.Add(currentAddr, cheat.Offsets.Last());
            }
            catch (Exception ex)
            {
                Log($"ResolvePointer exception for '{cheat.Name}': {ex.Message}");
                return IntPtr.Zero;
            }
        }

        private void TogglePatch(PatchCheat cheat, bool enable)
        {
            if (!isAttached) return;
            Task.Run(() =>
            {
                processSemaphore.Wait();
                try
                {
                    IntPtr address = cheat.ResolvedAddress;
                    if (address == IntPtr.Zero)
                    {
                        address = FindPattern(cheat.Patterns);
                        cheat.ResolvedAddress = address;
                    }
                    if (address != IntPtr.Zero)
                    {
                        byte[] bytesToWrite = enable ? cheat.BytesOn : cheat.BytesOff;
                        if (!WriteMemory(IntPtr.Add(address, cheat.Offset), bytesToWrite))
                        {
                            int err = Marshal.GetLastWin32Error();
                            Log($"WriteMemory failed for '{cheat.Name}' at 0x{address.ToInt64():X} (err {err}); rescanning");
                            cheat.ResolvedAddress = IntPtr.Zero;
                            address = FindPattern(cheat.Patterns);
                            cheat.ResolvedAddress = address;
                            if (address != IntPtr.Zero)
                                WriteMemory(IntPtr.Add(address, cheat.Offset), bytesToWrite);
                        }
                    }
                    else
                    {
                        Log($"Pattern not found for '{cheat.Name}'");
                        this.Invoke((MethodInvoker)delegate { if (patchCheckBoxes.TryGetValue(cheat.Name, out var chk)) chk.Checked = false; });
                    }
                }
                finally
                {
                    processSemaphore.Release();
                }
            });
        }

        private void SetControlsEnabled(bool enabled)
        {
            foreach (var chk in patchCheckBoxes.Values) chk.Enabled = enabled;
            foreach (var controls in pointerControls.Values)
            {
                controls.txt.Enabled = enabled;
                controls.btn.Enabled = enabled;
            }
        }

        private bool WriteMemory(IntPtr address, byte[] bytes) => WriteProcessMemory(processHandle, address, bytes, bytes.Length, out _);

        private void Log(string message) => Debug.WriteLine(message);

        private IntPtr FindPattern(string[] patterns)
        {
            if (!isAttached) return IntPtr.Zero;
            foreach (var pat in patterns)
            {
                var (patBytes, mask) = ParsePattern(pat);
                Log($"Scanning for pattern '{pat}'");
                foreach (var (modBase, modSize, modName) in EnumerateModules())
                {
                    IntPtr found = ScanModule(modBase, modSize, patBytes, mask, out int matches);
                    Log($"Module {modName}: found {matches} match(es)");
                    if (matches > 0)
                    {
                        Log($"Using address 0x{found.ToInt64():X}");
                        return found;
                    }
                }
                Log($"Pattern '{pat}' not found in any module");
            }
            Log("All provided patterns failed");
            return IntPtr.Zero;
        }

        private IEnumerable<(IntPtr baseAddress, int size, string name)> EnumerateModules()
        {
            EnumProcessModulesEx(processHandle, Array.Empty<IntPtr>(), 0, out int needed, LIST_MODULES_ALL);
            int count = needed / IntPtr.Size;
            IntPtr[] modules = new IntPtr[count];
            if (!EnumProcessModulesEx(processHandle, modules, needed, out needed, LIST_MODULES_ALL))
                yield break;
            int modInfoSize = Marshal.SizeOf<MODULEINFO>();
            foreach (var module in modules)
            {
                if (GetModuleInformation(processHandle, module, out MODULEINFO info, modInfoSize))
                {
                    StringBuilder name = new StringBuilder(260);
                    GetModuleBaseName(processHandle, module, name, name.Capacity);
                    yield return (info.lpBaseOfDll, info.SizeOfImage, name.ToString());
                }
            }
        }

        private IntPtr ScanModule(IntPtr moduleBase, long moduleSize, byte[] patternBytes, bool[] mask, out int matchCount)
        {
            matchCount = 0;
            IntPtr firstMatch = IntPtr.Zero;
            int patternLength = patternBytes.Length;
            IntPtr current = moduleBase;
            long remaining = moduleSize;
            while (remaining > 0)
            {
                if (VirtualQueryEx(processHandle, current, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == IntPtr.Zero)
                    break;
                long regionSize = Math.Min(remaining, (long)mbi.RegionSize);
                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    byte[] buffer = new byte[scanChunkSize];
                    for (long offset = 0; offset < regionSize; offset += Math.Max(1, scanChunkSize - patternLength))
                    {
                        int bytesToRead = (int)Math.Min(scanChunkSize, regionSize - offset);
                        IntPtr readAddr = IntPtr.Add(current, (int)offset);
                        int bytesRead = 0;
                        bool success = false;
                        for (int attempt = 0; attempt < MAX_READ_RETRIES; attempt++)
                        {
                            if (ReadProcessMemory(processHandle, readAddr, buffer, bytesToRead, out bytesRead))
                            {
                                success = true;
                                break;
                            }
                        }
                        if (!success)
                        {
                            Log($"ReadProcessMemory failed at 0x{readAddr.ToInt64():X}");
                            continue;
                        }
                        for (int i = 0; i <= bytesRead - patternLength; i++)
                        {
                            bool found = true;
                            for (int j = 0; j < patternLength; j++)
                            {
                                if (!mask[j] && buffer[i + j] != patternBytes[j])
                                {
                                    found = false;
                                    break;
                                }
                            }
                            if (found)
                            {
                                if (matchCount == 0)
                                    firstMatch = IntPtr.Add(readAddr, i);
                                matchCount++;
                            }
                        }
                    }
                }
                long advance = regionSize;
                current = IntPtr.Add(current, (int)advance);
                remaining -= advance;
            }
            return firstMatch;
        }

        private (byte[] bytes, bool[] mask) ParsePattern(string pattern)
        {
            var tokens = pattern.Split(' ');
            var bytes = new byte[tokens.Length];
            var mask = new bool[tokens.Length];
            for (int i = 0; i < tokens.Length; i++)
            {
                if (tokens[i] == "??")
                {
                    mask[i] = true;
                    bytes[i] = 0;
                }
                else
                {
                    mask[i] = false;
                    bytes[i] = byte.Parse(tokens[i], NumberStyles.HexNumber);
                }
            }
            return (bytes, mask);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public int SizeOfImage;
            public IntPtr EntryPoint;
        }

        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;

        private bool IsReadable(uint protect)
        {
            if ((protect & PAGE_GUARD) != 0 || protect == PAGE_NOACCESS) return false;
            return protect == 0x02 || protect == 0x04 || protect == 0x08 || protect == 0x20 || protect == 0x40 || protect == 0x80;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (isAttached)
            {
                foreach (var cheat in Cheats.OfType<PatchCheat>())
                {
                    if (patchCheckBoxes.TryGetValue(cheat.Name, out var chk) && chk.Checked)
                    {
                        TogglePatch(cheat, false);
                    }
                }
                CloseHandle(processHandle);
            }
            base.OnFormClosing(e);
        }
    }
}
