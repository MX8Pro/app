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
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Globalization;

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
            public string Pattern { get; }
            public byte[] BytesOn { get; }
            public byte[] BytesOff { get; }
            public int Offset { get; }

            public PatchCheat(string name, string pattern, byte[] bytesOn, byte[] bytesOff, int offset = 0) : base(name)
            {
                Pattern = pattern;
                BytesOn = bytesOn;
                BytesOff = bytesOff;
                Offset = offset;
            }
        }

        // --- Class for Pointer-based Values (e.g., Skill Points) ---
        public class PointerCheat : CheatItem
        {
            public string Pattern { get; }
            public int PointerInstructionOffset { get; }
            public int[] Offsets { get; }
            public IntPtr ResolvedAddress { get; set; }
            public Type DataType { get; } // e.g., typeof(int), typeof(byte)

            public PointerCheat(string name, string pattern, int pointerInstructionOffset, int[] offsets, Type dataType) : base(name)
            {
                Pattern = pattern;
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

        // --- Constants & State ---
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private IntPtr processHandle;
        private Process? targetProcess;
        private bool isAttached = false;
        private IntPtr baseAddress;

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
            var processes = Process.GetProcessesByName("GRW");
            if (processes.Length > 0)
            {
                if (!isAttached)
                {
                    targetProcess = processes[0];
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);
                    if (processHandle != IntPtr.Zero && targetProcess.MainModule != null)
                    {
                        baseAddress = targetProcess.MainModule.BaseAddress;
                        isAttached = true;
                        lblStatus.Text = $"الحالة: متصل بـ GRW.exe (PID: {targetProcess.Id})";
                        lblStatus.ForeColor = Color.LimeGreen;
                        SetControlsEnabled(true);
                    }
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
                lblStatus.Text = "الحالة: فقدت عملية الهدف. في انتظار GRW.exe...";
                lblStatus.ForeColor = Color.Red;
                SetControlsEnabled(false);
                foreach (var chk in patchCheckBoxes.Values) chk.Checked = false;
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
                ReadProcessMemory(processHandle, cheat.ResolvedAddress, buffer, buffer.Length, out _);
                object value = 0;
                if (cheat.DataType == typeof(int)) value = BitConverter.ToInt32(buffer, 0);
                else if (cheat.DataType == typeof(byte)) value = buffer[0];
                
                if (pointerControls.TryGetValue(cheat.Name, out var controls))
                {
                    controls.txt.Text = value.ToString();
                }
            }
        }

        private void WritePointerValue(PointerCheat cheat, string valueStr)
        {
            if (isAttached && cheat.ResolvedAddress != IntPtr.Zero && long.TryParse(valueStr, out long value))
            {
                byte[] buffer;
                if (cheat.DataType == typeof(int)) buffer = BitConverter.GetBytes((int)value);
                else if (cheat.DataType == typeof(byte)) buffer = new byte[] { (byte)value };
                else return;
                
                WriteProcessMemory(processHandle, cheat.ResolvedAddress, buffer, buffer.Length, out _);
            }
        }

        private IntPtr ResolvePointer(PointerCheat cheat)
        {
            try
            {
                IntPtr basePtrAddr = FindPattern(cheat.Pattern);
                if (basePtrAddr == IntPtr.Zero) return IntPtr.Zero;

                byte[] buffer = new byte[4];
                ReadProcessMemory(processHandle, IntPtr.Add(basePtrAddr, cheat.PointerInstructionOffset + 3), buffer, 4, out _);
                int relativeOffset = BitConverter.ToInt32(buffer, 0);
                IntPtr pointerBase = IntPtr.Add(basePtrAddr, cheat.PointerInstructionOffset + 7 + relativeOffset);
                
                IntPtr currentAddr = pointerBase;
                byte[] addrBuffer = new byte[8];
                for (int i = 0; i < cheat.Offsets.Length; i++)
                {
                    ReadProcessMemory(processHandle, currentAddr, addrBuffer, 8, out _);
                    currentAddr = (IntPtr)BitConverter.ToInt64(addrBuffer, 0);
                    if (currentAddr == IntPtr.Zero) return IntPtr.Zero;
                    if (i < cheat.Offsets.Length -1) // Apply all but the last offset to the address
                    {
                         currentAddr = IntPtr.Add(currentAddr, cheat.Offsets[i]);
                    }
                }
                // Apply the final offset
                return IntPtr.Add(currentAddr, cheat.Offsets.Last());
            }
            catch { return IntPtr.Zero; }
        }

        private void TogglePatch(PatchCheat cheat, bool enable)
        {
            if (!isAttached) return;
            Task.Run(() =>
            {
                IntPtr address = FindPattern(cheat.Pattern);
                if (address != IntPtr.Zero)
                {
                    byte[] bytesToWrite = enable ? cheat.BytesOn : cheat.BytesOff;
                    WriteMemory(IntPtr.Add(address, cheat.Offset), bytesToWrite);
                }
                else
                {
                    MessageBox.Show($"تعذر العثور على نمط الذاكرة لـ '{cheat.Name}'.", "خطأ", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.Invoke((MethodInvoker)delegate { if (patchCheckBoxes.TryGetValue(cheat.Name, out var chk)) chk.Checked = !enable; });
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

        private IntPtr FindPattern(string pattern)
        {
            if (targetProcess == null || !isAttached || targetProcess.HasExited || targetProcess.MainModule == null)
                return IntPtr.Zero;
            try
            {
                var module = targetProcess.MainModule;
                int moduleSize = module!.ModuleMemorySize;
                var moduleBytes = new byte[moduleSize];
                ReadProcessMemory(processHandle, baseAddress, moduleBytes, moduleSize, out _);
                var patternBytes = ParsePattern(pattern);
                for (int i = 0; i < moduleSize - patternBytes.Count; i++)
                {
                    bool found = true;
                    for (int j = 0; j < patternBytes.Count; j++)
                    {
                        var b = patternBytes[j];
                        if (b.HasValue && moduleBytes[i + j] != b.Value)
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found) return IntPtr.Add(baseAddress, i);
                }
            }
            catch { return IntPtr.Zero; }
            return IntPtr.Zero;
        }

        private List<byte?> ParsePattern(string pattern)
        {
            var bytes = new List<byte?>();
            foreach (var b in pattern.Split(' '))
            {
                bytes.Add(b == "??" ? (byte?)null : byte.Parse(b, NumberStyles.HexNumber));
            }
            return bytes;
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
