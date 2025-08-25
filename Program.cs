// Shadow Core V99 | Mission: Project Entry Point
// This file's only purpose is to start the CheatMenu form.

using System;
using System.Windows.Forms;

namespace ShadowCore // تأكد من أن هذا يطابق اسم مشروعك
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            // هذا السطر هو التغيير الحاسم: الآن سيتم تشغيل نافذة الغش الصحيحة
            Application.Run(new CheatMenu());
        }
    }
}
