using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.Threading;

namespace PocUserPanel
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        [DllImport("PocUserDll.dll")]
        static extern int PocUserInitCommPort(ref IntPtr hPort);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserGetMessage(IntPtr hPort, ref uint Command);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserSendMessage(IntPtr hPort, string Buffer, int Command);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserAddProcessRules(IntPtr hPort, string ProcessName, uint Access);
        [DllImport("Kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        const uint STATUS_SUCCESS = 0x00000001;

        const int POC_PR_ACCESS_READWRITE = 0x00000001;
        const int POC_PR_ACCESS_BACKUP = 0x00000002;

        private static IntPtr hPort;

        private void GetMessageThread()
        {
            uint ReturnCommand = 0;
            PocUserGetMessage(hPort, ref ReturnCommand);

            if (STATUS_SUCCESS == ReturnCommand)
            {
                MessageBox.Show("Poc add process rules success.");
            }
            else
            {
                string ErrorText = "Poc failed!->ReturnCommand = %d";
                ErrorText = ErrorText + ReturnCommand.ToString();
                MessageBox.Show(ErrorText);
            }

            if (0 != hPort.ToInt32())
            {
                //MessageBox.Show("hPort close.");
                CloseHandle(hPort);
                hPort = (IntPtr)0;
            }
        }


        private void AddPR_Click(object sender, RoutedEventArgs e)
        {
            uint AccessFlag = 0;

            if (string.Compare(Access.Text, "明文") == 0)
            {
                AccessFlag = POC_PR_ACCESS_READWRITE;
            }
            else if (string.Compare(Access.Text, "密文") == 0)
            {
                AccessFlag = POC_PR_ACCESS_BACKUP;
            }

            if (0 == hPort.ToInt32())
            {
                //MessageBox.Show("New port init.");
                PocUserInitCommPort(ref hPort);
            }

            Thread thread = new Thread(new ThreadStart(GetMessageThread));
            thread.Start();

            PocUserAddProcessRules(hPort, ProcessName.Text, AccessFlag);

        }
    }
}
