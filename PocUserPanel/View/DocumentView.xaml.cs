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

namespace ModernDashboard.View
{
    /// <summary>
    /// Interaction logic for DocumentView.xaml
    /// </summary>
    public partial class DocumentView : UserControl
    {
        public DocumentView()
        {
            InitializeComponent();
        }

        [DllImport("PocUserDll.dll")]
        static extern int PocUserInitCommPort(ref IntPtr hPort);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserGetMessage(IntPtr hPort, ref uint Command);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserGetMessageEx(IntPtr hPort, ref uint Command, StringBuilder MessageBuffer);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserSendMessage(IntPtr hPort, string Buffer, int Command);
        [DllImport("PocUserDll.dll")]
        static extern int PocUserAddProcessRules(IntPtr hPort, string ProcessName, uint Access);
        [DllImport("Kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        const uint STATUS_SUCCESS = 0x00000001;

        const int POC_PR_ACCESS_READWRITE = 0x00000001;
        const int POC_PR_ACCESS_BACKUP = 0x00000002;
        const int POC_PRIVILEGE_DECRYPT = 0x00000004;
        const int POC_PRIVILEGE_ENCRYPT = 0x00000008;
        const int POC_GET_PROCESS_RULES = 0x00000005;
        const int POC_ADD_PROCESS_RULES = 0x00000009;

        private static IntPtr hPort;

        private void GetMessageThread()
        {
            uint ReturnCommand = 0;
            PocUserGetMessage(hPort, ref ReturnCommand);

            if (POC_PRIVILEGE_DECRYPT == ReturnCommand)
            {
                MessageBox.Show("Poc decrypt file success.");
            }
            else if(POC_PRIVILEGE_ENCRYPT == ReturnCommand)
            {
                MessageBox.Show("Poc encrypt file success.");

            }
            else
            {
                string ErrorText = "Poc failed!->ReturnCommand = ";
                ErrorText = ErrorText + ReturnCommand.ToString("X");
                MessageBox.Show(ErrorText);

                if (0 != hPort.ToInt32())
                {
                    //MessageBox.Show("hPort close.");
                    CloseHandle(hPort);
                    hPort = (IntPtr)0;
                }

                return;
            }

            if (0 != hPort.ToInt32())
            {
                //MessageBox.Show("hPort close.");
                CloseHandle(hPort);
                hPort = (IntPtr)0;
            }
        }


        private void OpenFile_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            FileName.Text = "";

            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.Multiselect = false;//该值确定是否可以选择多个文件
            dialog.Title = "请选择文件";
            dialog.Filter = "文本文件(*.*)|*.*";


            if (dialog.ShowDialog() == true)
            {
                string file = dialog.FileName;
                FileName.AppendText(file);//显示路径，并且后面的叠加不删除
            }
        }

        private void EncryptFile_Click(object sender, System.Windows.RoutedEventArgs e)
        {

            if (0 == hPort.ToInt32())
            {
                //MessageBox.Show("New port init.");
                int ret = PocUserInitCommPort(ref hPort);
                if (0 != ret)
                {
                    return;
                }
            }

            Thread thread = new Thread(new ThreadStart(GetMessageThread));
            thread.Start();

            PocUserSendMessage(hPort, FileName.Text, POC_PRIVILEGE_ENCRYPT);
        }

        private void DecryptFile_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            if (0 == hPort.ToInt32())
            {
                //MessageBox.Show("New port init.");
                int ret = PocUserInitCommPort(ref hPort);
                if (0 != ret)
                {
                    return;
                }
            }

            Thread thread = new Thread(new ThreadStart(GetMessageThread));
            thread.Start();

            PocUserSendMessage(hPort, FileName.Text, POC_PRIVILEGE_DECRYPT);
        }
    
    }
}
