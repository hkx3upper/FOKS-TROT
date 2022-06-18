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
    /// Interaction logic for DesktopView.xaml
    /// </summary>
    public partial class DesktopView : UserControl
    {
        public DesktopView()
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

        const int POC_GET_PROCESS_RULES = 0x00000005;
        const int POC_ADD_PROCESS_RULES = 0x00000009;

        const int POC_PROCESS_RULES_SIZE = 324;

        private static IntPtr hPort;

        private void GetMessageThread()
        {
            uint ReturnCommand = 0;
            PocUserGetMessage(hPort, ref ReturnCommand);

            if (POC_ADD_PROCESS_RULES == ReturnCommand)
            {
                MessageBox.Show("Poc add process rules success.");
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


        private void AddPR_Click(object sender, RoutedEventArgs e)
        {
            uint AccessFlag = 0;

            if (string.Compare(Access.Text, "明文") == 0)
            {
                AccessFlag = POC_PR_ACCESS_READWRITE;
            }
            else if (string.Compare(Access.Text, "备份") == 0)
            {
                AccessFlag = POC_PR_ACCESS_BACKUP;
            }
            else
            {
                MessageBox.Show("Poc wrong access trye.");
            }

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

            PocUserAddProcessRules(hPort, ProcessName.Text, AccessFlag);

        }


        private void AddListBox()
        {
            uint ReturnCommand = 0;

            StringBuilder ReplyBuffer = new StringBuilder(4096 * 10);

            int count = PocUserGetMessageEx(hPort, ref ReturnCommand, ReplyBuffer);

            if (POC_GET_PROCESS_RULES == ReturnCommand)
            {
                //MessageBox.Show("Poc flush process rules success.");
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

            App.Current.Dispatcher.Invoke((Action)(() =>
            {
                ListBox.Items.Clear();
            }));

            ReplyBuffer.ToString().Replace("  ", "\0\0");

            for (int i = 0; i < count; i++)
            {
                App.Current.Dispatcher.Invoke((Action)(() =>
                {
                    ListBox.Items.Add(ReplyBuffer.ToString().Substring(i * POC_PROCESS_RULES_SIZE, POC_PROCESS_RULES_SIZE));
                }));
            }

            if (0 != hPort.ToInt32())
            {
                //MessageBox.Show("hPort close.");
                CloseHandle(hPort);
                hPort = (IntPtr)0;
            }
        }


        private void PR_Click(object sender, RoutedEventArgs e)
        {

            if (0 == hPort.ToInt32())
            {
                //MessageBox.Show("New port init.");
                int ret = PocUserInitCommPort(ref hPort);
                if(0 != ret)
                {
                    MessageBox.Show("Poc driver not start.");
                    return;
                }
            }

            Thread thread = new Thread(new ThreadStart(AddListBox));
            thread.Start();

            PocUserSendMessage(hPort, "Get PR", POC_GET_PROCESS_RULES);

        }


        private void RemovePR_Click(object sender, RoutedEventArgs e)
        {

            if (0 == ListBox.SelectedItems.Count)
            {
                return;
            }

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


            String ProcessName = ListBox.SelectedItem.ToString();


            PocUserAddProcessRules(hPort, ProcessName.Replace("  ", "\0\0"), 0);

            ListBox.Items.Remove(ListBox.SelectedItem);
        }

        private void OpenFile_Click(object sender, RoutedEventArgs e)
        {
            ProcessName.Text = "";

            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.Multiselect = false;//该值确定是否可以选择多个文件
            dialog.Title = "请选择文件";
            dialog.Filter = "可执行文件(*.exe)|*.exe";


            if (dialog.ShowDialog() == true)
            {
                string file = dialog.FileName;
                ProcessName.AppendText(file);//显示路径，并且后面的叠加不删除
            }

        }

        private void Access_MouseEnter(object sender, MouseEventArgs e)
        {
            if(string.Compare(Access.Text, "明文/备份") == 0)
                Access.Text = "";
        }

    }
}
