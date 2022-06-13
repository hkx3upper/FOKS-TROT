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
    /// Interaction logic for PictureView.xaml
    /// </summary>
    public partial class PictureView : UserControl
    {
        public PictureView()
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

        const int POC_ADD_SECURE_FODER = 0x00000002;
        const int POC_GET_FILE_EXTENSION = 0x00000006;
        const int POC_REMOVE_SECURE_FOLDER = 0x0000000B;
        const int POC_GET_SECURE_FOLDER = 0x0000000A;

        const int POC_PROCESS_RULES_SIZE = 324;
        const int POC_FILE_EXTENSION_SIZE = 32;
        const int POC_SECURE_FOLDER_SIZE = 320;

        private static IntPtr hPort;

        private void GetMessageThread()
        {
            uint ReturnCommand = 0;
            PocUserGetMessage(hPort, ref ReturnCommand);

            if (POC_ADD_SECURE_FODER == ReturnCommand)
            {
                //App.Current.Dispatcher.Invoke((Action)(() =>
                //{
                //    ListBox.Items.Add(FolderName.Text);
                //}));

                MessageBox.Show("Poc add secure folder success.");
            }
            else if (POC_REMOVE_SECURE_FOLDER == ReturnCommand)
            {
                MessageBox.Show("Poc remove secure folder success.");
            }
            else
            {
                string ErrorText = "Poc failed!->ReturnCommand = %d";
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

        private void AddListBox()
        {
            uint ReturnCommand = 0;

            StringBuilder ReplyBuffer = new StringBuilder(4096 * 10);

            int count = PocUserGetMessageEx(hPort, ref ReturnCommand, ReplyBuffer);

            if (POC_GET_SECURE_FOLDER == ReturnCommand)
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
                    ListBox.Items.Add(ReplyBuffer.ToString().Substring(i * POC_SECURE_FOLDER_SIZE, POC_SECURE_FOLDER_SIZE));
                }));
            }

            if (0 != hPort.ToInt32())
            {
                //MessageBox.Show("hPort close.");
                CloseHandle(hPort);
                hPort = (IntPtr)0;
            }
        }

        private void Folder_Click(object sender, RoutedEventArgs e)
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

            Thread thread = new Thread(new ThreadStart(AddListBox));
            thread.Start();

            PocUserSendMessage(hPort, "Get Folder", POC_GET_SECURE_FOLDER);
        }

        private void RemoveFolder_Click(object sender, RoutedEventArgs e)
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

            String Folder = ListBox.SelectedItem.ToString();

            PocUserSendMessage(hPort, Folder.Replace("  ", "\0\0"), POC_REMOVE_SECURE_FOLDER);

            ListBox.Items.Remove(ListBox.SelectedItem);
        }

        private void OpenFolder_Click(object sender, RoutedEventArgs e)
        {
            FolderName.Text = "";

            System.Windows.Forms.FolderBrowserDialog dilog = new System.Windows.Forms.FolderBrowserDialog();
            dilog.Description = "请选择文件夹";
            if (dilog.ShowDialog() == System.Windows.Forms.DialogResult.OK || 
                dilog.ShowDialog() == System.Windows.Forms.DialogResult.Yes)
            {
                FolderName.AppendText(dilog.SelectedPath);
            }

        }

        private void AddFolder_Click(object sender, RoutedEventArgs e)
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

            PocUserSendMessage(hPort, FolderName.Text, POC_ADD_SECURE_FODER);
        }

    }
}
