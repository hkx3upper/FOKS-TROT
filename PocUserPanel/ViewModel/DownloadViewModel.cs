
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using ModernDashboard.Model;

namespace ModernDashboard.ViewModel
{
    public class DownloadViewModel : INotifyPropertyChanged
    {
        private CollectionViewSource DownloadItemsCollection;
        public ICollectionView DownloadSourceCollection => DownloadItemsCollection.View;

        public DownloadViewModel()
        {            
            ObservableCollection<DownloadItems> downloadItems = new ObservableCollection<DownloadItems>
            {

            };

            DownloadItemsCollection = new CollectionViewSource { Source = downloadItems };
            DownloadItemsCollection.Filter += MenuItems_Filter;

        }

        private string filterText;
        public string FilterText
        {
            get => filterText;
            set
            {
                filterText = value;
                DownloadItemsCollection.View.Refresh();
                OnPropertyChanged("FilterText");
            }
        }

        private void MenuItems_Filter(object sender, FilterEventArgs e)
        {
            if (string.IsNullOrEmpty(FilterText))
            {
                e.Accepted = true;
                return;
            }

            DownloadItems _item = e.Item as DownloadItems;
            if (_item.DownloadName.ToUpper().Contains(FilterText.ToUpper()))
            {
                e.Accepted = true;
            }
            else
            {
                e.Accepted = false;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string propName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
        }

    }
}
