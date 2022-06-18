
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using ModernDashboard.Model;

namespace ModernDashboard.ViewModel
{
    public class DesktopViewModel : INotifyPropertyChanged
    {
        private readonly CollectionViewSource DesktopItemsCollection;
        public ICollectionView DesktopSourceCollection => DesktopItemsCollection.View;

        public DesktopViewModel()
        {            
            ObservableCollection<DesktopItems> desktopItems = new ObservableCollection<DesktopItems>
            {

            };

            DesktopItemsCollection = new CollectionViewSource { Source = desktopItems };
            DesktopItemsCollection.Filter += MenuItems_Filter;

        }

        private string filterText;
        public string FilterText
        {
            get => filterText;
            set
            {
                filterText = value;
                DesktopItemsCollection.View.Refresh();
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

            DesktopItems _item = e.Item as DesktopItems;
            if (_item.DesktopName.ToUpper().Contains(FilterText.ToUpper()))
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
