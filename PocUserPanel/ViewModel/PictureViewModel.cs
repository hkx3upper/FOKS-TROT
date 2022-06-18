
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using ModernDashboard.Model;

namespace ModernDashboard.ViewModel
{
    public class PictureViewModel : INotifyPropertyChanged
    {
        private CollectionViewSource PictureItemsCollection;
        public ICollectionView PictureSourceCollection => PictureItemsCollection.View;

        public PictureViewModel()
        {           
            ObservableCollection<PictureItems> pictureItems = new ObservableCollection<PictureItems>
            {

            };

            PictureItemsCollection = new CollectionViewSource { Source = pictureItems };
            PictureItemsCollection.Filter += MenuItems_Filter;

        }

        private string filterText;
        public string FilterText
        {
            get => filterText;
            set
            {
                filterText = value;
                PictureItemsCollection.View.Refresh();
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

            PictureItems _item = e.Item as PictureItems;
            if (_item.PictureName.ToUpper().Contains(FilterText.ToUpper()))
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
