# Description
This script allows to read and cleanse the following 3  network intrusion detection datasets as outlined in paper https://doi.org/10.1016/j.cose.2019.02.008:
- UNSW-NB-2015 dataset https://doi.org/10.26190/5d7ac5b1e8485
- NSL-KDD dataset https://www.unb.ca/cic/datasets/nsl.html
- CIC-IDS2017 dataset https://www.unb.ca/cic/datasets/ids-2017.html

# Usage
 1. Specify folder name where the dataset is located in ``
    - The script combines all .csv files in the folder to one pandas dataframe
 2. Call the respective function for the dataset you want to load and store the results in a pandas dataframe 
 3. After you have run the script once a **HDF5 file** is created that stores the loaded and cleansed data
    - This allows to load the dataset faster in future runs
 4. Please see https://doi.org/10.1016/j.cose.2019.02.008 for details of the data cleansing process