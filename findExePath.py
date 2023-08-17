import os

def get_unique_exe_folders(directory):
    exe_folders = []  # Sử dụng danh sách để lưu trữ đường dẫn thư mục
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.__contains__(".exe") or file.__contains__(".dll"):
                folder = os.path.abspath(root)
                if folder not in exe_folders:
                    exe_folders.append(folder)
    
    return exe_folders

# Thay đổi đường dẫn thư mục của bạn ở đây
target_directory = 'C:\\Users\\CHU-TUAN-KIET\\Desktop\\thuctap586\\trichdactrung\\RedLine\\100-132'

exe_folders_list = get_unique_exe_folders(target_directory)

for folder in exe_folders_list:
    print(folder)


