import os

def get_last_folder_name(path):
    parts = os.path.normpath(path).split(os.path.sep)
    last_folder_name = parts[-1] if parts[-1] else parts[-2]  
    return last_folder_name

def get_last_folder_nameA(path):
    last_folder_name = os.path.basename(os.path.normpath(path))
    return last_folder_name

# Đường dẫn tới thư mục
folder_path = "/path/to/your/folder/kiet/vim"

# Gọi hàm để lấy tên thư mục cuối cùng
last_folder_name = get_last_folder_nameA(folder_path)

print("Tên thư mục cuối cùng:", last_folder_name)
