import os

def find_exe_files_recursive(directory):
    exe_files = set()

    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)

        if os.path.isdir(item_path):
            exe_files.extend(find_exe_files_recursive(item_path))
        elif item.__contains__(".exe") or item.__contains__(".dll"):
            print(item_path)
            exe_files.append(item_path)

    return exe_files

def main():
    input_path = "C:\\Users\\CHU-TUAN-KIET\\Desktop\\thuctap586\\learndll\\38_Mau_MustangPanda\\38_Mau_MustangPanda\\MP"
    
    if os.path.isdir(input_path):
        exe_files = find_exe_files_recursive(input_path)
        
        if exe_files:
            print("Các file .exe đã tìm thấy:")
            for exe_file in exe_files:
                print(exe_file)
        else:
            print("Không tìm thấy file .exe trong thư mục và các thư mục con.")
    else:
        print("Đường dẫn không hợp lệ hoặc không phải là thư mục.")

if __name__ == "__main__":
    main()
