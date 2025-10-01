# WITRN conversion UI
# Created by JohnScotttt on 2025/8/16, modified on 2025/8/18
# Copyright (c) 2025 JohnScotttt
# Version 2.0

import tkinter as tk
from tkinter import filedialog, messagebox
import os
from witrn_conversion import old_to_new, new_to_old


class FileProcessorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("维简新旧上位机数据转换 - 批量处理")
        self.set_window_center(450, 280)
        self.root.resizable(False, False)

        self.input_paths = []
        self.output_dir = None
        self.mode = "o2n"  # 默认模式

        # 输入文件
        self.input_label = tk.Label(root, text="未选择输入CSV文件")
        self.input_label.pack(pady=5)

        self.input_btn = tk.Button(root, text="选择输入CSV文件(可多选)", command=self.select_input_files)
        self.input_btn.pack(pady=5)

        # 输出目录
        self.output_label = tk.Label(root, text="未选择输出目录")
        self.output_label.pack(pady=5)

        self.output_btn = tk.Button(root, text="选择输出目录", command=self.select_output_dir)
        self.output_btn.pack(pady=5)

        # 模式切换
        self.mode_btn = tk.Button(root, text="当前模式: old to new", command=self.toggle_mode)
        self.mode_btn.pack(pady=10)

        # 执行处理
        self.process_btn = tk.Button(root, text="开始批量处理", command=self.process_files)
        self.process_btn.pack(pady=10)

    def set_window_center(self, width, height):
        """设置窗口固定大小并居中"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def select_input_files(self):
        file_paths = filedialog.askopenfilenames(
            title="选择输入CSV文件", filetypes=[("CSV文件", "*.csv")]
        )
        if file_paths:
            self.input_paths = file_paths
            self.input_label.config(text=f"已选择 {len(file_paths)} 个文件")

    def select_output_dir(self):
        dir_path = filedialog.askdirectory(title="选择输出目录")
        if dir_path:
            self.output_dir = dir_path
            self.output_label.config(text=f"输出目录: {dir_path}")

    def toggle_mode(self):
        """切换处理模式"""
        self.mode = "n2o" if self.mode == "o2n" else "o2n"
        if self.mode == "o2n":
            self.mode_btn.config(text=f"当前模式: old to new")
        else:
            self.mode_btn.config(text=f"当前模式: new to old")

    def process_files(self):
        if not self.input_paths:
            messagebox.showwarning("错误", "请先选择输入CSV文件")
            return
        if not self.output_dir:
            messagebox.showwarning("错误", "请先选择输出目录")
            return

        try:
            for input_path in self.input_paths:
                filename = os.path.basename(input_path)
                if self.mode == "o2n":
                    output_path = os.path.join(self.output_dir, filename.replace(".csv", "_new.csv"))
                    old_to_new(input_path, output_path)
                else:
                    output_path = os.path.join(self.output_dir, filename.replace(".csv", "_old.csv"))
                    new_to_old(input_path, output_path)

            messagebox.showinfo("成功", f"已批量处理 {len(self.input_paths)} 个文件！")
        except Exception as e:
            messagebox.showerror("错误", f"处理文件时出错: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileProcessorApp(root)
    root.mainloop()
