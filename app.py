import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import json
import requests
from urllib.parse import urlparse

PROGRAMS_FILE = "programs.json"
ICONS_DIR = "icons"

if not os.path.exists(ICONS_DIR):
    os.makedirs(ICONS_DIR)

def simulate_download(button_frame, program):

    from tkinter import ttk
    import threading

    def choose_download_path():
        path = filedialog.askdirectory(title="Выберите папку для сохранения файла")
        return path if path else None

    download_dir = choose_download_path()
    if not download_dir:
        messagebox.showerror("Ошибка", "Вы не выбрали папку для сохранения!")
        return

    button = button_frame.winfo_children()[0]
    button.pack_forget()
    progress = tk.DoubleVar()
    progress_bar = ttk.Progressbar(
        button_frame, orient="horizontal", length=200, mode="determinate", variable=progress
    )
    progress_bar.pack()

    def download():
        try:
            url = program['url']
            response = requests.get(url, stream=True)
            response.raise_for_status()

            file_name = program['name']
            if 'Content-Disposition' in response.headers:
                content_disp = response.headers['Content-Disposition']
                if 'filename=' in content_disp:
                    file_name = content_disp.split('filename=')[-1].strip('"')

            if '.' not in file_name:
                parsed_url = urlparse(url)
                file_name = os.path.basename(parsed_url.path)

            if not file_name or '.' not in file_name:
                messagebox.showerror("Ошибка", "Не удалось определить расширение файла.")
                return

            save_path = os.path.join(download_dir, file_name)

            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0

            with open(save_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        progress.set(downloaded_size / total_size * 100)

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Ошибка загрузки", f"Произошла ошибка при загрузке:\n{e}")
            progress_bar.pack_forget()
            tk.Label(button_frame, text="Ошибка", bg="#222222", fg="red").pack()
            return

        progress_bar.pack_forget()
        tk.Label(button_frame, text=f"Сохранено:\n{save_path}",
                 bg="#222222", fg="white", wraplength=200).pack()

    threading.Thread(target=download).start()

def load_programs():

    if os.path.exists(PROGRAMS_FILE):
        with open(PROGRAMS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    return []


def save_programs(programs):

    with open(PROGRAMS_FILE, "w", encoding="utf-8") as file:
        json.dump(programs, file, ensure_ascii=False, indent=4)


def copy_icon_to_icons_dir(icon_path):

    if not os.path.exists(icon_path):
        raise FileNotFoundError(f"Иконка не найдена по пути: {icon_path}")

    icon_name = os.path.basename(icon_path)
    new_icon_path = os.path.join(ICONS_DIR, icon_name)

    try:
        with open(icon_path, "rb") as src, open(new_icon_path, "wb") as dest:
            dest.write(src.read())
    except Exception as e:
        raise IOError(f"Ошибка копирования файла иконки: {e}")

    return new_icon_path


def add_program_window(programs, update_program_list):
    def choose_icon():
        filetypes = [("Изображения", "*.png *.jpg *.jpeg *.bmp *.ico")]
        filepath = filedialog.askopenfilename(title="Выберите иконку", filetypes=filetypes)
        if filepath:
            icon_var.set(filepath)

    def paste_from_clipboard():
        """Функция для вставки содержимого из буфера обмена в поле URL"""
        clipboard_content = window.clipboard_get()
        url_var.set(clipboard_content.strip())

    def save_program():
        """Сохранение новой программы"""
        name = name_var.get().strip()
        description = description_text.get("1.0", tk.END).strip()
        icon_path = icon_var.get().strip()
        download_url = url_var.get().strip()

        if not name or not description or not icon_path or not download_url:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены!")
            return

        try:
            new_icon_path = copy_icon_to_icons_dir(icon_path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при копировании иконки: {e}")
            return

        new_program = {
            "name": name,
            "description": description,
            "icon": new_icon_path,
            "url": download_url,
        }

        programs.append(new_program)
        save_programs(programs)
        update_program_list()
        window.destroy()

    window = tk.Toplevel()
    window.title("Добавить программу")
    window.geometry("500x600")
    window.configure(bg="#222222")

    tk.Label(
        window, text="Добавление программы", font=("Arial", 16, "bold"), fg="white", bg="#222222"
    ).pack(pady=10)

    name_var = tk.StringVar()
    tk.Label(window, text="Название программы:", fg="white", bg="#222222").pack(padx=10, pady=5)
    tk.Entry(window, textvariable=name_var, bg="#333333", fg="white", insertbackground="white", relief="flat",
             highlightbackground="#444444", highlightthickness=1).pack(fill="x", padx=10)

    tk.Label(window, text="Описание программы:", fg="white", bg="#222222").pack(padx=10, pady=5)
    description_text = tk.Text(
        window, height=5, bg="#333333", fg="white", insertbackground="white", relief="flat",
        highlightbackground="#444444", highlightthickness=1
    )
    description_text.pack(fill="x", padx=10)

    icon_var = tk.StringVar()
    tk.Label(window, text="Иконка:", fg="white", bg="#222222").pack(padx=10, pady=5)
    tk.Entry(window, textvariable=icon_var, state="readonly", bg="#333333", fg="white", relief="flat",
             highlightbackground="#444444", highlightthickness=1).pack(fill="x", padx=10)
    tk.Button(
        window, text="Выбрать иконку", command=choose_icon, bg="#444444", fg="white", relief="flat"
    ).pack(pady=5)

    url_var = tk.StringVar()
    tk.Label(window, text="URL для скачивания:", fg="white", bg="#222222").pack(padx=10, pady=5)

    url_frame = tk.Frame(window, bg="#222222")
    url_frame.pack(fill="x", padx=10)

    tk.Entry(
        url_frame,
        textvariable=url_var,
        bg="#333333",
        fg="white",
        insertbackground="white",
        relief="flat",
        highlightbackground="#444444",
        highlightthickness=1
    ).pack(side="left", fill="x", expand=True, pady=5)

    tk.Button(
        url_frame,
        text="Вставить",
        bg="#444444",
        fg="white",
        activebackground="#555555",
        activeforeground="white",
        relief="flat",
        command=paste_from_clipboard
    ).pack(side="right", padx=5)

    button_save = tk.Button(
        window, text="Сохранить", command=save_program, bg="#007BFF", fg="white", font=("Arial", 12),
        padx=10, pady=5, relief="flat"
    )
    button_save.pack(pady=20)
    button_save.bind("<Enter>", lambda e: button_save.configure(bg="#0056b3"))
    button_save.bind("<Leave>", lambda e: button_save.configure(bg="#007BFF"))


def create_app_store():
    programs = load_programs()

    root = tk.Tk()
    root.title("Менеджер программ")
    root.geometry("800x700")
    root.configure(bg="#111111", padx=10, pady=10)
    root.tk_setPalette(background="#111111")  # Фон верхней части окна

    is_delete_mode = tk.BooleanVar(value=False)

    tk.Label(root, text="Менеджер программ", font=("Arial", 24, "bold"), bg="#111111", fg="white").pack(pady=10)

    canvas = tk.Canvas(root, bg="#111111", highlightthickness=0)
    scrollable_frame = tk.Frame(canvas, bg="#111111")
    scrollable_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    def on_mousewheel(event):
        canvas.yview_scroll(-1 * int(event.delta / 120), "units")

    root.bind_all("<MouseWheel>", on_mousewheel)

    canvas.pack(side="left", fill="both", expand=True)

    def toggle_delete_mode():
        is_delete_mode.set(not is_delete_mode.get())
        update_program_list()

    def delete_program(program):
        nonlocal programs
        programs.remove(program)
        save_programs(programs)
        update_program_list()

    def update_program_list():
        for widget in scrollable_frame.winfo_children():
            widget.destroy()

        for program in programs:
            entry_frame = tk.Frame(scrollable_frame, bg="#222222", pady=10, padx=10)
            entry_frame.pack(fill="x", pady=5)

            try:
                icon = Image.open(program["icon"]).resize((80, 80), Image.ANTIALIAS)
                icon_image = ImageTk.PhotoImage(icon)
                icon_label = tk.Label(entry_frame, image=icon_image, bg="#222222")
                icon_label.image = icon_image
                icon_label.pack(side="left", padx=10)
            except Exception:
                tk.Label(entry_frame, text="[Иконка]", bg="#222222", fg="#ffffff").pack(side="left", padx=10)

            text_frame = tk.Frame(entry_frame, bg="#222222")
            text_frame.pack(side="left", fill="both", expand=True, padx=10)
            tk.Label(
                text_frame, text=program["name"],
                bg="#222222", fg="#ffffff", font=("Arial", 16, "bold")
            ).pack(anchor="w")

            tk.Label(
                text_frame, text=program["description"],
                bg="#222222", fg="#cccccc", wraplength=500
            ).pack(anchor="w")

            button_frame = tk.Frame(entry_frame, bg="#222222")
            button_frame.pack(side="right", padx=10)

            download_button = tk.Button(
                button_frame, text="Скачать", bg="#007BFF", fg="white", font=("Arial", 12),
                relief="flat", padx=10, pady=5,
                command=lambda bf=button_frame, p=program: simulate_download(bf, p)
            )
            download_button.pack()

            if is_delete_mode.get():
                delete_button = tk.Button(
                    entry_frame, text="Удалить", bg="#FF4444", fg="white", relief="flat",
                    font=("Arial", 12), padx=10, pady=5,
                    command=lambda p=program: delete_program(p)
                )
                delete_button.pack(side="right", padx=10)
    update_program_list()

    buttons_frame = tk.Frame(root, bg="#111111")
    buttons_frame.pack(side="top", anchor="nw", padx=10, pady=10)

    add_button = tk.Button(
        buttons_frame, text="Добавить", command=lambda: add_program_window(programs, update_program_list),
        bg="#007BFF", fg="white", font=("Arial", 12), relief="flat", padx=10, pady=5
    )
    add_button.pack(side="top", pady=5, fill="x")

    delete_mode_button = tk.Button(
        buttons_frame, text="Удалить программы", command=toggle_delete_mode,
        bg="#FF4444", fg="white", font=("Arial", 12), relief="flat", padx=10, pady=5
    )
    delete_mode_button.pack(side="top", pady=5, fill="x")

    root.mainloop()


if __name__ == "__main__":
    create_app_store()