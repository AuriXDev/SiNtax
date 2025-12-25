import os
import sys
import json
import hashlib
import ctypes
import tempfile
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
    import winreg
    from ctypes import wintypes
except ImportError:
    print("Установка зависимостей...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "pywin32"])
    import psutil
    import winreg

# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    VERSION = "Lite"
    AUTHOR = "AuriX"
    
    SUSPICIOUS_PATHS = [
        os.environ.get('TEMP', ''),
        os.environ.get('LOCALAPPDATA', '') + '\\Temp',
        os.path.join(os.environ.get('APPDATA', ''), 'Roaming'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp')
    ]
    
    MINER_PROCESSES = ['xmrig', 'minerd', 'cpuminer', 'ethminer', 'ccminer']
    FAKE_PROCESSES = ['taskhr', 'taskmgr', 'taskeng', 'csrss', 'lsass', 'smss']
    
    STARTUP_PATHS = {
        'HKCU': r"Software\Microsoft\Windows\CurrentVersion\Run",
        'HKLM': r"Software\Microsoft\Windows\CurrentVersion\Run",
        'Startup': os.path.join(os.environ.get('APPDATA', ''), 
                               r"Microsoft\Windows\Start Menu\Programs\Startup"),
        'CommonStartup': os.path.join(os.environ.get('PROGRAMDATA', ''),
                                     r"Microsoft\Windows\Start Menu\Programs\Startup")
    }

# ============================================================================
# ЯДРО: МОНИТОРИНГ ПРОЦЕССОВ
# ============================================================================

class ProcessMonitor:
    
    def __init__(self):
        self.threats_found = []
        self.suspicious_cache = set()
    
    def get_all_processes(self):
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 
                                        'memory_percent', 'exe', 'cmdline']):
            try:
                info = proc.info
                
                if sys.platform == 'win32':
                    info['username'] = proc.username()
                    info['create_time'] = datetime.fromtimestamp(proc.create_time())
                    info['is_hidden'] = self._check_if_hidden(proc)
                
                info['is_suspicious'] = self.analyze_process(info)
                
                if info['is_suspicious']:
                    self.threats_found.append(info)
                
                processes.append(info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def analyze_process(self, proc_info):
        """Анализирует процесс на угрозы"""
        name = proc_info['name'].lower() if proc_info['name'] else ''
        exe = proc_info['exe'].lower() if proc_info['exe'] else ''

        if name == 'system idle process' or proc_info['pid'] == 0:
            return False
        
        for miner in Config.MINER_PROCESSES:
            if miner in name or (proc_info['exe'] and miner in exe):
                return True
        
        for fake in Config.FAKE_PROCESSES:
            if fake in name and not self._is_real_system_process(exe):
                return True
        
        if proc_info['exe']:
            for suspicious_path in Config.SUSPICIOUS_PATHS:
                if suspicious_path and suspicious_path.lower() in exe:
                    return True
        
        if (proc_info.get('cpu_percent', 0) > 70 or 
            proc_info.get('memory_percent', 0) > 30):
            if sys.platform == 'win32' and not self._has_visible_window(proc_info['pid']):
                return True
        
        return False
    
    def _check_if_hidden(self, proc):
        try:
            exe = proc.exe()
            name = proc.name()
            
            if exe and any(path.lower() in exe.lower() for path in Config.SUSPICIOUS_PATHS):
                if any(fake in name.lower() for fake in Config.FAKE_PROCESSES):
                    return True
        except:
            pass
        return False
    
    def _is_real_system_process(self, exe_path):
        if not exe_path:
            return False
        
        system_paths = [
            r'C:\Windows\System32',
            r'C:\Windows\SysWOW64',
            r'C:\Windows\System'
        ]
        
        exe_lower = exe_path.lower()
        return any(sp.lower() in exe_lower for sp in system_paths)
    
    def _has_visible_window(self, pid):
        try:
            if sys.platform == 'win32':
                import win32gui
                import win32process
                
                def callback(hwnd, pid_list):
                    if win32gui.IsWindowVisible(hwnd):
                        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                        if found_pid == pid:
                            pid_list.append(True)
                    return True
                
                pid_list = []
                win32gui.EnumWindows(callback, pid_list)
                return len(pid_list) > 0
        except:
            pass
        return True
    
    def kill_suspicious_processes(self):
        killed = []
        for proc in psutil.process_iter():
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'exe'])
                if self.analyze_process(info):
                    proc.terminate()
                    killed.append(info)
            except:
                continue
        return killed

# ============================================================================
# ЯДРО: УПРАВЛЕНИЕ АВТОЗАГРУЗКОЙ
# ============================================================================

class StartupManager:
    
    def __init__(self):
        self.backup_file = os.path.join(tempfile.gettempdir(), 'sintax_startup_backup.json')
    
    def get_all_startup_items(self):
        items = []
        
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                              Config.STARTUP_PATHS['HKCU']) as key:
                items.extend(self._read_registry_key(key, 'HKCU'))
        except WindowsError:
            pass
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              Config.STARTUP_PATHS['HKLM']) as key:
                items.extend(self._read_registry_key(key, 'HKLM'))
        except WindowsError:
            pass
        
        startup_folder = Config.STARTUP_PATHS['Startup']
        if os.path.exists(startup_folder):
            items.extend(self._read_startup_folder(startup_folder, 'User'))
        
        common_startup = Config.STARTUP_PATHS['CommonStartup']
        if os.path.exists(common_startup):
            items.extend(self._read_startup_folder(common_startup, 'Common'))
        
        return items
    
    def _read_registry_key(self, key, location):
        items = []
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                
                is_suspicious = self._analyze_startup_item(name, value)
                
                items.append({
                    'name': name,
                    'path': value,
                    'location': location,
                    'type': 'Registry',
                    'enabled': True,
                    'is_suspicious': is_suspicious
                })
                i += 1
            except WindowsError:
                break
        return items
    
    def _read_startup_folder(self, folder, location):
        items = []
        for item in os.listdir(folder):
            full_path = os.path.join(folder, item)
            if os.path.isfile(full_path) and item.lower().endswith(('.exe', '.bat', '.vbs', '.lnk')):
                
                is_suspicious = self._analyze_startup_item(item, full_path)
                
                items.append({
                    'name': item,
                    'path': full_path,
                    'location': location,
                    'type': 'Shortcut' if item.endswith('.lnk') else 'File',
                    'enabled': True,
                    'is_suspicious': is_suspicious
                })
        return items
    
    def _analyze_startup_item(self, name, path):
        suspicious_keywords = ['update', 'helper', 'service', 'loader', 
                              'launcher', 'host', 'runtime']
        
        path_lower = path.lower()
        name_lower = name.lower()
        
        if any(temp in path_lower for temp in ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp']):
            return True
        
        for keyword in suspicious_keywords:
            if keyword in name_lower and not self._is_trusted_path(path):
                return True
        
        return False
    
    def _is_trusted_path(self, path):
        trusted_paths = [
            r'C:\Program Files',
            r'C:\Program Files (x86)',
            r'C:\Windows',
            r'C:\ProgramData'
        ]
        path_lower = path.lower()
        return any(tp.lower() in path_lower for tp in trusted_paths)
    
    def freeze_startup(self, exclude_system=True):
        """Экстренная заморозка автозагрузки"""
        items = self.get_all_startup_items()
        suspicious_items = [item for item in items if item['is_suspicious']]
        
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'items': suspicious_items
        }
        
        with open(self.backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2)
        
        disabled_count = 0
        for item in suspicious_items:
            if self.disable_startup_item(item):
                disabled_count += 1
        
        return disabled_count, suspicious_items
    
    def disable_startup_item(self, item):
        """Отключает элемент автозагрузки"""
        try:
            if item['type'] == 'Registry':
                if item['location'] == 'HKCU':
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                       Config.STARTUP_PATHS['HKCU'],
                                       0, winreg.KEY_SET_VALUE)
                else:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       Config.STARTUP_PATHS['HKLM'],
                                       0, winreg.KEY_SET_VALUE)
                
                winreg.DeleteValue(key, item['name'])
                winreg.CloseKey(key)
                
            elif item['type'] in ['File', 'Shortcut']:
                new_name = item['path'] + '.syntax_disabled'
                os.rename(item['path'], new_name)
                
            return True
        except Exception as e:
            print(f"Ошибка отключения {item['name']}: {e}")
            return False
    
    def restore_startup(self):
        if not os.path.exists(self.backup_file):
            return 0
        
        with open(self.backup_file, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        restored_count = 0
        for item in backup_data['items']:
            try:
                if item['type'] == 'Registry':
                    if item['location'] == 'HKCU':
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                           Config.STARTUP_PATHS['HKCU'],
                                           0, winreg.KEY_SET_VALUE)
                    else:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                           Config.STARTUP_PATHS['HKLM'],
                                           0, winreg.KEY_SET_VALUE)
                    
                    winreg.SetValueEx(key, item['name'], 0,
                                    winreg.REG_SZ, item['path'])
                    winreg.CloseKey(key)
                
                elif item['type'] in ['File', 'Shortcut']:
                    disabled_name = item['path'] + '.syntax_disabled'
                    if os.path.exists(disabled_name):
                        os.rename(disabled_name, item['path'])
                
                restored_count += 1
            except:
                continue
        
        return restored_count

# ============================================================================
# ЯДРО: ВОССТАНОВЛЕНИЕ СИСТЕМЫ
# ============================================================================

class SystemRecovery:
    def __init__(self):
        self.fonts_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts')
        self.assets_dir = os.path.join(os.path.dirname(__file__), 'assets')
        self.arial_path = os.path.join(self.assets_dir, 'arial.ttf')

    def restore_default_fonts(self):
        try:
            if not os.path.exists(self.arial_path):
                print(f"Ошибка: Файл шрифта Arial не найден по пути: {self.arial_path}")
                return False

            if not self.load_arial_from_assets():
                print("Ошибка: Не удалось загрузить шрифт Arial.")
                return False

            print("Шрифт Arial успешно загружен из папки assets.")
            return True

        except Exception as e:
            print(f"Ошибка при загрузке шрифта: {e}")
            return False

    def load_arial_from_assets(self):
        try:
            if not os.path.exists(self.arial_path):
                raise FileNotFoundError(f"Файл {self.arial_path} не найден!")

            if 'tkinter' in globals():
                tkfont.nametofont("TkDefaultFont").configure(family="Arial")
                tkfont.nametofont("TkTextFont").configure(family="Arial")
                tkfont.nametofont("TkFixedFont").configure(family="Arial")

            return True

        except Exception as e:
            print(f"Ошибка загрузки шрифта Arial: {e}")
            return False


    def _find_suspicious_fonts(self):
     suspicious = []
     standard_fonts = ['arial', 'times', 'calibri', 'courier', 'tahoma', 'verdana', 'segoe']
     for font_file in os.listdir(self.fonts_dir):
        font_path = os.path.join(self.fonts_dir, font_file)
        if os.path.isfile(font_path):
            font_name = os.path.splitext(font_file)[0].lower()
            if not any(font_name.startswith(std) for std in standard_fonts):
                suspicious.append(font_path)
     return suspicious

    
    def restore_default_cursors(self):
        default_cursors = {
            'Arrow': '%SystemRoot%\\Cursors\\arrow.cur',
            'Help': '%SystemRoot%\\Cursors\\help.cur',
            'Wait': '%SystemRoot%\\Cursors\\wait.cur'
        }
        
        try:
            import win32api
            import win32con
            
            for cursor_name, cursor_path in default_cursors.items():
                win32api.SystemParametersInfo(
                    win32con.SPI_SETCURSORS, 
                    0, 
                    cursor_path, 
                    win32con.SPIF_UPDATEINIFILE
                )
            return True
        except:
            return False

# ============================================================================
# ИНТЕРФЕЙС
# ============================================================================

class SimpleUI:
    
    def __init__(self):
        self.monitor = ProcessMonitor()
        self.startup_mgr = StartupManager()
        self.recovery = SystemRecovery()
    
    def show_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print("═" * 50)
            print(f"    SiNtax v-{Config.VERSION}")
            print("═" * 50)
            print("1. Мониторинг процессов")
            print("2. Экстренная заморозка автозагрузки")
            print("3. Восстановление системы")
            print("4. Убить подозрительные процессы")
            print("5. Статистика системы")
            print("6. Восстановить автозагрузку")
            print("0. Выход")
            print("═" * 50)
            
            choice = input("\nВыберите действие: ")
            
            if choice == '1':
                self.show_process_monitor()
            elif choice == '2':
                self.emergency_freeze()
            elif choice == '3':
                self.show_recovery_menu()
            elif choice == '4':
                self.kill_processes()
            elif choice == '5':
                self.show_system_stats()
            elif choice == '6':
                self.restore_startup()
            elif choice == '0':
                print("\nДо свидания!")
                break
            
            input("\nНажмите Enter для продолжения...")
    
    def show_process_monitor(self):
        print("\n" + "=" * 80)
        print("МОНИТОРИНГ ПРОЦЕССОВ".center(80))
        print("=" * 80)
        
        processes = self.monitor.get_all_processes()
        suspicious = [p for p in processes if p['is_suspicious']]
        
        print(f"\nВсего процессов: {len(processes)}")
        print(f"Подозрительных: {len(suspicious)}")
        
        if suspicious:
            print("\nОБНАРУЖЕНЫ УГРОЗЫ:")
            print("-" * 80)
            for proc in suspicious[:10]:
                cpu = proc.get('cpu_percent', 0)
                mem = proc.get('memory_percent', 0)
                print(f"├─ {proc['name']} (PID: {proc['pid']})")
                print(f"│  CPU: {cpu:.1f}% | Память: {mem:.1f}%")
                print(f"│  Путь: {proc.get('exe', 'Неизвестно')}")
                print("├" + "─" * 78)
        
        print("\nНажмите Ctrl+C для остановки мониторинга...")
        
        try:
            while True:
                time.sleep(3)
                os.system('cls' if os.name == 'nt' else 'clear')
                
                processes = self.monitor.get_all_processes()
                suspicious = [p for p in processes if p['is_suspicious']]
                
                print(f"Активных процессов: {len(processes)} | Угроз: {len(suspicious)}")
                if suspicious:
                    print("\nПоследние возможные угрозы:")
                    for proc in suspicious[:5]:
                        print(f"  • {proc['name']} (PID: {proc['pid']})")
        except KeyboardInterrupt:
            pass
    
    def emergency_freeze(self):
        print("\n" + "!" * 80)
        print("ЭКСТРЕННАЯ ЗАМОРОЗКА АВТОЗАГРУЗКИ".center(80))
        print("!" * 80)
        
        confirm = input("\nЭто отключит все подозрительные программы в автозагрузке.\n"
                       "Продолжить? (да/НЕТ): ")
        
        if confirm.lower() != 'да':
            print("Отменено.")
            return
        
        count, items = self.startup_mgr.freeze_startup()
        
        print(f"\nОтключено элементов: {count}")
        
        if items:
            print("\nОтключенные элементы:")
            for item in items:
                print(f"  • {item['name']} ({item['location']})")
        
        print(f"\nРезервная копия сохранена в: {self.startup_mgr.backup_file}")
    
    def show_recovery_menu(self):
        print("\n" + "ВОССТАНОВЛЕНИЕ СИСТЕМЫ".center(80))
        print("=" * 80)
        print("1. Восстановить шрифты")
        print("2. Восстановить курсоры")
        print("3. Вернуться")
        
        choice = input("\nВыберите: ")
        
        if choice == '1':
            result = self.recovery.restore_default_fonts()
            print(result)
        elif choice == '2':
            result = self.recovery.restore_default_cursors()
            if result:
                print("Курсоры восстановлены")
            else:
                print("Ошибка восстановления курсоров")
    
    def kill_processes(self):
        killed = self.monitor.kill_suspicious_processes()
        
        print(f"\nУбито процессов: {len(killed)}")
        for proc in killed:
            print(f"  • {proc['name']} (PID: {proc['pid']})")
    
    def show_system_stats(self):
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        print("\n" + "СТАТИСТИКА СИСТЕМЫ".center(80))
        print("=" * 80)
        print(f"Процессор: {cpu_percent:.1f}%")
        print(f"Память: {memory.percent:.1f}% ({memory.used//1024**3}ГБ / {memory.total//1024**3}ГБ)")
        print(f"Диск C:: {disk.percent:.1f}%")
        
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current:
                            print(f"Температура {name}: {entry.current}°C")
        except:
            pass
    
    def restore_startup(self):
        count = self.startup_mgr.restore_startup()
        print(f"\nВосстановлено элементов: {count}")

# ============================================================================
# GUI ВЕРСИЯ
# ============================================================================

class SimpleGUI:
    
    def __init__(self):
        try:
            import tkinter as tk
            from tkinter import ttk, scrolledtext, messagebox
            
            self.tk = tk
            self.ttk = ttk
            self.messagebox = messagebox
            
            self.monitor = ProcessMonitor()
            self.startup_mgr = StartupManager()
            
            self.root = tk.Tk()
            self.root.title(f"SiNtax v-{Config.VERSION}")
            self.root.geometry("800x600")
            
            self.setup_ui()
            
        except ImportError:
            print("Tkinter не установлен. Запускаем консольную версию.")
            SimpleUI().show_menu()
    
    def setup_ui(self):
        notebook = self.ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        monitor_frame = self.tk.Frame(notebook)
        self.setup_monitor_tab(monitor_frame)
        notebook.add(monitor_frame, text='Мониторинг')
        
        startup_frame = self.tk.Frame(notebook)
        self.setup_startup_tab(startup_frame)
        notebook.add(startup_frame, text='Автозагрузка')
        
        recovery_frame = self.tk.Frame(notebook)
        self.setup_recovery_tab(recovery_frame)
        notebook.add(recovery_frame, text='Восстановление')
        
        exit_btn = self.ttk.Button(self.root, text="Выход", 
                                 command=self.root.quit)
        exit_btn.pack(pady=5)
    
    def setup_monitor_tab(self, parent):
        btn_frame = self.tk.Frame(parent)
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        self.ttk.Button(btn_frame, text="Обновить", 
                       command=self.update_process_list).pack(side='left', padx=2)
        self.ttk.Button(btn_frame, text="Убить выбранные", 
                       command=self.kill_selected).pack(side='left', padx=2)
        
        columns = ('PID', 'Имя', 'CPU%', 'Память%', 'Путь')
        self.tree = self.ttk.Treeview(parent, columns=columns, show='headings')
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        
        scrollbar = self.ttk.Scrollbar(parent, orient='vertical', 
                                     command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.update_process_list()
    
    def update_process_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        processes = self.monitor.get_all_processes()
        
        for proc in processes[:50]:
            values = (
                proc['pid'],
                proc['name'],
                f"{proc.get('cpu_percent', 0):.1f}",
                f"{proc.get('memory_percent', 0):.1f}",
                proc.get('exe', '')[:50] + '...' if proc.get('exe') and len(proc['exe']) > 50 else proc.get('exe', '')
            )
            
            item = self.tree.insert('', 'end', values=values)
            
            if proc['is_suspicious']:
                self.tree.item(item, tags=('threat',))
        
        self.tree.tag_configure('threat', background='#ffcccc')
    
    def setup_startup_tab(self, parent):
        """Настраивает вкладку автозагрузки"""
        self.ttk.Label(parent, text="Управление автозагрузкой", 
                      font=('Arial', 12, 'bold')).pack(pady=10)
        
        self.ttk.Button(parent, text="Экстренная заморозка", 
                       command=self.emergency_freeze_gui,
                       style='Emergency.TButton').pack(pady=5)
        
        self.ttk.Button(parent, text="Восстановить автозагрузку", 
                       command=self.restore_startup_gui).pack(pady=5)
        
        style = self.ttk.Style()
        style.configure('Emergency.TButton', foreground='red', font=('Arial', 10, 'bold'))
    
    def emergency_freeze_gui(self):
        if self.messagebox.askyesno("Подтверждение", 
                                   "Отключить все подозрительные элементы автозагрузки?"):
            count, items = self.startup_mgr.freeze_startup()
            self.messagebox.showinfo("Готово", 
                                   f"Отключено {count} элементов\n"
                                   f"Резервная копия: {self.startup_mgr.backup_file}")
    
    def restore_startup_gui(self):
        count = self.startup_mgr.restore_startup()
        self.messagebox.showinfo("Готово", f"Восстановлено {count} элементов")
    
    def setup_recovery_tab(self, parent):
        self.ttk.Label(parent, text="Восстановление системы", 
                      font=('Arial', 12, 'bold')).pack(pady=10)
        
        self.ttk.Button(parent, text="Восстановить шрифты", 
                       command=self.restore_fonts_gui).pack(pady=5)
        
        self.ttk.Button(parent, text="Восстановить курсоры", 
                       command=self.restore_cursors_gui).pack(pady=5)
    
    def restore_fonts_gui(self):
     recovery = SystemRecovery()
     result = recovery.restore_default_fonts()

     if result is None:
        self.messagebox.showerror(
            "Ошибка",
            "Не удалось получить результат восстановления шрифта."
        )
        return

     if isinstance(result, str) and "загружен" in result.lower():
        self.messagebox.showinfo(
            "Шрифт восстановлен",
            f"Шрифт Arial успешно загружен из папки assets и используется в программе.\n{result}"
        )
     else:
        self.messagebox.showerror(
            "Откладка",
            f"Загрузка Arial : {result}"
        )


    
    def restore_cursors_gui(self):
        recovery = SystemRecovery()
        if recovery.restore_default_cursors():
            self.messagebox.showinfo("Готово", "Курсоры восстановлены")
        else:
            self.messagebox.showerror("Ошибка", "Не удалось восстановить курсоры")
    
    def kill_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        
        pids = []
        for item in selected:
            values = self.tree.item(item)['values']
            pids.append(values[0])
        
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
            except:
                pass
        
        self.messagebox.showinfo("Готово", f"Завершено процессов: {len(pids)}")
        self.update_process_list()

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

def main():
    print(f"SiNtax Lite")
    print("=" * 66)
    
    if sys.platform == 'win32':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("   Для полного функционала запустите от имени администратора!")
                print("   (Нажмите правой кнопкой → 'Запуск от имени администратора')")
                print("-" * 66)

        except:
            pass
    
    print("\nВыберите интерфейс:")
    print("1. Консольный (рекомендуется для серверов)")
    print("2. Графический (требует Tkinter)")
    print("3. Только проверка (автоматический режим)\n")
    print("-" * 66)
    
    try:
        choice = input("\nВаш выбор (1/2/3): ").strip()
        
        if choice == '1':
            ui = SimpleUI()
            ui.show_menu()
        elif choice == '2':
            gui = SimpleGUI()
            gui.root.mainloop()
        elif choice == '3':
            monitor = ProcessMonitor()
            processes = monitor.get_all_processes()
            suspicious = [p for p in processes if p['is_suspicious']]
            
            if suspicious:
                print(f"\nНайдено угроз: {len(suspicious)}")
                for proc in suspicious:
                    print(f"  • {proc['name']} (PID: {proc['pid']})")
                
                if input("\nВыполнить экстренную заморозку автозагрузки? (да/нет): ").lower() == 'да':
                    startup_mgr = StartupManager()
                    count, _ = startup_mgr.freeze_startup()
                    print(f"Отключено элементов: {count}")
            else:
                print("\nУгроз не обнаружено")
        
    except KeyboardInterrupt:
        print("\n\nПрограмма завершена пользователем.")
    except Exception as e:
        print(f"\nОшибка: {e}")
        input("Нажмите Enter для выхода...")

# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("Установка необходимых библиотек...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    
    main()
