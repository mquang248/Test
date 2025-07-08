import os
import time
import threading
import requests
import hashlib
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import winreg
import stat
import psutil

# === CONFIG ===
VT_API_KEY = 'ded50dd47bad2f01ab9e7a17a208489b988e7825d671a512ba03d9811829b8f7'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MALICIOUS_EXTENSIONS = (
    '.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf',
    '.lnk', '.ps1', '.zip', '.rar', '.cab', '.docm', '.xlsm', '.iso', '.img',
    '.py', '.jar', '.apk'
)

WATCHED_DIRS = [
    os.environ.get("APPDATA"),
    os.environ.get("TEMP"),
    r"C:\\ProgramData",
    rf"C:\\Users\\{os.getlogin()}\\AppData\\Local",
    rf"C:\\Users\\{os.getlogin()}\\Documents",
    rf"C:\\Users\\{os.getlogin()}\\Downloads",
    r"C:\\Games",
]

HEADERS = {
    "x-apikey": VT_API_KEY
}

DETECTED_HASHES = set()

# === CORE FUNCTIONS ===
def get_sha256(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Cannot hash file: {file_path} - {e}")
        return None

def kill_processes_using(file_path):
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['exe'] and file_path.lower() in proc.info['exe'].lower():
                proc.kill()
                print(f"[⚠️] Killed process using {file_path}")
        except: pass

def force_delete(file_path):
    try:
        if not os.path.exists(file_path):
            print(f"[x] File no longer exists: {file_path}")
            return
        os.chmod(file_path, stat.S_IWRITE)
        kill_processes_using(file_path)
        os.remove(file_path)
        print(f"[🔥] Deleted malware: {file_path}")
    except Exception as e:
        print(f"[x] Force delete failed: {file_path} - {e}")
        with open("failed_deletions.log", "a") as logf:
            logf.write(f"{file_path} - {e}\n")

def vt_upload_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            res = requests.post(f"{VT_BASE_URL}/files", headers=HEADERS, files=files)
        if res.status_code == 200:
            print(f"[✓] File uploaded to VirusTotal: {file_path}")
            return True
        else:
            print(f"[x] Upload error {res.status_code}: {res.text}")
            return False
    except Exception as e:
        print(f"[x] Upload exception: {e}")
        return False

def vt_get_threat_score(file_hash):
    try:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        for _ in range(10):
            res = requests.get(url, headers=HEADERS)
            if res.status_code == 200:
                data = res.json()
                attr = data['data']['attributes']
                malicious = attr['last_analysis_stats']['malicious']
                suspicious = attr['last_analysis_stats']['suspicious']
                total = malicious + suspicious
                threat_info = attr.get('popular_threat_classification', {})
                malware_info = []

                label = threat_info.get('suggested_threat_label')
                if label: malware_info.append(label)
                malware_info += threat_info.get('techniques', [])
                malware_info += threat_info.get('families', [])
                if not malware_info and 'names' in attr:
                    malware_info.append(attr['names'][0])

                malware_info = list(set(malware_info))
                malware_str = ", ".join(malware_info) if malware_info else "Unknown"

                print(f"[✓] VT Threat score: {total}")
                print(f"[⚠️] Malware Type: {malware_str}")
                DETECTED_HASHES.add(file_hash)
                return total
            elif res.status_code == 404:
                return -1
            else:
                time.sleep(10)
        return 0
    except Exception as e:
        print(f"[x] Threat score error: {e}")
        return 0

def handle_file(file_path):
    if not os.path.exists(file_path): return
    if not file_path.lower().endswith(MALICIOUS_EXTENSIONS): return
    print(f"\n[+] New suspicious file: {file_path}")
    sha256 = get_sha256(file_path)
    if not sha256: return
    score = vt_get_threat_score(sha256)
    if score == -1:
        if vt_upload_file(file_path):
            print("[~] Waiting for scan...")
            time.sleep(30)
            score = vt_get_threat_score(sha256)
    if score >= 3:
        force_delete(file_path)

def scan_existing_files():
    for root in WATCHED_DIRS:
        for dirpath, _, filenames in os.walk(root):
            for file in filenames:
                path = os.path.join(dirpath, file)
                if not os.path.exists(path): continue
                if not path.lower().endswith(MALICIOUS_EXTENSIONS): continue
                sha256 = get_sha256(path)
                if sha256 in DETECTED_HASHES:
                    print(f"[⚠️] Clone detected: {path}")
                    force_delete(path)

REG_PATHS = [
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    r"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"Software\\Policies\\Microsoft\\Windows\\System"
]

def delete_registry_autorun():
    try:
        for path in REG_PATHS:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(ext in value.lower() for ext in MALICIOUS_EXTENSIONS) or 'vnc' in value.lower():
                            winreg.DeleteValue(key, name)
                            print(f"[🗑] Deleted autorun: {name} from {path}")
                        else:
                            i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                continue
    except Exception as e:
        print(f"[!] Registry cleanup error: {e}")

class MalwareWatcher(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            handle_file(event.src_path)
            scan_existing_files()

class MalwareApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Malware Cleaner")
        self.master.geometry("400x200")
        self.status = tk.StringVar()
        self.status.set("⛔ Not Scanning")
        self.observers = []
        self.scanning = False

        tk.Label(master, text="Realtime Malware Scanner", font=("Arial", 14)).pack(pady=10)
        tk.Button(master, text="▶️ Start Scanning", command=self.start_scan).pack(pady=5)
        tk.Button(master, text="⏹ Stop Scanning", command=self.stop_scan).pack(pady=5)
        tk.Button(master, text="🧹 Clean Registry Autorun", command=delete_registry_autorun).pack(pady=5)
        tk.Label(master, textvariable=self.status, fg="green").pack(pady=10)

    def start_scan(self):
        if self.scanning: return
        self.status.set("🟢 Scanning...")
        self.scanning = True
        for path in WATCHED_DIRS:
            if not os.path.exists(path): continue
            event_handler = MalwareWatcher()
            observer = Observer()
            observer.schedule(event_handler, path=path, recursive=True)
            observer.start()
            self.observers.append(observer)
        print("[+] Monitoring started.")

    def stop_scan(self):
        if not self.scanning: return
        self.status.set("⛔ Not Scanning")
        for obs in self.observers:
            obs.stop()
            obs.join()
        self.observers = []
        self.scanning = False
        print("[x] Monitoring stopped.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareApp(root)
    root.mainloop()
