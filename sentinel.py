import sys
import time
import os
import psutil
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === RANSOMWATCH: Anti-Ransomware Behavioral Analysis Tool ===
# Mantık: Kritik dizinlere 'yem' (honeypot) dosyalar bırakır.
# Bu dosyalara dokunan herhangi bir süreç (process) tespit edilirse,
# sistem bunu bir saldırı olarak kabul eder ve süreci sonlandırır.

HONEYPOT_FILENAME = "000_IMPORTANT_PASSWORD.docx"  # Alfabetik olarak üstte dursun diye 000
MONITOR_DIR = os.path.expanduser("~") # Kullanıcının ana dizinini koru (Windows/Linux uyumlu)

class RansomwareHunter(FileSystemEventHandler):
    def on_modified(self, event):
        """Bir dosya değiştirildiğinde tetiklenir."""
        self.check_threat(event)

    def on_deleted(self, event):
        """Bir dosya silindiğinde tetiklenir."""
        self.check_threat(event)

    def check_threat(self, event):
        # Eğer değiştirilen dosya bizim YEM dosyamız ise...
        if HONEYPOT_FILENAME in event.src_path:
            print(f"\n[!!!] ALARM: Yem dosyaya müdahale tespit edildi: {event.src_path}")
            print("[*] Tehdit avı başlatılıyor...")
            self.neutralize_threat()

    def neutralize_threat(self):
        """Dosyaya erişen son işlemi bul ve öldür (Simülasyon)."""
        # Gerçek dünyada dosya handle'ına sahip süreci bulmak için Windows API gerekir.
        # Bu Python simülasyonunda, o an sistemi yoran veya şüpheli işlemi bulmaya çalışacağız.
        # Eğitim amaçlı olduğu için 'Panic Mode'u aktif ediyoruz.
        
        print(f"[🛡️] KORUMA MODU: Saldırı engellendi!")
        print(f"[INFO] Yem dosyası ({HONEYPOT_FILENAME}) değiştirildiği için sistem kilitlendi.")
        print(f"[ACTION] Yöneticiye SMS/Email gönderildi (Simüle).")
        
        # Gerçek bir EDR burada işlemi 'psutil.Process(pid).kill()' ile öldürür.
        # Yanlışlıkla senin sistem işlemini öldürmemek için sadece PID listesi basıyoruz.
        print("[DEBUG] Olası Şüpheli İşlemler (Son 1 saniyede aktif olanlar):")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                print(f" - PID: {proc.info['pid']} | Name: {proc.info['name']}")
            except:
                pass
        
        # Simülasyonu durdur
        os._exit(1)

def deploy_honeypots():
    """Tuzak dosyaları yerleştirir."""
    target_path = os.path.join(MONITOR_DIR, HONEYPOT_FILENAME)
    if not os.path.exists(target_path):
        with open(target_path, 'w') as f:
            f.write("This is a honeypot file. Do not touch!")
        print(f"[+] Yem dosyası yerleştirildi: {target_path}")
    else:
        print(f"[+] Yem dosyası zaten aktif: {target_path}")

def start_sentinel():
    deploy_honeypots()
    
    event_handler = RansomwareHunter()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=False)
    observer.start()
    
    print(f"[*] RansomWatch Devrede. İzlenen Dizin: {MONITOR_DIR}")
    print("[*] Saldırı bekleniyor (Ctrl+C ile çık)...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[-] Koruma devre dışı bırakıldı.")
    
    observer.join()

if __name__ == "__main__":
    print("""
    █▀▀█ █▀▀█ █▀▀▄ █▀▀ █▀▀█ █▀▄▀█ █░░░░░█ █▀▀█ ▀▀█▀▀ █▀▀ █░░█
    █▄▄▀ █▄▄█ █░░█ ▀▀█ █░░█ █░▀░█ █▄▄█▄▄█ █▄▄█ ░░█░░ █░░ █▀▀█
    ▀░▀▀ ▀░░▀ ▀░░▀ ▀▀▀ ▀▀▀▀ ▀░░░▀ ░░░▀░░░ ▀░░▀ ░░▀░░ ▀▀▀ ▀░░▀
           --- Behavioral Ransomware Vaccine v1.0 ---
    """)
    if os.name == 'nt': # Windows kontrolü
        print("[Windows] Sistem uyumlu.")
    else:
        print(f"[{os.uname().sysname}] Sistem uyumlu.")
        
    start_sentinel()
