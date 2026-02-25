import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class FinalCertificateApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Raqamli Sertifikat Markazi")
        self.root.geometry("600x750")
        self.root.configure(bg="#f4f4f9")

        self.private_key = None
        self.certificate = None
        self.setup_ui()

    def setup_ui(self):
        # 1. Ma'lumot kiritish maydonlari (Yuqorida va bo'sh holda)
        input_frame = tk.LabelFrame(self.root, text="Sertifikat Ma'lumotlari (Qo'lda kiritish)", bg="#f4f4f9", pady=10)
        input_frame.pack(fill="x", padx=20, pady=10)

        self.entries = {}
        fields = ["Common Name (CN)", "Organizational Unit (OU)", "Organization (O)", "Locality (L)", "State (S)", "Country (C)"]
        
        for field in fields:
            f = tk.Frame(input_frame, bg="#f4f4f9")
            f.pack(fill="x", padx=10, pady=2)
            tk.Label(f, text=f"{field}:", width=20, anchor="w", bg="#f4f4f9").pack(side="left")
            entry = tk.Entry(f, bd=1, relief="solid")
            entry.pack(side="right", expand=True, fill="x")
            self.entries[field] = entry

        # 2. Asosiy Yaratish va Saqlash tugmasi
        tk.Button(self.root, text="Yangi Sertifikatni Generatsiya Qilish", command=self.create_certificate,
                  bg="#3498db", fg="white", font=("Arial", 10, "bold"), height=2).pack(pady=10, padx=20, fill="x")

        # 3. Fayl turlari bo'yicha saqlash/yuklash tugmalari
        file_frame = tk.LabelFrame(self.root, text="Formatlar bo'yicha saqlash va yuklash", bg="#f4f4f9", pady=10)
        file_frame.pack(fill="x", padx=20, pady=10)

        # Tugmalar paneli
        btn_grid = tk.Frame(file_frame, bg="#f4f4f9")
        btn_grid.pack()

        formats = [
            (".CRT (Sertifikat)", self.save_crt),
            (".KEY (Shaxsiy kalit)", self.save_key),
            (".PEM (Umumiy format)", self.save_pem),
            (".CSR (So'rovnoma)", self.save_csr)
        ]

        for i, (text, cmd) in enumerate(formats):
            tk.Button(btn_grid, text=text, command=cmd, width=25, bg="#ffffff").grid(row=i//2, column=i%2, padx=5, pady=5)

        # 4. Holat oynasi
        self.status_box = tk.Text(self.root, height=10, width=70, font=("Courier", 9), bg="#eeeeee")
        self.status_box.pack(pady=10, padx=20)

    def create_certificate(self):
        try:
            # Ma'lumotlarni tekshirish
            if not self.entries["Common Name (CN)"].get():
                messagebox.showwarning("Xato", "CN maydonini to'ldirish shart!")
                return

            # Kalit yaratish
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            # Sub'ekt ma'lumotlari
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.entries["Common Name (CN)"].get()),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.entries["Organizational Unit (OU)"].get()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.entries["Organization (O)"].get()),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.entries["Locality (L)"].get()),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.entries["State (S)"].get()),
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.entries["Country (C)"].get()),
            ])

            now = datetime.datetime.now(datetime.timezone.utc)
            self.certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                self.private_key.public_key()).serial_number(x509.random_serial_number()
            ).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)
            ).sign(self.private_key, hashes.SHA256())

            self.status_box.insert(tk.END, f"[{now.strftime('%H:%M:%S')}] Yangi sertifikat xotirada yaratildi. Endi uni saqlashingiz mumkin.\n")
            messagebox.showinfo("Tayyor", "Sertifikat generatsiya qilindi!")

        except Exception as e:
            messagebox.showerror("Xato", str(e))

    def save_crt(self):
        if not self.certificate: return
        path = filedialog.asksaveasfilename(defaultextension=".crt", initialfile="file.crt")
        if path:
            with open(path, "wb") as f:
                f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            self.status_box.insert(tk.END, f"Saqlandi: {path}\n")

    def save_key(self):
        if not self.private_key: return
        path = filedialog.asksaveasfilename(defaultextension=".key", initialfile="file.key")
        if path:
            with open(path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))
            self.status_box.insert(tk.END, f"Kalit saqlandi: {path}\n")

    def save_pem(self):
        if not self.certificate: return
        path = filedialog.asksaveasfilename(defaultextension=".pem", initialfile="file.pem")
        if path:
            pem_data = self.certificate.public_bytes(serialization.Encoding.PEM)
            with open(path, "wb") as f: f.write(pem_data)
            self.status_box.insert(tk.END, f"PEM saqlandi: {path}\n")

    def save_csr(self):
        if not self.private_key: return
        path = filedialog.asksaveasfilename(defaultextension=".csr", initialfile="file.csr")
        if path:
            csr = x509.CertificateSigningRequestBuilder().subject_name(self.certificate.subject).sign(self.private_key, hashes.SHA256())
            with open(path, "wb") as f: f.write(csr.public_bytes(serialization.Encoding.PEM))
            self.status_box.insert(tk.END, f"CSR saqlandi: {path}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = FinalCertificateApp(root)
    root.mainloop()
