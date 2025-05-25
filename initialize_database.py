import sqlite3
import os
from enhanced_auth_system import DatabaseManager, SecurityConfig

def initialize_database():
    # Eğer veritabanı dosyası varsa sil
    if os.path.exists("enhanced_users.db"):
        os.remove("enhanced_users.db")
    
    # Veritabanı yöneticisini oluştur
    db = DatabaseManager()
    
    print("Veritabanı başarıyla oluşturuldu!")
    print("Tablolar:")
    print("- users")
    print("- password_history")
    print("- login_history")
    print("- sessions")

if __name__ == "__main__":
    initialize_database() 