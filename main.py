# main.py
from core.password_manager import PasswordManager

def main():
    pm = PasswordManager()
    if not pm._validate_master_password():
        return

    while True:
        print("\n1. Add Credentials\n2. Get Credentials\n3. Exit")
        choice = input("Choose option: ")

        if choice == '1':
            account = input("Enter account name (e.g., Gmail): ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            pm.add_password(account, username, password)
            print("Credentials saved successfully!")
        
        elif choice == '2':
            account = input("Enter account name: ")
            credentials = pm.get_password(account)
            if credentials:
                print(f"\nAccount: {account}")
                print(f"Username: {credentials['username']}")
                print(f"Password: {credentials['password']}")
            else:
                print("Account not found!")
        
        elif choice == '3':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()