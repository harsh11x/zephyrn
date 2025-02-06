import subprocess

def run_server():
    print("Starting server...")
    subprocess.run(['python', 'server.py'])  # Change 'python' to 'python3' if needed

def run_client():
    print("Starting client...")
    subprocess.run(['python', 'client.py'])  # Change 'python' to 'python3' if needed

def main():
    print("Do you want to be a server or a client?")
    choice = input("Enter 'server' to run as server or 'client' to run as client: ").strip().lower()

    if choice == 'server':
        run_server()
    elif choice == 'client':
        run_client()
    else:
        print("Invalid choice. Please choose 'server' or 'client'.")

if __name__ == '__main__':
    main()
