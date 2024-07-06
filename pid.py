import psutil

def list_processes(filter_name=None):
    print(f"{'PID':<10}{'Process Name':<25}")
    print("-" * 35)

    for proc in psutil.process_iter(['pid', 'name']):
        pid = proc.info['pid']
        name = proc.info['name']

        if filter_name is None or filter_name.lower() in name.lower():
            print(f"{pid:<10}{name:<25}")

if __name__ == "__main__":
    filter_name = input("Enter process name to filter (leave blank to list all processes): ").strip()
    if not filter_name:
        filter_name = None
    list_processes(filter_name)
