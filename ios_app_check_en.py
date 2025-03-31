import paramiko
import getpass
import plistlib
import io

def list_apps_with_details():
    device_ip = input("> Device IP address: ")
    username = input("> SSH username (usually 'root'): ")
    password = getpass.getpass("🔑 SSH password: ")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(device_ip, username=username, password=password)

        stdin, stdout, stderr = ssh.exec_command("ls /var/containers/Bundle/Application")
        bundle_uuids = stdout.read().decode().splitlines()

        stdin, stdout, stderr = ssh.exec_command(
            "find /var/mobile/Containers/Data/Application -type f -path '*/Library/Preferences/*.plist'"
        )
        all_plist_paths = stdout.read().decode().splitlines()

        app_list = []

        for uuid in bundle_uuids:
            app_dir_cmd = f"ls /var/containers/Bundle/Application/{uuid}"
            stdin, stdout, stderr = ssh.exec_command(app_dir_cmd)
            files = stdout.read().decode().splitlines()

            app_folder = next((f for f in files if f.endswith('.app')), None)

            if app_folder:
                app_path = f"/var/containers/Bundle/Application/{uuid}/{app_folder}"
                binary_name = app_folder.replace('.app', '')
                binary_path = f"{app_path}/{binary_name}"
                info_plist_path = f"{app_path}/Info.plist"

                stdin, stdout, stderr = ssh.exec_command(f"cat '{info_plist_path}'")
                plist_data = stdout.read()

                try:
                    plist = plistlib.load(io.BytesIO(plist_data))
                    bundle_id = plist.get("CFBundleIdentifier", "")
                except Exception:
                    bundle_id = ""

                matched_data_path = None
                for path in all_plist_paths:
                    if bundle_id in path:
                        matched_data_path = path.split("/Library/Preferences/")[0]
                        break

                if not matched_data_path and bundle_id:
                    grep_cmd = f"grep -slR '{bundle_id}' /var/mobile/Containers/Data/Application | head -n 1"
                    stdin, stdout, stderr = ssh.exec_command(grep_cmd)
                    grep_result = stdout.read().decode().strip()
                    if grep_result:
                        matched_data_path = grep_result.split("/Library")[0].split("/tmp")[0]

                final_data_path = matched_data_path if matched_data_path else "?**? Not matched"

                app_info = {
                    "uuid": uuid,
                    "app_name": binary_name,
                    "bundle_id": bundle_id,
                    "app_path": app_path,
                    "binary_path": binary_path,
                    "data_path": final_data_path
                }

                app_list.append(app_info)

        ssh.close()

        print("\n📦 Installed Applications:")
        for i, app in enumerate(app_list):
            print(f"[{i}] {app['app_name']} ({app['bundle_id']})")
            print(f"     📁 Binary : {app['binary_path']}")
            print(f"     📂 Data   : {app['data_path']}\n")

        return app_list, device_ip, username, password

    except Exception as e:
        print(f"XX An error occurred: {e}")
        return [], None, None, None

if __name__ == "__main__":
    list_apps_with_details()
