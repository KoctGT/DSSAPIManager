# DSSAPIManager ver1.0
import os
import json
import requests
import base64
import datetime
import keyring
import argparse
from requests_oauthlib import OAuth2Session
from getpass import getpass


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # FIX insecure conn
DELIMETER_LEVEL = "=" * 80
DELIMETER_ULEVEL = "-" * 80

parser = argparse.ArgumentParser(description="DSS API Manager")
parser.add_argument(
    "-s",
    "--settings_path",
    type=str,
    default=r"C:\distr\DSSAPIManager\\",
    help="Enter the path to the settings file 'settings.json' (default: C:\distr\DSSAPIManager\\)",
)
parser.add_argument(
    "-m",
    "--mode",
    type=str,
    default="",
    help="Select an operating mode. 1 - DSS user, 2 - DSS operator",
)
parser.add_argument(
    "-d",
    "--debug",
    type=str,
    default="",
    help="Debug mode. 'True' - enable, 'False' - disable.",
)
DAM_args = parser.parse_args()
settings_path = DAM_args.settings_path


def main():
    print(
        """______  _____ _____    ___  ______ _____  ___  ___                                  
|  _  \/  ___/  ___|  / _ \ | ___ \_   _| |  \/  |                                  
| | | |\ `--.\ `--.  / /_\ \| |_/ / | |   | .  . | __ _ _ __   __ _  __ _  ___ _ __ 
| | | | `--. \`--. \ |  _  ||  __/  | |   | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
| |/ / /\__/ /\__/ / | | | || |    _| |_  | |  | | (_| | | | | (_| | (_| |  __/ |   
|___/  \____/\____/  \_| |_/\_|    \___/  \_|  |_/\__,_|_| |_|\__,_|\__, |\___|_|   
                                                                     __/ |          
                                                                    |___/           
                                                                            v1.0"""
    )
    print(
        DELIMETER_LEVEL,
        "\nThe following path to the settings file is selected:",
        settings_path,
        "\n",
        DELIMETER_ULEVEL,
    )
    config_dict = load_settings(settings_path)
    if not keyring.get_password("CDRA", "ACI") or not keyring.get_password(
        "CDRA", "DCI"
    ):
        print("Credentials not found! Add credentials to Windows Credential Locker.")
        os.sys.exit(1)
    mode, debug = select_mode(mode=DAM_args.mode, debug=DAM_args.debug)  # Make choice
    SessionDSS = SessionCls(config_dict, debug)
    # User DSS mode
    if mode == "1":
        print(f"User Authorization in DSS ...")
        try:
            SessionDSS._adfs_client_id = keyring.get_password("CDRA", "ACI")
            SessionDSS._adfs_client_secret = keyring.get_password("CDRA", "ACS")
            SessionDSS._DSS_client_id = keyring.get_password("CDRA", "DCI")
            SessionDSS.get_ADFS_token()
            SessionDSS.get_DSS_token(mode)
        except ValueError as err:
            print("Authorization Error:", str(err))

        SessionDSS.get_certs(auth_token=SessionDSS._DSS_token)
        while True:
            print(DELIMETER_LEVEL)
            print(
                """
Select an action:
1 - Quick Signing Test (signing embedded test file and verify)
2 - Sign Document
3 - Verify Document Sign
4 - Current session info
5 - Quit (q)
"""
            )
            print(DELIMETER_LEVEL, "\n")
            inp_choice = input("Input action (1-5): ")
            if inp_choice in ["1", "2", "3", "4", "5", "q", "Q"]:
                if inp_choice == "1":
                    print(
                        "\n",
                        DELIMETER_LEVEL,
                        "\n",
                        "Attempt to sign a test document with the following parameters: ",
                        "\n",
                        DELIMETER_ULEVEL,
                        sep="",
                    )
                    print(
                        "Selected user certificate: ",
                        "Certificate ID: ",
                        SessionDSS.certs[0]["ID"],
                        "; Distinguished Name: ",
                        SessionDSS.certs[0]["DName"],
                        "\n",
                        DELIMETER_ULEVEL,
                        sep="",
                    )
                    SessionDSS._pincode = get_pin()
                    print("DocType:", SessionDSS.doc_types[0])
                    print("CAdES Type:", SessionDSS.cades_types[0])
                    SessionDSS.user_file_path = ""  # Clear File Path
                    SessionDSS.last_signed_doc = ""  # Clear sDoc
                    SessionDSS.sign_doc(cert_num=0, doc_type=0, cades_type=0)
                    print(
                        "The document was successfully signed!",
                        "\n",
                        DELIMETER_ULEVEL,
                        sep="",
                    )
                    print("Verify Sign...")
                    SessionDSS.user_sfile_path = ""  # Clear File Path
                    SessionDSS.user_file_base64 = SessionDSS._test_doc
                    SessionDSS.verify_sign(SessionDSS.user_sfile_path, 0)
                    print("\n", DELIMETER_LEVEL)

                if inp_choice == "2":
                    print("\n", DELIMETER_LEVEL, "\n", "User certificates:")
                    for i in range(len(SessionDSS.certs)):
                        print(
                            DELIMETER_ULEVEL,
                            "\n",
                            "Certificate № ",
                            str(i),
                            ". ",
                            "Certificate ID: ",
                            SessionDSS.certs[i]["ID"],
                            ", Distinguished Name: ",
                            SessionDSS.certs[i]["DName"],
                            "\n",
                            DELIMETER_ULEVEL,
                            sep="",
                        )

                    while True:
                        print("\n")
                        cert_choice = input(
                            "Select certificate (0-"
                            + str((len(SessionDSS.certs) - 1))
                            + "): "
                        )
                        if cert_choice in [
                            str(i) for i in range(len(SessionDSS.certs))
                        ]:
                            print(
                                "\n",
                                "Selected certificate №",
                                cert_choice,
                                " (",
                                "Certificate ID: ",
                                str(SessionDSS.certs[int(cert_choice)]["ID"]),
                                ", Distinguished Name: ",
                                SessionDSS.certs[int(cert_choice)]["DName"],
                                ")",
                                "\n",
                                DELIMETER_LEVEL,
                                "\n",
                                sep="",
                            )
                            break
                        print(
                            "Incorrect value. Please enter value 0 to "
                            + str((len(SessionDSS.certs)) - 1)
                        )

                    while True:
                        file_path = input("Enter full path to file: ")
                        if os.path.exists(file_path):
                            SessionDSS.user_file_path = file_path
                            print("\n", DELIMETER_LEVEL)
                            break
                        print("Incorrect file path! Please repeat.")

                    while True:
                        print(DELIMETER_LEVEL, "\n\n", "Select DocTypes: ", sep="")
                        for i in range(len(SessionDSS.doc_types)):
                            print(str(i) + ". " + SessionDSS.doc_types[i])
                        doc_type_choice = input(
                            "\nSelect DocTypes (0-"
                            + str((len(SessionDSS.doc_types) - 1))
                            + "): "
                        )
                        if doc_type_choice in [
                            str(i) for i in range(len(SessionDSS.doc_types))
                        ]:
                            print(
                                "\n",
                                "Selected DocType: ",
                                doc_type_choice,
                                " (",
                                SessionDSS.doc_types[int(doc_type_choice)],
                                ")",
                                "\n",
                                DELIMETER_LEVEL,
                                sep="",
                            )
                            break
                        print(
                            "Incorrect value. Please enter value 0 to "
                            + str((len(SessionDSS.doc_types)) - 1)
                        )

                    while True:
                        print(DELIMETER_LEVEL, "\n", "\nSelect CADESType: ")
                        for i in range(len(SessionDSS.cades_types)):
                            print(str(i) + ". " + SessionDSS.cades_types[i])
                        cades_types_choice = input(
                            "\nSelect (0-"
                            + str((len(SessionDSS.cades_types) - 1))
                            + "): "
                        )
                        if cades_types_choice in [
                            str(i) for i in range(len(SessionDSS.cades_types))
                        ]:
                            print(
                                "\n",
                                "Selected CADESType: ",
                                cades_types_choice,
                                " (",
                                SessionDSS.cades_types[int(cades_types_choice)],
                                ")",
                                "\n",
                                DELIMETER_LEVEL,
                                sep="",
                            )
                            break
                        print(
                            "Incorrect value. Please enter value 0 to ",
                            (len(SessionDSS.cades_types)) - 1,
                            sep="",
                        )

                    print(DELIMETER_LEVEL)
                    SessionDSS._pincode = get_pin()
                    print(DELIMETER_LEVEL)

                    SessionDSS.sign_doc(
                        cert_num=int(cert_choice),
                        doc_type=int(doc_type_choice),
                        cades_type=int(cades_types_choice),
                    )

                if inp_choice == "3":
                    print("\n", DELIMETER_LEVEL, "\n")
                    chk_path = True
                    while chk_path:
                        spath = input("Enter full path to the file being checked: ")
                        if os.path.exists(spath):
                            chk_path = False
                            while True:
                                for i in range(len(SessionDSS.doc_types)):
                                    print(str(i) + ". " + SessionDSS.doc_types[i])
                                doc_type_choice = input(
                                    "\nSelect Signature Type (0-"
                                    + str((len(SessionDSS.doc_types) - 1))
                                    + "): "
                                )
                                if doc_type_choice in [
                                    str(i) for i in range(len(SessionDSS.doc_types))
                                ]:
                                    print(
                                        "\n",
                                        "Selected Signature Type: ",
                                        doc_type_choice,
                                        " (",
                                        SessionDSS.doc_types[int(doc_type_choice)],
                                        ")",
                                        "\n",
                                        DELIMETER_LEVEL,
                                        sep="",
                                    )
                                    break
                                print(
                                    "Incorrect value. Please enter value 0 to "
                                    + str((len(SessionDSS.doc_types)) - 1)
                                )
                        if not chk_path:
                            break
                        print("Incorrect file path! Please repeat.")

                    SessionDSS.verify_sign(spath, int(doc_type_choice))
                    print("\n", DELIMETER_LEVEL)

                if inp_choice == "4":
                    back = False
                    while not back:
                        print("\n", DELIMETER_LEVEL, "\n")
                        print(
                            """
Select an item:
1 - Information about user certificates
2 - Show ADFS Token value
3 - Show DSS Token value
4 - Show last Signed Document
5 - Show last Base64 Document (before signing)
6 - Back to Main menu (q)
"""
                        )
                        print(DELIMETER_LEVEL, "\n")
                        inp_choice = input("Input action (1-6): ")
                        if inp_choice in ["1", "2", "3", "4", "5", "6", "q", "Q"]:
                            if inp_choice == "1":
                                print("\n", DELIMETER_LEVEL, "\n", "User certificates:")
                                for i in range(len(SessionDSS.certs)):
                                    print(
                                        DELIMETER_ULEVEL,
                                        "\n",
                                        "Certificate № ",
                                        str(i),
                                        ": ",
                                        "\n",
                                        SessionDSS.certs[i],
                                        "\n",
                                        DELIMETER_ULEVEL,
                                        sep="",
                                    )
                                print("\n", DELIMETER_LEVEL)

                            if inp_choice == "2":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="ADFS Token value: ",
                                    attr_val=SessionDSS._ADFS_token,
                                )
                                print(DELIMETER_LEVEL)

                            if inp_choice == "3":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="DSS Token value: ",
                                    attr_val=SessionDSS._DSS_token,
                                )
                                print(DELIMETER_LEVEL)

                            if inp_choice == "4":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="Path to save the last signed document: ",
                                    attr_val=SessionDSS.user_sfile_path,
                                )
                                print_attribute(
                                    attr_name="Last Signed Document(Base64): ",
                                    attr_val=SessionDSS.last_signed_doc,
                                )
                                print(DELIMETER_LEVEL)

                            if inp_choice == "5":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="Document Path: ",
                                    attr_val=SessionDSS.user_file_path,
                                )
                                print_attribute(
                                    attr_name="Document(Base64) before signing: ",
                                    attr_val=SessionDSS.user_file_base64,
                                )
                                print(DELIMETER_LEVEL)

                            elif inp_choice in ["6", "q", "Q"]:
                                back = True

                elif inp_choice in ["5", "q", "Q"]:
                    os._exit(1)
            else:
                print("Incorrect value. Please enter value 1 to 5")

    # Operator DSS mode
    if mode == "2":
        print(f"Operator Authorization in DSS ...")
        try:
            print("DSS Get Code URL: ", SessionDSS.getDSScode_url)
            print("Path to Operator Cert: ", SessionDSS.operator_cert_path)
            print("Path to Operator Key: ", SessionDSS.operator_key_path)
            SessionDSS._DSS_client_id = keyring.get_password("CDRA", "DCI")
            SessionDSS._DSS_client_secret = keyring.get_password("CDRA", "DCS")
            SessionDSS.get_DSS_code_mTLS()
            SessionDSS.get_DSS_token(mode)
        except ValueError as err:
            print("Authorization Error:", str(err))
        print(
            "Enter username to manage (local user login DSS). Example: HQ00-SC-ECM-TEST"
        )
        user = input("Enter username: ")
        SessionDSS.get_DSS_dm_token(user)
        SessionDSS.get_policy()
        while True:
            print(DELIMETER_LEVEL)
            print(
                """
Select an action:
1 - Certificate Issue Request
2 - Removing a certificate 
3 - Creating a DSS User
4 - DSS user search
5 - Deleting a DSS user
6 - Current session info
7 - Quit (q)
"""
            )
            print(DELIMETER_LEVEL, "\n")
            inp_choice = input("Input action (1-7): ")
            if inp_choice in ["1", "2", "3", "4", "5", "6", "7", "q", "Q"]:
                if inp_choice == "1":
                    print(
                        "\n",
                        DELIMETER_LEVEL,
                        "\n",
                        "Certificate Issue Request.",
                        sep="",
                    )
                    SessionDSS.new_cert_issue()

                if inp_choice == "2":
                    SessionDSS.get_certs(auth_token=SessionDSS._DSS_dm_token)
                    print("\n", DELIMETER_LEVEL, "\n", "User certificates:")
                    for i in range(len(SessionDSS.certs)):
                        print(
                            DELIMETER_ULEVEL,
                            "\n",
                            "Certificate № ",
                            str(i),
                            ": ",
                            "\n",
                            SessionDSS.certs[i],
                            "\n",
                            DELIMETER_ULEVEL,
                            sep="",
                        )

                    print("Select the certificate to remove from the list above.")
                    while True:
                        rm_cert_num = input(
                            "Select certificate (0-"
                            + str((len(SessionDSS.certs) - 1))
                            + "): "
                        )

                        if rm_cert_num in [
                            str(i) for i in range(len(SessionDSS.certs))
                        ]:
                            print(
                                "\n",
                                "Selected certificate №",
                                rm_cert_num,
                                " (",
                                "Certificate ID: ",
                                str(SessionDSS.certs[int(rm_cert_num)]["ID"]),
                                ", Distinguished Name: ",
                                SessionDSS.certs[int(rm_cert_num)]["DName"],
                                ")",
                                "\n",
                                DELIMETER_ULEVEL,
                                "\n",
                                sep="",
                            )
                            chk_accept = input(
                                r"Delete this certificate? It's right?(Y/N): "
                            )
                            if chk_accept.upper() == "Y":
                                SessionDSS.cert_remove(
                                    SessionDSS.certs[int(rm_cert_num)]["ID"]
                                )
                                break
                        else:
                            print(
                                "Incorrect value. Please enter value 0 to "
                                + str((len(SessionDSS.certs)) - 1)
                            )

                    print("\n", DELIMETER_LEVEL)

                if inp_choice == "3":
                    print("\n", DELIMETER_LEVEL, "\n", "Creating a DSS User.")
                    chk = False
                    while not chk:
                        user_attr = {}
                        user_attr["Login"] = input("Enter login: ")
                        user_attr["DisplayName"] = input(
                            "Enter DisplayName (ex, login@domain): "
                        )
                        user_attr["DistinguishName"] = input(
                            "Enter DistinguishName(Full name): "
                        )
                        print(
                            "\nThe following user attributes are specified: \n",
                            user_attr,
                            "\n",
                            sep="",
                        )
                        chk = input(r"It's right?(Y/N): ")
                        if chk.upper() == "Y":
                            chk = True
                    print("Request to create a user...")
                    SessionDSS.create_user(attr=user_attr)
                    print("\n", DELIMETER_LEVEL)

                if inp_choice == "4":
                    print("\n", DELIMETER_LEVEL, "\n", "DSS user search.\n")
                    param = {}
                    UID = input("Enter UserID (if unknown, leave blank): ")
                    if UID == "":
                        while True:
                            print(
                                "List of types: \nLogin (value: unique number),\nDisplayName (value: user@domain),\nDistinguishName (CN=Full Name)\n"
                            )
                            inp = input("Choose a type from the list above: ")
                            if inp in ["Login", "DisplayName", "DistinguishName"]:
                                param["type"] = inp
                                param["value"] = input("Enter value: ")
                                break
                            else:
                                print(
                                    "\nInvalid type value entered! Enter a type from the list!\n"
                                )
                    user_info = SessionDSS.find_user(user_id=UID, sparam=param)
                    print_attribute(attr_name="User info: \n", attr_val=user_info)
                    print(DELIMETER_LEVEL)

                if inp_choice == "5":
                    print("\n", DELIMETER_LEVEL, "\n", "Deleting a DSS user.")
                    while True:
                        user_id = input("Enter user ID: ")
                        try:
                            user_info = SessionDSS.find_user(user_id=user_id)
                            print_attribute(
                                attr_name="User info: \n", attr_val=user_info
                            )
                            chk_accept = input(r"Delete this user?(Y/N): ")
                            if chk_accept.upper() == "Y":
                                SessionDSS.delete_user(user_id)
                                break
                        except ValueError as err:
                            print("User search Error:", str(err))
                    print(DELIMETER_LEVEL)

                if inp_choice == "6":
                    back = False
                    while not back:
                        print("\n", DELIMETER_LEVEL, "\n")
                        print(
                            """
Select an item:
1 - Information about user certificates
2 - Show DSS Policy
3 - Show DSS Tokens
4 - Back to Main menu (q)
"""
                        )
                        print(DELIMETER_LEVEL, "\n")
                        inp_choice = input("Input action (1-6): ")
                        if inp_choice in ["1", "2", "3", "4", "q", "Q"]:
                            if inp_choice == "1":
                                SessionDSS.get_certs(
                                    auth_token=SessionDSS._DSS_dm_token
                                )
                                print("\n", DELIMETER_LEVEL, "\n", "User certificates:")
                                for i in range(len(SessionDSS.certs)):
                                    print(
                                        DELIMETER_ULEVEL,
                                        "\n",
                                        "Certificate № ",
                                        str(i),
                                        ": ",
                                        "\n",
                                        SessionDSS.certs[i],
                                        "\n",
                                        DELIMETER_ULEVEL,
                                        sep="",
                                    )
                                print("\n", DELIMETER_LEVEL)

                            if inp_choice == "2":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="DSS Policy value: ",
                                    attr_val=SessionDSS.policy,
                                )
                                print(DELIMETER_LEVEL)

                            if inp_choice == "3":
                                print("\n", DELIMETER_LEVEL, sep="")
                                print_attribute(
                                    attr_name="DSS token value: ",
                                    attr_val=SessionDSS._DSS_token,
                                )
                                print_attribute(
                                    attr_name="DSS dm-token value: ",
                                    attr_val=SessionDSS._DSS_dm_token,
                                )
                                print(DELIMETER_LEVEL)

                            elif inp_choice in ["4", "q", "Q"]:
                                back = True

                elif inp_choice in ["7", "q", "Q"]:
                    os._exit(1)
            else:
                print("Incorrect value. Please enter value 1 to 7")


class SessionCls:
    def __init__(self, config_dict, debug):
        self._ADFS_token = ""
        self._DSS_token = ""
        self._DSS_code_mTLS = ""
        self._DSS_dm_token = ""
        self._adfs_client_id = ""
        self._adfs_client_secret = ""
        self._DSS_client_id = ""
        self._DSS_client_secret = ""
        self._pincode = ""
        self.ADFS_authorize_url = config_dict["APIEndpoints"]["ADFSAuthorize"]
        self.ADFS_get_token_url = config_dict["APIEndpoints"]["ADFSGetToken"]
        self.get_DSS_token_url = config_dict["APIEndpoints"]["GetDSSToken"]
        self.get_certs_url = config_dict["APIEndpoints"]["Certs"]
        self.sign_url = config_dict["APIEndpoints"]["Sign"]
        self.verify_sign_url = config_dict["APIEndpoints"]["VerifySign"]
        self.redirect_uri = config_dict["APIEndpoints"]["RedirectURI"]
        self.getDSScode_url = config_dict["APIEndpoints"]["GetDSScode"]
        self.policy_uri = config_dict["APIEndpoints"]["PolicyURI"]
        self.requests_uri = config_dict["APIEndpoints"]["RequestsURI"]
        self.user_uri = config_dict["APIEndpoints"]["User"]
        self._adfs_scope = config_dict["AuthConfig"]["ADFS"]["scope"]
        self.doc_types = config_dict["SignConfig"]["DocTypes"]
        self.cades_types = config_dict["SignConfig"]["SignParameters"]["CADESType"]
        self.TSP_address = config_dict["SignConfig"]["SignParameters"]["TSPAddress"]
        self.debug = debug
        self.certs = ""
        self._test_doc = config_dict["TestDoc"]
        self.operator_cert_path = config_dict["Operator_cert_path"]
        self.operator_key_path = config_dict["Operator_key_path"]
        self.policy = ""
        self.user_file_path = ""
        self.user_sfile_path = ""
        self.user_file_base64 = ""
        self.last_signed_doc = ""

    def get_ADFS_token(self):
        self._ADFS_token = adfs_auth(
            auth_url=self.ADFS_authorize_url,
            token_url=self.ADFS_get_token_url,
            client_id=self._adfs_client_id,
            client_secret=self._adfs_client_secret,
            redirect_uri=self.redirect_uri,
            scope=self._adfs_scope,
            debug=self.debug,
        )

    def get_DSS_token(self, mode):
        if mode == "1":
            grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
        if mode == "2":
            grant_type = "authorization_code"

        self._DSS_token = dss_auth(
            dss_token_url=self.get_DSS_token_url,
            client_id=self._DSS_client_id,
            subject_token=self._ADFS_token,
            grant_type=grant_type,
            code=self._DSS_code_mTLS,
            redirect_uri="urn:ietf:wg:oauth:2.0:oob:auto",
            mode=mode,
            debug=self.debug,
        )
        if self.debug:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Received DSS Token: ",
                "\n",
                self._DSS_token,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

    def get_certs(self, auth_token):
        self.certs = dss_get_req(get_url=self.get_certs_url, dss_token=auth_token)
        if self.debug:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Received certs: ",
                "\n",
                self.certs,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

    def sign_doc(self, cert_num, doc_type, cades_type):
        if self.user_file_path == "":
            enc_doc = self._test_doc
        else:
            try:
                print("\n", "Loading and encoding document...", sep="")
                enc_doc = base64_encode(self.user_file_path)
                self.user_file_base64 = enc_doc
            except ValueError:
                print(f"Encode document error: {ValueError}")
        if self.debug:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Base64 doc: ",
                "\n",
                enc_doc[:30],
                "......",
                enc_doc[-30:],
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

        print("Attempt to sign a document...")
        self.last_signed_doc, status = sign_doc_req(
            sign_url=self.sign_url,
            DSS_token=self._DSS_token,
            TSP_address=self.TSP_address,
            cert_id=self.certs[cert_num]["ID"],
            doc_type=self.doc_types[doc_type],
            cades_type=self.cades_types[cades_type],
            doc=enc_doc,
            pincode=self._pincode,
        )
        if status == 200:
            if self.user_file_path == "":
                pass
            else:
                try:
                    base64_decode_and_save(
                        base64signdoc=self.last_signed_doc,
                        path_to_save=self.user_file_path + ".sig",
                    )
                    self.user_sfile_path = self.user_file_path + ".sig"
                except ValueError:
                    print(f"Save signed document error: {ValueError}")

                print(
                    "The document was successfully signed and saved in: ",
                    self.user_file_path + ".sig",
                )

            if self.debug:
                print(
                    DELIMETER_ULEVEL,
                    "\n",
                    "Signed Document (Base64 encoded): ",
                    "\n",
                    self.last_signed_doc[:30],
                    "......",
                    self.last_signed_doc[-30:],
                    "\n",
                    DELIMETER_ULEVEL,
                    sep="",
                )
        else:
            print(
                "Document signing failed! Response received:\n",
                "Status code: ",
                status,
                "\nMessage:\n",
                self.last_signed_doc,
                sep="",
            )

    def verify_sign(self, sdoc_path, signature_type):
        if sdoc_path == "" and self.user_sfile_path == "":
            enc_doc = self.last_signed_doc
        else:
            try:
                enc_doc = base64_encode(sdoc_path)
            except ValueError:
                print(f"Encode document error: {ValueError}")

        verify_res, status = verify_sign_req(
            verify_sign_url=self.verify_sign_url,
            DSS_token=self._DSS_token,
            doc=enc_doc,
            sign_type=self.doc_types[signature_type],
        )

        if status == 200 and verify_res[0]["Result"] == True:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Document verification passed!\n",
                DELIMETER_ULEVEL,
                "\nResult received: \n",
                verify_res,
                "\n",
                DELIMETER_ULEVEL,
                "\n",
                sep="",
            )
        else:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Document validation failed! Response received:\n",
                "Status code: ",
                status,
                "\nMessage:\n",
                verify_res,
                "\n",
                DELIMETER_ULEVEL,
                "\n",
                sep="",
            )

    def get_DSS_code_mTLS(self):
        args = {
            "client_id": self._DSS_client_id,
            "response_type": "code",
            "scope": "dss",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob:auto",
            "resource": "urn:cryptopro:dss:signserver:signserver",
        }
        r = requests.get(
            self.getDSScode_url,
            params=args,
            cert=(self.operator_cert_path, self.operator_key_path),
            verify=False,
            allow_redirects=False,
        )
        if r.status_code == 302:
            loc_header = r.headers["Location"]
            self._DSS_code_mTLS = loc_header.split("?")[1].split("=")[1]
            print("DSS code: ", self._DSS_code_mTLS, sep="")
        else:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Code getting error! ",
                "Received: ",
                "\n",
                r.headers,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

    def get_DSS_dm_token(self, user):
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
        current_time = datetime.datetime.now()
        time_to_live = current_time + datetime.timedelta(minutes=10)
        nbf = int(current_time.timestamp())
        exp = int(time_to_live.timestamp())
        iat = nbf
        sub_token_head = {"alg": "none", "typ": "JWT"}
        sub_token_payload = {"unique_name": user, "nbf": nbf, "exp": exp, "iat": iat}

        encoded_sub_token = (
            base64.b64encode(
                json.dumps(sub_token_head, indent=4).encode("utf-8")
            ).decode("utf-8")
            + "."
            + base64_url_encode(
                json.dumps(sub_token_payload, indent=4).encode("utf-8")
            ).decode("utf-8")
            + "."
        )
        print("encoded_sub_token: ", encoded_sub_token)

        self._DSS_dm_token = dss_auth(
            dss_token_url=self.get_DSS_token_url,
            client_id=self._DSS_client_id,
            client_secret=self._DSS_client_secret,
            token=self._DSS_token,
            subject_token=encoded_sub_token,
            grant_type=grant_type,
            mode="3",
            debug=self.debug,
        )
        if self.debug:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Received DSS dm-Token: ",
                "\n",
                self._DSS_dm_token,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

    def get_policy(self):
        self.policy = dss_get_req(get_url=self.policy_uri, dss_token=self._DSS_token)
        if self.debug:
            print(
                DELIMETER_ULEVEL,
                "\n",
                "Received policy: ",
                "\n",
                self.policy,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )

    def new_cert_issue(self):
        ca_id = self.policy["CAPolicy"][0]["ID"]
        print(
            "Used next CA: ",
            "CA Name: ",
            self.policy["CAPolicy"][0]["Name"],
            "; CA ID: ",
            ca_id,
            "\n",
            DELIMETER_LEVEL,
            sep="",
        )

        cert_templ = self.policy["CAPolicy"][0]["EKUTemplates"]["Пользователь"][0]
        print(
            DELIMETER_LEVEL, "\nThe following certificate template has been selected: "
        )
        print(
            "Template 'Пользователь' (OID: ", cert_templ, ")\n", DELIMETER_LEVEL, sep=""
        )
        chk = False
        cert_args = {}
        cert_args_res = {}
        while not chk:
            print(
                DELIMETER_LEVEL,
                "\nEnter the attributes of the issued certificate.\n",
                sep="",
            )
            for i in range(len(self.policy["CAPolicy"][0]["NamePolicy"])):
                if (
                    self.policy["CAPolicy"][0]["NamePolicy"][i]["OID"]
                    == "1.2.643.100.3"
                ):
                    print(
                        "Attention! The SNILS format must contain 11 digits in a row!. Example: 17816373499"
                    )
                inp = input(
                    "Введите "
                    + self.policy["CAPolicy"][0]["NamePolicy"][i]["Name"]
                    + " (OID: "
                    + self.policy["CAPolicy"][0]["NamePolicy"][i]["OID"]
                    + "): "
                )
                cert_args[self.policy["CAPolicy"][0]["NamePolicy"][i]["OID"]] = [
                    inp,
                    self.policy["CAPolicy"][0]["NamePolicy"][i]["Name"],
                ]

            print(
                DELIMETER_ULEVEL,
                "\nThe following certificate attributes have been entered: \n",
                sep="",
            )
            for oid, inp_and_name in cert_args.items():
                print(inp_and_name[1], "(OID: ", oid, "): ", inp_and_name[0])
            inp_chk = input("\n" + r"It's right?(Y\N): ")
            if inp_chk.upper() == "Y":
                for k, v in cert_args.items():
                    cert_args_res[k] = v[0]
                print(DELIMETER_LEVEL)
                chk = True

        print(DELIMETER_LEVEL)
        self._pincode = get_pin()
        print(DELIMETER_LEVEL)

        resp, status = new_cert_req(
            url=self.requests_uri,
            dss_token=self._DSS_dm_token,
            ca_id=ca_id,
            templ=cert_templ,
            attr=cert_args_res,
            pin=self._pincode,
            debug=self.debug,
        )
        if status == 200:
            if resp["Status"] == "ACCEPTED":
                print(
                    DELIMETER_LEVEL,
                    "\n",
                    "Certificate issued successfully!\n Information about the issued certificate: \n",
                    sep="",
                )
                print(
                    "CertificateID: ",
                    resp["CertificateID"],
                    "\n",
                    "DistName: ",
                    resp["DistName"],
                    "\n",
                    "Certificate_in_Base64: ",
                    resp["Base64Request"],
                    "\n",
                    DELIMETER_LEVEL,
                    sep="",
                )
            else:
                print(
                    DELIMETER_LEVEL,
                    "\n",
                    "Certificate issue status:",
                    resp["Status"],
                    sep="",
                )
                print("Message:\n", resp, "\n", DELIMETER_LEVEL, sep="")
        else:
            print(
                DELIMETER_LEVEL,
                "\n",
                "Error issuing certificate! Response received:\n",
                "Status code: ",
                status,
                "\nMessage:\n",
                resp,
                "\n",
                DELIMETER_LEVEL,
                sep="",
            )

        if self.debug:
            print(
                DELIMETER_LEVEL,
                "\n",
                "Request status: ",
                status,
                "\nResponse received: \n",
                resp,
                "\n",
                DELIMETER_LEVEL,
                sep="",
            )

    def cert_remove(self, cert_id):
        headers = {
            "Authorization": "Bearer " + self._DSS_dm_token,
        }
        full_url = self.get_certs_url + "/" + str(cert_id)
        resp, status = dss_del_req(url=full_url, headers=headers, debug=self.debug)
        if status == 200:
            print(
                DELIMETER_ULEVEL,
                "\nCertificate was successfully remove.\n",
                DELIMETER_ULEVEL,
                sep="",
            )
        else:
            print(
                DELIMETER_ULEVEL,
                "\nAn error occurred while deleting the certificate: \n",
                "Status: ",
                status,
                "DSS response: ",
                resp,
                DELIMETER_ULEVEL,
                sep="",
            )

    def create_user(self, attr):
        headers = {"Content-Type": "application/json; charset=utf-8"}

        resp, status = dss_post_req(
            url=self.user_uri,
            headers=headers,
            data=attr,
            cert_path=[self.operator_cert_path, self.operator_key_path],
            debug=self.debug,
        )

        if status == 200:
            print(
                DELIMETER_ULEVEL,
                "\nUser successfully created.\n",
                "User ID: ",
                resp,
                "\n",
                DELIMETER_ULEVEL,
                sep="",
            )
        else:
            print(
                DELIMETER_ULEVEL,
                "\nAn error occurred while creating user: \n",
                "Status: ",
                status,
                "DSS response: ",
                resp,
                DELIMETER_ULEVEL,
                sep="",
            )

    def find_user(self, user_id="", sparam={}):
        if user_id:
            full_url = self.user_uri + "/" + user_id
            resp = dss_get_req(
                get_url=full_url,
                cert_path=[self.operator_cert_path, self.operator_key_path],
                req_auth=False,
                rtype="json",
                debug=self.debug,
            )
        elif sparam:
            resp = dss_get_req(
                get_url=self.user_uri,
                params=sparam,
                cert_path=[self.operator_cert_path, self.operator_key_path],
                req_auth=False,
                rtype="json",
                debug=self.debug,
            )

        return resp

    def delete_user(self, user_id):
        full_url = self.user_uri + "/" + user_id
        resp, status = dss_del_req(
            url=full_url,
            cert_path=[self.operator_cert_path, self.operator_key_path],
            debug=self.debug,
        )
        if status == 200:
            print(
                DELIMETER_ULEVEL,
                "\nUser deleted successfully.\n",
                DELIMETER_ULEVEL,
                sep="",
            )
        else:
            print(
                DELIMETER_ULEVEL,
                "\nAn error occurred while deleting a user: \n",
                "Status: ",
                status,
                "DSS response: ",
                resp,
                DELIMETER_ULEVEL,
                sep="",
            )


def load_settings(path=""):
    full_path = path + "settings.json"
    if os.path.exists(full_path):
        with open(full_path, "r") as file:
            dictData = json.loads(file.read())
        return dictData
    else:
        print(r"Not found configuration file...Enter any key for exit.")
        _ = input(": ")
        os._exit(1)


def select_mode(mode, debug):
    if mode == "" or mode not in ["1", "2"]:
        answ = True
        while answ:
            print("Select mode: 1 - User DSS, 2 - Operator DSS, 'q' - quit")
            mode = input("Enter mode: ")
            if mode in ["1", "2"]:
                answ = False
            elif mode.lower() == "q":
                os._exit(1)
            else:
                print("Incorrect value. Please enter '1', '2' or 'q'")

    if debug == "" or debug not in ["True", "False"]:
        debug = False
        print("Enable debug?(N)")
        debug = input("Enter Y or N: ")
        if debug.upper() == "Y":
            debug = True
    elif debug in ["True", "False"]:
        if debug == "True":
            debug = True
        else:
            debug = False

    if debug == True:
        print("Debug messages enabled.\n", DELIMETER_ULEVEL)
    if mode == "1":
        print("Selected mode 'User DSS'\n", DELIMETER_LEVEL, "\n")
    else:
        print("Selected mode: 'Operator DSS'\n", DELIMETER_LEVEL, "\n", sep="")

    return mode, debug


def adfs_auth(
    auth_url,
    token_url,
    client_id,
    client_secret,
    redirect_uri,
    debug,
    scope=["openid", "allatclaims"],
):
    """Bad code. In future change oauthlib on requests"""
    state = "OpenIdConnect.AuthenticationProperties=r1F_RjGUIqyjZYHN29lvw9kxVjUzcF3V-Oc1ylU2K_RFLOgKrC_CgGfvHQnzU7AKj6Ac8sl-fbYF_CaAdebTv-AbJqsM6IWnyMIWl2wj9okjDJi2PHGKdyhl66MCYd8LfOLl-jH8TL2tT8A7TCf7tPeQsJzJGbzfa2r2rgYXRhGp_evI0f4arASMXD-YvDvg1BjiReQqGlge6c1blbBmIod6J6Hj01sJPL-L73DpKB3gbKdzjR2Ri_Rw8LK6jC44T7kI2omeR-SP_oq7RTqReZh2XP12iWKWC1akAw3YFR-bsNAxGdx2S2Ca-3h62ggfn2DIMmiVAqvuFb-Tj12S-VKTO-s-3ScsYxR3aEdFj6oDIBY7qcNmunvAlnkqf1LX1_uX9r3-h4cqi7jLu5b2tL1nulN4lSeopZPt8Qocd7oyepm85aA_7G3-CWwZ9iUTKNpPIa6txkFxc9u8iHPmhSqaKrUOob_6KiHX63kw44gdk3rQMTmr-MNHojue9dxUj4WmPEhMeD7vPgZXV2oCXaRefhlnPZ-qFTajpqY6DfN1UZCZSj1Vkph06njlllYcv8i9IhjIBacuQSVDjh2-xKKqoKlWlQRec1EfaoWmmfOY_x39_ciqp-HZFYPzxkC8nt6EiGt3O7HZYRR3J5NBfnaYSn-9WXGmjC9-4_koj9o"
    response_mode = "form_post"
    nonce = "637721215633622240.MmIzYTkzNjgtNmE4OC00NmMxLTliZGYtNWFmNDIxMjUzMWFlY2Y5ZDUxNmMtM2YxZi00YTU2LThhZjAtNGZlMWM4OWNkOWY1"

    adfs_session = OAuth2Session(
        client_id, scope=scope, redirect_uri=redirect_uri, state=state
    )

    # Redirect  the user owner to the OAuth provider using an URL with a few key OAuth parameters.
    # authorization_url, state = adfs_session.authorization_url(auth_url, response_type='id_token')
    authorization_url, state = adfs_session.authorization_url(auth_url)
    authorization_url = (
        authorization_url
        + "&"
        + "response_mode="
        + response_mode
        + "&"
        + "nonce="
        + nonce
    )  # FIX ADFS requirements

    print("Please go here and authorize,", authorization_url)

    # Get the authorization verifier code from the callback url
    # redirect_response = input('Paste the full redirect URL here:')
    id_token = input("Paste the id_token value:")
    print(DELIMETER_ULEVEL)
    # redirect_response =

    # Fetch the access token
    """if client_secret:
        token = adfs_session.fetch_token(token_url, client_secret=client_secret, authorization_response=redirect_response)
    else:
        token = adfs_session.fetch_token(token_url, authorization_response=redirect_response)
    """
    # Fetch a protected resource and print token. Debug mode
    return id_token


def dss_auth(
    dss_token_url,
    client_id,
    grant_type,
    mode,
    client_secret="",
    token="",
    subject_token="",
    code="",
    redirect_uri="",
    debug=False,
):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data1 = {
        "grant_type": grant_type,
        "client_id": client_id,
        "resource": "urn:cryptopro:dss:signserver:SignServer",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    }

    data2 = {
        "grant_type": grant_type,
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    data3 = {
        "grant_type": grant_type,
        "client_id": client_id,
        "resource": "urn:cryptopro:dss:signserver:SignServer",
        "actor_token": token,
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": subject_token,
    }

    if mode == "1":
        data = data1
    if mode == "2":
        data = data2
    if mode == "3":
        data = data3
        auth = base64.b64encode(
            (client_id + ":" + client_secret).encode("utf-8")
        ).decode("utf-8")
        headers["Authorization"] = "Basic " + auth

    r = requests.post(dss_token_url, data=data, headers=headers)
    if debug:
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.url: ",
            "\n",
            r.request.url,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.headers: ",
            "\n",
            r.request.headers,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.body: ",
            "\n",
            r.request.body,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "DSS Response: ",
            "\n",
            r.json(),
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
    return r.json()["access_token"]


def dss_get_req(
    get_url,
    dss_token="",
    headers="",
    req_auth=True,
    params="",
    cert_path=[],
    rtype="json",
    debug=False,
):
    if req_auth:
        headers = {}
        headers["Authorization"] = "Bearer " + dss_token

    if params == "":
        params = {}

    if headers == "":
        headers = {}

    if get_url[4] == "s":
        r = requests.get(
            get_url,
            headers=headers,
            params=params,
            cert=(cert_path[0], cert_path[1]),
            verify=False,
        )
    else:
        r = requests.get(get_url, headers=headers, params=params)

    if debug:
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.url: ",
            "\n",
            r.request.url,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.headers: ",
            "\n",
            r.request.headers,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.body: ",
            "\n",
            r.request.body,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "DSS Response: ",
            "\n",
            r.text,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )

    if rtype == "json":
        return r.json()
    else:
        return r.text


def dss_post_req(url, headers, data, debug, cert_path=[]):
    if url[4] == "s":
        r = requests.post(
            url,
            json=data,
            headers=headers,
            cert=(cert_path[0], cert_path[1]),
            verify=False,
        )
    else:
        r = requests.post(url, json=data, headers=headers)
    if debug:
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.url: ",
            "\n",
            r.request.url,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.headers: ",
            "\n",
            r.request.headers,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.body: ",
            "\n",
            r.request.body,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "DSS Response: ",
            "\n",
            r.text,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )

    return r.text, r.status_code


def dss_del_req(url, headers={}, cert_path=[], debug=False):
    if url[4] == "s":
        r = requests.delete(
            url, headers=headers, cert=(cert_path[0], cert_path[1]), verify=False
        )
    else:
        r = requests.delete(url, headers=headers)

    if debug:
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.url: ",
            "\n",
            r.request.url,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.headers: ",
            "\n",
            r.request.headers,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.body: ",
            "\n",
            r.request.body,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "DSS Response: ",
            "\n",
            r.text,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
    return r.text, r.status_code


def base64_encode(file):
    with open(file, "rb") as bin_file:
        encoded_string = base64.b64encode(bin_file.read())
    return encoded_string.decode()


def base64_decode_and_save(base64signdoc, path_to_save):
    with open(path_to_save, "wb") as bin_file:
        bin_file.write(base64.b64decode(base64signdoc))


def sign_doc_req(
    sign_url, DSS_token, TSP_address, cert_id, doc_type, cades_type, doc, pincode
):
    auth_header = "Bearer " + DSS_token
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Expect": "100-continue",
    }
    req_body = get_json_body(TSP_address, cert_id, doc_type, cades_type, doc, pincode)
    print(
        "Request_body: \n",
        json.dumps(req_body)[:300],
        ".....",
        json.dumps(req_body)[-300:],
        "\n",
        sep="",
    )
    r = requests.post(sign_url, json=req_body, headers=headers)
    return r.json(), r.status_code


def verify_sign_req(verify_sign_url, DSS_token, doc, sign_type):
    auth_header = "Bearer " + DSS_token
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Expect": "100-continue",
    }
    jdata_templ = """{
    "SignatureType": "",
    "Content": ""
    }"""
    jdata_dict = json.loads(jdata_templ)
    jdata_dict["SignatureType"] = sign_type
    jdata_dict["Content"] = doc
    r = requests.post(verify_sign_url, json=jdata_dict, headers=headers)
    return r.json(), r.status_code


def get_json_body(TSP_address, cert_id, doc_type, cades_type, doc, pincode):
    jdata_cades_templ = """{
            "Content": "",
            "Signature": {
                "Type": "CAdES",
                "Parameters": {
                    "Hash": "False",
                    "CADESType": "",
                    "IsDetached": "False"
                    },
                "CertificateId": "",
                "PinCode": ""
                }
            }"""

    jdata_pdf_templ = """{
            "Content": "",
            "Signature": {
                "Type": "PDF",
                "Parameters": {
                    "PDFFormat": "CMS"
                    },
                "CertificateId": "",
                "PinCode": ""
                }
            }"""

    if doc_type == "PDF":
        jdata_dict = json.loads(jdata_pdf_templ)
        if cades_type == "BES":
            jdata_dict["Signature"]["Parameters"]["PDFFormat"] = "CMS"
        elif cades_type == "XLT1":
            jdata_dict["Signature"]["Parameters"]["PDFFormat"] = "1"  # 1=XLT1
    else:
        jdata_dict = json.loads(jdata_cades_templ)
        jdata_dict["Signature"]["Parameters"]["CADESType"] = cades_type
        if cades_type == "XLT1":
            jdata_dict["Signature"]["Parameters"]["TSPAddress"] = TSP_address

    jdata_dict["Content"] = doc
    jdata_dict["Signature"]["Type"] = doc_type
    jdata_dict["Signature"]["CertificateId"] = cert_id
    jdata_dict["Signature"]["PinCode"] = pincode

    return jdata_dict


def print_attribute(attr_name, attr_val):
    print(
        "\n",
        DELIMETER_ULEVEL,
        "\n",
        attr_name,
        attr_val,
        "\n",
        DELIMETER_ULEVEL,
        sep="",
    )


def get_pin():
    while True:
        print("Enter certificate PIN (empty input = default PIN)")
        pin = getpass("Enter PIN: ")
        if pin == "":
            pin = keyring.get_password("CDRA", "DPN")
            print("Will be used default PIN.")
            break

        pin_chk = getpass("Repeat PIN: ")
        if pin == pin_chk:
            break
        print("The entered values PIN do not match. Please repeat." + "\n")

    return pin


def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def base64_url_decode(data):
    padding = b"=" * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)


def new_cert_req(url, dss_token, ca_id, templ, attr, pin, debug):
    headers = {
        "Authorization": "Bearer " + dss_token,
        "Content-Type": "application/json; charset=utf-8",
        "Expect": "100-continue",
    }

    data = {
        "AuthorityId": ca_id,
        "PinCode": pin,
        "Template": templ,
        "DistinguishedName": attr,
        "Parameters": {},
    }

    r = requests.post(url, json=data, headers=headers)
    if debug:
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.url: ",
            "\n",
            r.request.url,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.headers: ",
            "\n",
            r.request.headers,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "r.request.body: ",
            "\n",
            r.request.body,
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
        print(
            DELIMETER_ULEVEL,
            "\n",
            "DSS Response: ",
            "\n",
            r.json(),
            "\n",
            DELIMETER_ULEVEL,
            sep="",
        )
    return r.json(), r.status_code


if __name__ == "__main__":
    main()
