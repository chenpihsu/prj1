#!/usr/bin/python2.7

import argparse
import base64
import getpass
import os
import os.path
import socket
from sre_constants import IN
import sys
import xml.etree.ElementTree as ET
import time

from subprocess import PIPE, Popen


#
# Set the Python Path requirement for this script
#

sys.path.append("/opt/em7/backend")
sys.path.append("/opt/em7/lib/python")
sys.path.append("/var/lib/em7/content")

#
# Load the Modules based in the path we set up
#

module_detail = "winrm"

try:
    from winrm.protocol import Protocol

    module_detail = "kerberos BasicAuthError"
    from kerberos import BasicAuthError

    module_detail = "winrm.exceptions"
    from winrm.exceptions import WinRMTransportError
except Exception as e:
    #
    # Force an exit with a "helpful" message
    #

    sys.exit(
        "\n**** The {0} module was not loaded, make sure it is in the path where the script is located. Error:\n    {1}".format(
            module_detail, e
        )
    )
# end try

# Are we Python 3 or 2?
IS_PY3 = sys.version_info[0] > 2

# Constants used

MIN_PORT = 1024
MAX_PORT = 49151
DEFAULT_HTTPS_PORT = 5986
DEFAULT_HTTP_PORT = 5985

MAX_WINRM_CMD_LENGTH = 8160

PYWINRM_TRANSPORT_KRB = "kerberos"
PYWINRM_TRANSPORT_NT = "ntlm"
PYWINRM_TRANSPORT_PLAINTEXT = "plaintext"

PYWINRM_SERVICE_HTTP = "http"
PYWINRM_SERVICE_HTTPS = "http"
PYWINRM_SERVICE_HOST = "host"
PYWINRM_SERVICE_WSMAN = "wsman"

PS_CMD = "powershell -NoProfile"
PS_ENCODED_CMD = "powershell -NoProfile -EncodedCommand"

WSMAN_HTTP_URL = "http://{0}:{1}/wsman"
WSMAN_HTTPS_URL = "https://{0}:{1}/wsman"

CLIXML = "CLIXML"
CLIXML_ERR_SIG = ""
CLIXML_REMOVE = "_x000D__x000A_"
CLIXML_SCHEMA = "{http://schemas.microsoft.com/powershell/2004/04}"

PYWINRM_PROXY_CMD_WRAPPER = (
    '$pwd=ConvertTo-SecureString -String "%s" -AsPlainText -Force;'
    '$cred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "%s",$pwd;'
    "$ses=New-PSSession -ComputerName %s -Credential $cred;"
    "Invoke-Command -Session $ses -ScriptBlock { %s } | %s | Out-String -Width 250;exit;"
    "Remove-PSSession $ses;"
)
DEFAULT_PROXY_FORMAT = "fl"

DEFAULT_CMD = "(Get-CimInstance -ClassName Win32_ComputerSystem).Name"

KRB_TICKET_TEMPLATE = "/tmp/test_krb5cc_{0}_{1}"

KDC_ENTRY = "[realms]\n{0} = {1}\n\tkdc = {2}\n{3}"
LEFT_B = "{"
RIGHT_B = "}"

SECTION = "========================================================================================================================"  #

# Global data

RETURN_TIMES = {}
ACTION_INFO = {
    1: "Create Shell",
    2: "Submit Command",
    3: "Execute Command and Read Output",
}

INPUTS = {
    "target": None,
    "lookup": None,
    "proxy": None,
    "user": None,
    "principal": None,
    "realm": None,
    "HTTPS": None,
    "Port": None,
    "NoPing": True,
    "cmd": None,
    "cert_validation": None,
    "NoOut": False,
    "format": None,
    "force": False,
    "service_wsman": False,
    "service_host": False,
    "transport": PYWINRM_TRANSPORT_KRB,
}

# Functions used to prepare


def wv(message):
    """
    Write a message if verbose is enabled
    :param message:
    :return:
    """
    if VERBOSE:
        print(message)
    # end if


# ev


def valid_ports(value):
    """
    Use to allow only values between 1024 and 49151
    :param value:
    :return:
    """

    ivalue = None

    try:
        ivalue = int(value)
    except Exception:
        raise argparse.ArgumentTypeError(
            "\n\n**** The port number must be an integer value. {0} is invalid".format(value)
        )
    # end try

    if ivalue and (ivalue < MIN_PORT or ivalue > MAX_PORT):
        raise argparse.ArgumentTypeError(
            "\n\n**** Port number must be between {0} and {1}, {2} is invalid".format(
                MIN_PORT, MAX_PORT, ivalue
            )
        )
    # end if

    return ivalue


# valid_ports


def _parse_cli_xml_error(raw_data):
    """
    Use Xml parsing to determine if the meassage is simply informational or an error
    :param raw_data:
    :return:
    """

    is_error = False
    error_data = ""
    short_error = ""

    if raw_data.find(CLIXML) > -1:
        # Only process if this is CLIXML

        try:
            location = "setting Xml tree"
            tree = ET.fromstring(raw_data.replace(CLIXML, "").replace("#<", ""))

            location = "starting Xml processing"
            child_loop = 0

            for child in tree:
                child_loop += 1
                location = "processn Xml child node {0}".format(child_loop)

                if child.attrib["S"] == "Error":
                    location += ", attribute is error"
                    is_error = True
                    error_line = child.text.replace(CLIXML_REMOVE, "").replace("\\'", "'")
                    error_data += "{0}".format(error_line)

                    #
                    # For display. Looks odd but Microsoft use a message format of
                    #
                    # MESSAGE HERE
                    #   + CONTINUE HERE
                    #   + CONTINUE HERE
                    #
                    # And also try to format within x characters, so some lines are
                    #
                    #   + CONINUE HERE BUT
                    #       BREAKS HERE
                    #

                    if error_line.lstrip()[0:1] != "+" and error_line.lstrip() == error_line:
                        short_error += "{0}".format(error_line)

        except BaseException as err:
            print(
                "PowerShell runtime error, failed to process raw error message when {0}. The error was: {1} and the"
                "message being processed was: {2}".format(location, err, raw_data)
            )
            error_data = raw_data
            short_error = raw_data

    else:
        error_data = raw_data
        short_error = raw_data

    # log to debug the long error if there is one

    if len(error_data) > 0:
        wv("PowerShell runtime error = %s" % error_data)

    return is_error, short_error


def validate_inputs():
    """
    Validate the inputs and store the data
    :return:
    """

    ok = True
    msg = ""

    if not INPUTS["target"]:
        msg += "\n  No target server was specified"
        ok = False
    else:
        #
        # If a proxy is used then the proxy is the server to lookup/ping, otherwise the tagrget is
        #

        if INPUTS["proxy"]:
            INPUTS["lookup"] = INPUTS["proxy"]
        else:
            INPUTS["lookup"] = INPUTS["target"]
        # end if

    if not INPUTS["user"]:
        msg += "\n  No username was specified"
        ok = False
    else:
        #
        # User needs to be in a specific format if Kerberos is to be used
        #

        tmp = INPUTS["user"]

        if tmp.find("@") == -1 and tmp.find("\\") == -1:
            INPUTS["transport"] = PYWINRM_TRANSPORT_PLAINTEXT
        else:
            #
            # Get the user (principal) and domain(realm) from the input
            #

            if tmp.find("@") > -1:
                INPUTS["principal"] = tmp.split("@")[0]
                INPUTS["realm"] = tmp.split("@")[1].upper()
            else:
                INPUTS["principal"] = tmp.split("\\")[1]
                INPUTS["realm"] = tmp.split("\\")[0].upper()
            # end if

            # Now store the user as user@DOMAIN
            INPUTS["user"] = "{0}@{1}".format(INPUTS["principal"], INPUTS["realm"])
        # end if

    # end if

    #
    # Set the default port for the transport if the port is not specified
    #

    if INPUTS["HTTPS"] and not INPUTS["Port"]:
        INPUTS["Port"] = DEFAULT_HTTPS_PORT
    # end if

    if not INPUTS["HTTPS"] and not INPUTS["Port"]:
        INPUTS["Port"] = DEFAULT_HTTP_PORT
    # end if

    wv("\nInputs:\n\n{0}\n".format(INPUTS))

    if not ok:
        print("**** Unable to continue:\n{0}".format(msg))
    # end if

    return ok


# validate_inputs

# Announce ourselves

__author__ = "Andy Doran"
__version__ = "2.2"
__copyright__ = "Copyright 2021 ScienceLogic, Inc. All Rights Reserved"
__status__ = "Prototype"

print(
    """

************************************************************************************************************************
SL1 PowerShell Test and Verification helper V{0} {1}
************************************************************************************************************************
""".format(
        __version__, __copyright__
    )
)

# Process the inputs

usage = """
This script can be used on a Data Collector server or Concurrent PowerShell container - it will verify the supplied
credentials can be used to issue a PowerShell command on the target server. If the process fails at any point, then
information will be provided to show why the failure happened and at which stage of the process.

If a proxy is specified, the script will execute PSRemote to the target server from the Proxy (meaning that the
WinRM connection will be made to the Proxy device rather than the target device).

The default command issued will be:

  {0}

but this can be overridden. If the override (-cmd) specifies a file then the contents of that file will be parsed and
sent as the PowerShell command.\n\n
""".format(
    DEFAULT_CMD
)

parser = argparse.ArgumentParser(
    epilog=usage, formatter_class=argparse.RawDescriptionHelpFormatter
)

parser.add_argument(
    "-server", "--target-server", help="Server to execute command on", dest="target"
)
parser.add_argument("-proxy", "--proxy-server", help="Proxy server to use", dest="proxy")
parser.add_argument(
    "-user", "--username", help="User in DOMAIN\\USER or USER@DOMAIN format", dest="user"
)
parser.add_argument(
    "-pwd", "--password", help="Password (leave blank to be prompted)", dest="password"
)
parser.add_argument(
    "-encrypted",
    "--use-https",
    help="Use encrypted (HTTPS) connection",
    action="store_true",
    dest="secure",
)
parser.add_argument(
    "-np",
    "--no-ping",
    help="Do not ping target server (or proxy)",
    action="store_true",
    dest="noping",
)
parser.add_argument("-port", "--port-number", help="WinRM port", type=valid_ports, dest="port")
parser.add_argument("-cmd", "--pos-cmd", help="PowerShell command to run", dest="cmd")
parser.add_argument("-v", "--verbose", help="verbose output", action="store_true", dest="verbose")
parser.add_argument(
    "-cv",
    "--cert_validation",
    help="Certificate Validation",
    choices=["validate", "ignore"],
    default="ignore",
    dest="cv",
)
parser.add_argument(
    "-no",
    "--no-output",
    help="Do not show output of remote command",
    action="store_true",
    dest="noout",
)
parser.add_argument("-pf", "--proxy-format", help="Proxy command output format", dest="pf")
parser.add_argument(
    "-f",
    "--force-cmd",
    help="Force execution of commands which exceed max length",
    action="store_true",
    dest="force",
)
parser.add_argument("-sw", help="Use WSMAN service", action="store_true", dest="service_wsman")
parser.add_argument("-sh", help="Use HOST service", action="store_true", dest="service_host")

args = parser.parse_args()

INPUTS["target"] = args.target if args.target is not None else None
INPUTS["proxy"] = args.proxy if args.proxy is not None else None
INPUTS["user"] = args.user if args.user is not None else None
INPUTS["HTTPS"] = args.secure if args.secure is not None else False
INPUTS["NoPing"] = args.noping if args.noping is not None else False
INPUTS["Port"] = args.port if args.port is not None else False
INPUTS["cmd"] = args.cmd if args.cmd is not None else DEFAULT_CMD
INPUTS["cert_validation"] = args.cv
INPUTS["NoOut"] = args.noout if args.noout is not None else False
INPUTS["format"] = args.pf if args.pf is not None else DEFAULT_PROXY_FORMAT
INPUTS["force"] = args.force if args.force is not None else False
INPUTS["service_wsman"] = args.service_wsman if args.service_wsman is not None else False
INPUTS["service_host"] = args.service_host if args.service_host is not None else False

PASSWORD = args.password if args.password is not None else None
VERBOSE = args.verbose if args.verbose is not None else False


if PASSWORD == "" or PASSWORD is None:
    #
    # Prompt for the password
    #

    if INPUTS["user"] is None:
        sys.exit("**** No username or password was provided\n")

    PASSWORD = getpass.getpass("Provide the password for {0}: ".format(INPUTS["user"]))

    if len(PASSWORD) == 0:
        #
        # Need a password
        #

        sys.exit("**** No password supplied, cannot continue\n")

#
# Main routines
#


def format_error(message, line_len=132):
    """
    Take an input message and format it to be like

    **** line1
         line2
         line3

    :param message:
    :return:
    """

    #
    # Obey the line breaks that are deliberstely inserted
    #

    first_line = True
    check_len = line_len - 5
    out_message = ""

    for line in message.split("\n"):

        if first_line:
            line = "\n**** {0}".format(line)
            first_line = False
        else:
            line = "     {0}".format(line)
        # end if

        #
        # Now we need to split this line up over multiple lines if it is longer than the max allowed
        #

        if len(line) < -check_len:
            out_message += "{0}\n".format(line)
        else:
            #
            # Too big
            #

            new_line = ""

            for word in line.split(" "):

                if len(new_line) + len(word) < check_len:
                    #
                    # OK to add
                    #

                    new_line += "{0} ".format(word)
                else:
                    out_message += "{0}\n".format(new_line)
                    new_line = "     {0} ".format(word)
                # end if

            # next

            if len(new_line) > 5:
                out_message += "{0}\n".format(new_line)
        # end if

    # next

    return "{0}\n".format(out_message)


# format_error


def check_lookups():
    """
    Verify forward and reverse lookup for the target server
    :return:
    """

    return_ok = False
    ip_list = []
    host_list = []

    #
    # see if this is a valid IP address, assume host if not
    #

    try:
        is_ip = socket.inet_aton(INPUTS["lookup"])
        ip_message = "IP Address"
    except Exception:
        is_ip = False
        ip_message = "host name"

        if INPUTS["lookup"].find(".") > -1:
            ip_message = "FQDN"
        # end if

    # end try

    print(
        """
{0}
Checking that both forward and reverse lookup is working for {1} {2}. This is required in order for
WinRM to connect to the remote server
{0}
    """.format(
            SECTION, ip_message, INPUTS["lookup"]
        )
    )

    try:
        if is_ip:
            lookup_host, host_list, ip_list = socket.gethostbyaddr(INPUTS["lookup"])
        else:
            ip_address = socket.gethostbyname(INPUTS["lookup"])
            ip_list.append(ip_address)
            lookup_host = INPUTS["lookup"]
        # end if

        lookup_worked = True
    except Exception as exc:
        print(
            format_error(
                "Failed to perform a lookup for {0}. Make sure that either DNS is correctly configured (including "
                "having a PTR record) or that /etc/hosts has the server entry defined. Error:\n\n{1}".format(
                    INPUTS["lookup"], exc
                )
            )
        )
        lookup_worked = False
    # end try

    if lookup_worked:
        num_hosts = len(host_list)
        num_ip = len(ip_list)
        print('Forward/Reverse lookup has returned host: "{0}"'.format(lookup_host))

        if num_hosts > 0:
            msg = "\n  Addtional hosts found by lookup:"

            for host in host_list:
                msg += "\n    {0}".format(host)
            # next

            print(msg)
        # end if

        if num_ip > 0:
            msg = "\n  IP addresses found by lookup:"

            for ip in ip_list:
                msg += "\n    {0}".format(ip)
            # next

            print(msg)
        # next

        if not is_ip:

            if lookup_host.upper() != INPUTS["lookup"].upper():
                print(
                    format_error(
                        "The target server name is different to the host name returned by the lookup "
                        "which may cause issues with kerberos"
                    )
                )
            # end if

        # end if

        return_ok = True
    # end if

    print("")
    return return_ok, is_ip, ip_list


# check_lookups


def do_ping(ip):
    """
    Perform a ping
    :param ip:
    :return:
    """

    return_ok = False

    #
    # To support running in a container which does not have ping, check to see if ping is available
    #

    p = Popen(["whereis", "ping"], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    stdout, stderr = p.communicate()

    if not stdout:
        print("Running in container without ping utility - ping will be skipped")
        return True
    # end if

    if IS_PY3:

        if str(stdout, encoding="utf-8")[:5] == "ping:":
            print("Running in container without ping utility - ping will be skipped")
            return True
        # end if

    # end if

    print("Checking IP address {0}...".format(ip))

    p = Popen(["ping", "-c", "3", ip], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    stdout, stderr = p.communicate()

    if p.returncode == 0:
        print("Successfully able to communicate with the IP address")
        return_ok = True
    else:
        print(format_error("Unable to reach destination IP address"))

        if len(stderr) > 0:
            msg = stderr
        else:
            msg = stdout
        # end if

        wv("Information returned from ping:\n\n{0}\n".format(msg))
    # end if

    return return_ok


# do_ping


def ping_server(is_ip, ip_list):
    """
    Ping a server - if the server is IP just use that otherwise go through the list of IP
    addresses

    :param is_ip:
    :param ip_list:
    :return:
    """

    return_ok = False

    print(
        """
{0}
Checking connectivity to server {1}.
If there is a firewall preventing ping from being used then this check can be disabled
{0}
        """.format(
            SECTION, INPUTS["lookup"]
        )
    )

    if not is_ip:

        for ip_address in ip_list:
            return_ok = do_ping(ip_address)

            if return_ok:
                #
                # Break at first success
                #

                break
            # end if

        # loop

    else:
        return_ok = do_ping(INPUTS["lookup"])
    # end if

    return return_ok


# ping_server


def refresh_ticket(principal, password, realm):
    """
    Refresh the kerberos ticket using kinit
    :return:
    """

    return_ok = False

    print(
        """
{0}
Obtaining a Kerberos ticket from the Active Directory Domain Controller. This ticket is required in order to grant
access to execute a command remotely on the Windows server.

User: {1}
Domain: {2}
{0}
    """.format(
            SECTION, principal, realm
        )
    )

    cache_file = KRB_TICKET_TEMPLATE.format(realm.upper(), principal.strip())
    wv(
        "Using kerberos cache file: {0}\nFor principal: {1}, realm: {2}".format(
            cache_file, principal, realm
        )
    )

    param = "{0}@{1}".format(principal, realm)
    wv("kerberos command: {0}".format("kinit -c {0} {1}".format(cache_file, param)))

    location = "running kinit"

    try:
        ph = Popen(["kinit", "-c", cache_file, param], stdout=PIPE, stderr=PIPE, stdin=PIPE)

        location = "sending password"

        if IS_PY3:
            _stdout, _stderr = ph.communicate(bytes(password, "utf-8"), timeout=10)
        else:
            _stdout, _stderr = ph.communicate(password)
        # end if

        return_ok = True
    except BasicAuthError as b_err:
        print(
            format_error(
                "Authentication error. Make sure the password is correct for the account {0}. Error:\n\n{1}\n".format(
                    principal, b_err
                )
            )
        )
    except Exception as exc:
        kdc_info = KDC_ENTRY.format(realm, "<Active Directory Domain Controller>")

        print(
            format_error(
                "Error encountered processing kerberos ticket at {0}. The following call failed:\n\n"
                "kinit -c {1} {2}\n\n"
                "The error returned was:\n\n{3}\n".format(location, cache_file, param, exc)
            )
        )
    # end try

    #
    # Check there were no additional problems
    #

    if return_ok:
        rc = ph.returncode

        if rc != 0:
            return_ok = False
            kdc_info = KDC_ENTRY.format(realm.upper(), LEFT_B, "<ADSERVER>", RIGHT_B)

            if _stderr:
                msg = "Failed to update kerberos ticket, return code: {0} with error:\n{1}".format(
                    rc, str(_stderr)
                )
            else:
                msg = "Failed to update kerberos ticket, return code: {0}".format(rc)

            msg += """
\nError encountered processing kerberos ticket. Ensure that the Active Directory information has been added to the
file:\n\n/etc/krb5.conf\n\nIt should appear in a format similar to:\n\n
{0}\n\n
Where <ADSERVER> is the host/FQDN or IP address for a Domain controller in the domain {1}. This section can have
multiple entries for the kdc, matching multiple Domain Controllers. The section [realms] should have one entry per domain
with each entry having at least one defined kdc (Active Directory Domain Controller).
                """.format(
                kdc_info, realm
            )
            print(format_error(msg))
        else:
            #
            # Set the cache file
            #

            wv("Setting kerberos cache file to: {0}".format(cache_file))
            os.environ["KRB5CCNAME"] = cache_file

    return return_ok


# refresh_ticket


def format_from_file(data):
    """
    The inoput from the file will be a list, so turn that into a string. Simple str was not doing it
    :param data:
    :return:
    """

    return_data = ""

    for line in data:
        return_data += "{0}\n".format(line)
    # next

    return return_data


def clean_string(message):
    return message


# clean_string


def build_cmd():
    """
    Build the command to run - it will have an encoded sction, and may be a PSRemote command
    :return:
    """

    #
    # See if the command is actually a file - that we will then read
    #

    do_format = False

    if os.path.isfile(INPUTS["cmd"]):
        wv("Command is a file - reading the file")

        try:
            with open(INPUTS["cmd"], "r") as ps_file:
                my_cmd = format_from_file(ps_file.readlines())
                wv("command read from file:\n{0}\n".format(my_cmd))
            # end with

            do_format = True
        except Exception as exc:
            print(format_error("Failed to read the script file. Error:\n\n{0}\n".format(exc)))
        except BaseException as b_err:
            print(format_error("System error reading input file:\n\n{0}\n".format(b_err)))
        # end try

    else:
        my_cmd = INPUTS["cmd"]
        do_format = True
    # end if

    if do_format:

        if INPUTS["proxy"]:
            proxy_cmd = PYWINRM_PROXY_CMD_WRAPPER % (
                PASSWORD,
                INPUTS["user"],
                INPUTS["target"],
                my_cmd,
                INPUTS["format"],
            )
            wv("proxy command:\n\n{0}".format(proxy_cmd))
            encoded_cmd = base64.b64encode(proxy_cmd.encode("utf-16-le"))

            if IS_PY3:
                encoded_cmd = encoded_cmd.decode("ascii")
            # end if

            actual_cmd = "{0} {1}".format(PS_ENCODED_CMD, encoded_cmd)
        else:
            encoded_cmd = base64.b64encode(my_cmd.encode("utf-16-le"))

            if IS_PY3:
                encoded_cmd = encoded_cmd.decode("ascii")
            # end if

            actual_cmd = "{0} {1}".format(PS_ENCODED_CMD, encoded_cmd)
        # end if

        wv("Command to run:\n\n{0}\n\n".format(actual_cmd))
    # end if

    return actual_cmd


# build_cmd


def run_remote_command(cmd):
    """
    Run the command on the remote server
    :param cmd:
    :return:
    """

    print(
        """
{0}
Using pyWinRM to execute a command remotely on the Windows server over the Kerberos transport. This will require
the target server to be able to authenticate with the domain controller that has issued the Kerberos ticket
{0}
    """.format(
            SECTION
        )
    )
    return_ok = False
    return_output = ""

    winrm_target = INPUTS["proxy"] if INPUTS["proxy"] is not None else INPUTS["target"]
    transport = INPUTS["transport"]
    logon_user = INPUTS["user"]

    if INPUTS["HTTPS"]:
        winrm_url = WSMAN_HTTPS_URL.format(winrm_target, INPUTS["Port"])
        winrm_service = PYWINRM_SERVICE_HTTPS
    else:
        winrm_url = WSMAN_HTTP_URL.format(winrm_target, INPUTS["Port"])
        winrm_service = PYWINRM_SERVICE_HTTP
    # end if

    # Use alternate servicce if specified. Note that if both specified then HOST wins
    if INPUTS["service_wsman"]:
        winrm_service = PYWINRM_SERVICE_WSMAN
    if INPUTS["service_host"]:
        winrm_service = PYWINRM_SERVICE_HOST

    location = "initiating protocol"
    shell_id = None
    cmd_id = None
    stdout = None
    stderr = None
    stderr_raw = None
    stdout_raw = None

    #
    # Check the cmd length
    #

    do_cmd = True
    rc = 0

    if len(cmd) > MAX_WINRM_CMD_LENGTH:
        print(
            "!!!! The command length is {0} which is more than the maximum command length allowed by WinRM".format(
                len(cmd)
            )
        )

        if INPUTS["force"]:
            print(
                '     The command will still be executed as the "force" option was used, but is expected to fail'
            )
        else:
            print("     The command will not be executed")
            do_cmd = False
        # end if
    # end if

    if do_cmd:
        try:
            print("Using WinRM on {0}".format(winrm_url))
            wv(
                "Protocol initiated with:\n"
                "     endpoint: {0}\n"
                "     transport: {1}\n"
                "     username: {2}\n"
                "     password: {3}\n"
                "     server_cert_validation: {4}\n"
                "     service: {5}\n".format(
                    winrm_url,
                    transport,
                    logon_user,
                    "<SET>",
                    INPUTS["cert_validation"],
                    winrm_service,
                )
            )

            p = Protocol(
                endpoint=str(winrm_url),
                transport=str(transport),
                username=str(logon_user),
                password=str(PASSWORD),
                server_cert_validation=str(INPUTS["cert_validation"]),
                service=str(winrm_service),
            )

            start_time = time.time()
            location = "opening shell to remote server"
            shell_id = p.open_shell(codepage=65001)
            end_time = time.time()
            RETURN_TIMES[1] = int(end_time - start_time)

            start_time = time.time()
            location = "executing command on remote server"
            cmd_id = p.run_command(shell_id, cmd)
            end_time = time.time()
            RETURN_TIMES[2] = int(end_time - start_time)

            start_time = time.time()
            location = "reading result"
            stdout_raw, stderr_raw, rc = p.get_command_output(shell_id, cmd_id)
            end_time = time.time()
            RETURN_TIMES[3] = int(end_time - start_time)
            return_ok = True
        except WinRMTransportError as err:
            print(
                format_error(
                    "Transport error in connection. WinRM was unable to connect to the server. Error:\n\n{0}\n".format(
                        err
                    )
                )
            )
        except BasicAuthError as err:
            print(
                format_error(
                    "Authentication error when {0}. WinRM was unable to connect to the server. Error:\n\n{1}\n".format(
                        location, err
                    )
                )
            )
        except Exception as err:
            print(
                format_error(
                    "Error executing command when {0}. An error at this stage means that the username and password "
                    "was successfully used to obtain a kerberos ticket, so check that the user has access rights on "
                    "the Windows server and that the documentation for configuring Windows servers for remote monitoring "
                    "has been followed. Error:\n\n{1}\n".format(location, err)
                )
            )
        finally:
            location = "cleaning up"

            if shell_id:
                p.cleanup_command(shell_id, cmd_id)
                p.close_shell(shell_id)
            # end if

        # end try

        #
        # out/err format different between Python 3 and 2 ...
        #

        if rc is not None:
            wv("Command return code: {0}".format(rc))

        if stdout_raw is not None:

            if IS_PY3:
                stdout = str(stdout_raw, encoding="utf-8")
            else:
                stdout = stdout_raw
            # end if

            wv("Command output:\n\n{0}\n".format(stdout))

        if stderr_raw is not None:

            if IS_PY3:
                stderr = str(stderr_raw, encoding="utf-8")
            else:
                stderr = stderr_raw
            # end if

            is_error, stderr = _parse_cli_xml_error(stderr)

            if not is_error:
                stderr = ""

        if return_ok:
            #
            # Check the status code
            #

            if rc != 0 or (len(stdout.strip()) == 0 and len(stderr) > 0):
                print(
                    format_error(
                        "Error returned from remote command (the command was executed but returned a failure):\n\n{0}".format(
                            stderr
                        )
                    )
                )
                return_ok = False
            else:
                return_output = clean_string(stdout)
            # end if

        # end if

    # end if

    return return_ok, return_output


# run_remote_command


def main():
    """
    Main routine
    :return:
    """

    lookup_ok, is_ip, ip_list = check_lookups()

    if not lookup_ok:
        print(
            format_error(
                "Forward and reverse looukup has failed. No further tests will take place. Ensure that DNS "
                'or /etc/hosts file is correctly configured and in the case of DNS, the server "{0}" has both '
                "A and PTR records defined".format(INPUTS["lookup"])
            )
        )
        return
    # end if

    #
    # Ping the server
    #

    if not INPUTS["NoPing"]:
        ok = ping_server(is_ip, ip_list)

        if not ok:
            print(
                format_error(
                    "Unable to communicate with the target server, further checks will not be made"
                )
            )
            return
        # end if

    # end if

    #
    # Get a kerberos ticket
    #

    if INPUTS["transport"] == PYWINRM_TRANSPORT_KRB:
        ok = refresh_ticket(INPUTS["principal"], PASSWORD, INPUTS["realm"])
    else:
        print("Using basic authentication")
        ok = True

    if not ok:
        print(
            format_error(
                "An error was encountered with the Kerberos ticket, further checks will not be made"
            )
        )
        return
    # end if

    if INPUTS["transport"] == PYWINRM_TRANSPORT_KRB:
        print("Kerberos ticket succesfully issued for user {0}".format(INPUTS["user"]))

    remote_cmd = build_cmd()
    ok, strdout = run_remote_command(remote_cmd)

    remote_system = INPUTS["proxy"] if INPUTS["proxy"] is not None else INPUTS["target"]

    if ok:
        print(
            'The command was succesfully executed on the remote system "{0}"'.format(remote_system)
        )

        if not INPUTS["NoOut"]:
            print("The output from the command was:\n\n{0}".format(strdout))
        # end if

        if RETURN_TIMES:
            sorted_times = dict(sorted(RETURN_TIMES.items()))
            for action in sorted_times:
                print(
                    "Action: {}, elapsed time: {} seconds".format(
                        ACTION_INFO[action],
                        sorted_times[action]
                    )
                )
            print("")
    else:
        print(
            format_error(
                "Kerberos authentication was successful, but the remote command execution on the server failed when using "
                "the Kerberos transport via WinRM"
            )
        )
    # end if


# main

#
# Start here
#


if validate_inputs():
    if __name__ == "__main__":
        main()
