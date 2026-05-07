rule insecure_service_telnet
{
  meta:
    description = "Detect telnet or legacy cleartext shell strings"
    score = 3
  strings:
    $telnet = /\btelnetd\b/i
    $telnet2 = /\btelnet\b/i
    $telnet_conf = /telnet\.enable/i
  condition:
    any of them
}

rule hardcoded_credentials_or_tokens
{
  meta:
    description = "Detect likely hardcoded credentials or provisioning tokens"
    score = 4
  strings:
    $root = /\broot:/i
    $passwd = /password[\s:=]/i
    $token = /\bPROVISION\b/i
    $factory = /\bFACTORY\b/i
    $hardcoded = /\bHARDCODED\b/i
  condition:
    any of them
}

rule debug_and_jtag_indicators
{
  meta:
    description = "Detect debug interfaces mentions or jtag/uarts"
    score = 2
  strings:
    $jtag = /\bJTAG\b/i
    $uart = /\bUART\b/i
    $debug = /\bDEBUG\b/i
    $u_boot = /U-?Boot/i
  condition:
    any of them
}

rule private_key_pem
{
  meta:
    description = "Detect PEM-encoded private keys"
    score = 8
  strings:
    $rsa = "-----BEGIN RSA PRIVATE KEY-----"
    $pk = "-----BEGIN PRIVATE KEY-----"
  condition:
    any of them
}

rule jaguar_attack_indicators
{
  meta:
    description = "Heuristic indicators related to provisioning/firmware attacks; defensive only"
    score = 1
  strings:
    $prov = /JAGUAR_PROVISION/i
    $token = /PROVISION_TOKEN/i
    $serial = /SERIAL_NUMBER[\s:=]/i
  condition:
    any of them
}
