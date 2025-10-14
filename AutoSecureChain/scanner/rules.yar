rule insecure_service_telnet
{
  meta:
    description = "Detect telnet or legacy cleartext shell strings"
  strings:
    $telnet = "telnetd"
    $telnet2 = "TELNET"
    $telnet_conf = "telnet.enable"
  condition:
    any of them
}

rule hardcoded_credentials_or_tokens
{
  meta:
    description = "Detect likely hardcoded credentials or provisioning tokens"
  strings:
    $root = "root:"
    $passwd = "password="
    $token = "PROVISION"
    $factory = "FACTORY"
    $hardcoded = "HARDCODED"
  condition:
    any of them
}

rule debug_and_jtag_indicators
{
  meta:
    description = "Detect debug interfaces mentions or jtag/uarts"
  strings:
    $jtag = "JTAG"
    $uart = "UART"
    $debug = "DEBUG"
    $u_boot = "U-Boot"
  condition:
    any of them
}

rule private_key_pem
{
  meta:
    description = "Detect PEM-encoded private keys"
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
  strings:
    $prov = "JAGUAR_PROVISION"
    $token = "PROVISION_TOKEN"
    $serial = "SERIAL_NUMBER="
  condition:
    any of them
}
