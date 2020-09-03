rule Block_Logon {
    meta:
        author = "@_batsec_"
        description = "Prevent a users logon being reported"
    strings:
        $provider = "Microsoft-Windows-Security-Auditing"
        $username = "backdoor"
        $logon1 = "LogonType"
        $logon2 = "TargetLogonId"
    condition:
        $provider and $username and $logon*
}