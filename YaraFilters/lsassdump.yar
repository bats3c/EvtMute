rule Block_Lsass_Dump {
    meta:
        author = "@_batsec_"
        description = "Prevent lsass dumping being reported by sysmon"
    strings:
        $provider = "Microsoft-Windows-Sysmon"
        $image = "lsass.exe" nocase
        $access = "GrantedAccess"
        $type = "0x1fffff"
    condition:
        all of them
}