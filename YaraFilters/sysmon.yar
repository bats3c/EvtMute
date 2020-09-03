rule Block_All_Sysmon_Events {
    meta:
        author = "@_batsec_"
        description = "Prevent all sysmon events from being reported"
    strings:
        $provider = "Microsoft-Windows-Sysmon"
    condition:
        $provider
}