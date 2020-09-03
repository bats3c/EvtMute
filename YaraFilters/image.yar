rule Block_Image {
    meta:
        author = "@_batsec_"
        description = "Prevent an image from appering in any event logs"
    strings:
        $imagename = "hideme.exe"
    condition:
        $imagename
}