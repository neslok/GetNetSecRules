Try {
    ((Invoke-WebRequest -Uri "https://10.42.16.39:9440/api/nutanix/v3/network_security_rule/list").Content | ConvertFrom-Json).headers
}
catch {
    $e = $_.Exception
    $msg = $e.Message
    $depth = ">"
    while ($e.InnerException) {
        $e = $e.InnerException
        $msg += "`n$depth $($e.Message)" 
        $depth += ">"
    }
    $msg
}