##Function to execute a single one Ping
function SendPing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )

    Try{
        $res = Test-Connection -ComputerName $Hostname -Count 1 -ErrorAction SilentlyContinue
        if($res.StatusCode -eq 0){
            #Write-Host "$Hostname is reachable." -ForegroundColor Green
            return $true
        }else{
            #Write-Host "$Hostname is unreachable." -ForegroundColor Red
            return $false
        }
    }Catch{
        #Write-Host "$Hostname is unreachable." -ForegroundColor Red
        return $false
    }
}


function CalculateNetwork{
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetIP
    )

    if($NetIP -match ".*/[0-9]+$"){
        [int] $cidr = ($NetIP -split "/")[1]
        $IP = ($NetIP -split "/")[0]
        if ($IP -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"){
            ##Verifying the CIDR is between 7 and 30
            if($cidr -ge 7 -and $cidr -le 30){
                $BinaryIP = @() 
                ##Divide IP in octects
                $octects = $IP -split "\."
                foreach($octect in $octects){
                    ##Convert octect in a bit sequence string
                    $binary = [convert]::ToString($octect,2)
                    ##Create byte rapresentation
                    $oct_binary = '0'* (8 - $binary.Length) + $binary

                    $BinaryIP = $BinaryIP + $oct_binary
                }
                ##Create the binary sequence of the entire IP
                $BinaryIP = $BinaryIP -join ''
                
                ##Number of bit for hosts part and Ids part for Network and Hosts
                $host_len = 32 - $cidr
                $NetworkID = $BinaryIP.Substring(0,$cidr)

                $HostID = $BinaryIP.Substring($cidr,$host_len)
                $HostID = $HostID -replace '1','0'

                #Max number of configurable IPs
                $max_ips = [convert]::ToInt32(('1'* $host_len),2) -1
                $IPs = @()

                For ($i = 1; $i -le $max_ips; $i++){
                    $HostIDdecimal = ([convert]::ToInt32($HostID, 2) + $i )
                    $HostIDbinary = [convert]::ToString($HostIDdecimal, 2)

                    $NoOfZerosToAdd = $HostID.Length - $HostIDbinary.Length
                    $HostIDbinary = ('0' * $NoOfZerosToAdd) + $HostIDbinary

                    $NextIPbinary = $NetworkID + $HostIDbinary

                    $IP = @()
                    #Transform each Octect
                    For ($x = 1; $x -le 4; $x++){
                        $StartCharNumber = ($x-1) * 8
                        $IPoctectBinary = $NextIPbinary.Substring($StartCharNumber, 8)
                        $IPoctectDecimal = [convert]::ToInt32($IPoctectBinary, 2)
                        
                        $IP += $IPoctectDecimal
                    }
                    $IP = $IP -join '.'
                    $IPs += $IP
                    
                }
                return $IPs
                #Write-Output -InputObject $Ips    
            }else{
                Write-Error "The value of CIDR is not correct" -ErrorAction Stop
            }
        }else{
            Write-Error "The IP is not valid." -ErrorAction Stop
        }
    }else{
        Write-Error "The $NetIP is not a network address" -ErrorAction Stop
    }
}

function CheckPortsValidity{
    param(
        [Parameter(Mandatory=$true)]
        [string]$p
    )
    $Ports = @()
    #If is a port range
    if($p -match "[0-9]+\.\.[0-9]+"){
        [int[]]$Range = $p -split "\.\."
        if($Range[0] -ge $Range[1] -or $Range[0] -le 0 -or $Range[1] -le 0 -or $Range[1] -gt 65535){
            Write-Error "Port range is not valid." -ErrorAction Stop
        }
        $Ports = (Invoke-Expression $p)
    }
    #If is a set of ports or single port number
    elseif($p -match "^(?:[0-9]+,*)+$"){
        $r = Invoke-Expression $p
        if($r.GetType().Name -eq "Int32"){
            if([int]$p -ge 0 -and [int]$p -lt 65536){
                $Ports += [int]$p
            }else{
                Write-Error "Port number is not valid." -ErrorAction Stop
            }
        }else{
            ForEach($port in $r){
                if((Invoke-Expression $port) -is [int] -and [int]$port -ge 0 -and [int]$port -lt 65536){
                    $Ports += [int]$port
                }else{
                    Write-Error "Some port number in the set is not valid." -ErrorAction Stop
                }
            }
        }
    }
    else{
        Write-Error "Is either not a valid port number or set." -ErrorAction Stop
    }
    return $Ports
}

function Scan{
    param(
        [Parameter(Mandatory=$true)]
        [string]$h,
        [Parameter(Mandatory=$true)]
        [object]$ps
    )
    $res = @()
    ForEach ($p in $ps){
        $port_res = @{}
        $port_res["Port"] = $p
        
        try{
            $socket = New-Object System.Net.Sockets.TcpClient($h,$p)
            if($socket.Connected){           
                $port_res["Status"] = "Open"
                $socket.Close()
            }else{
                $port_res["Satus"] = "Closed"
            }
            $res += $port_res
        }catch{
            $port_res["Status"] = "Closed"
            $res += $port_res
        }
    }
    return $res
}

function PortScanner{
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Hosts,
        
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Ports,
        
        [System.Management.Automation.SwitchParameter]$Pn,

        [System.Management.Automation.SwitchParameter]$n
    )
    begin{
        $Hrange = @()
        $dPorts = @()
        Write-Host "Scan started at: " (Get-Date)
        
        #If Hosts is an IP address
        if ($Hosts -match "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"){
            #If a network address
            if ($Hosts -match ".*/[0-9]+$"){
                $Hrange = CalculateNetwork -NetIP $Hosts
            #If Hosts is a single IP 
            }else{
                $Hrange += $Hosts
            }
        }
        #If Hosts is a hostname
        else{
            $Hrange += $Hosts
        }
        #If no hosts to scan
        if($Hrange.Length -eq 0){
            Write-Error "No available hosts to scan." -ErrorAction Stop
        }

        #Check Port values
        $dPorts = CheckPortsValidity -p $Ports
        if($dPorts.Length -eq 0){
            Write-Error "No available ports to scan." -ErrorAction Stop
        }
    }
    process{
        #$ScanResult = New-Object PSObject
        #Start Scan
        ForEach($target in $Hrange){
            $ObjTarget = New-Object PSObject
            #If DNS resolution
            if(-not $n){
                Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name Hostname -Value (Resolve-DnsName -Name $target -Type A).IPAddress 
            }else{
                Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name Hostname -Value $target
            }
            #If Ping option
            if(-not $Pn){
                #If host is reachable
                if((SendPing -Hostname $target)){
                    Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name Ping -Value "Reachable"
                    ##Scan Host
                    $scan = Scan -h $target -ps $dPorts 
                    Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name ScanResult -Value [PSObject]$scan
                }else{
                    Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name Ping -Value "Reachable"
                }
            }
            #No Ping options
            else{
                Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name Ping -Value "Not Requested"
                ##Scan Host
                $scan = Scan -h $target -ps dPorts
                Add-Member -InputObject $ObjTarget -MemberType NoteProperty -Name ScanResult -Value [PSObject]$scan
            }
            $ObjTarget.ScanResult.Port | Format-Table
        }
    }
    end{
        #$ScanResult | Format-Table
        Write-Host "Script execution is terminated at: " (Get-Date)
    }
}
PortScanner -Hosts "google.com" -Ports "80,22" -Pn 