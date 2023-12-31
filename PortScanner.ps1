<#
.SYNOPSIS
    Powershell TCP Port Scanner.

.DESCRIPTION
    This script performs TCP port scans, providing the option to specify an entire network.

.PARAMETER Hosts
    A hostname, an IPv4 address, or a network to be scanned.

.PARAMETER Ports
    A TCP port, a range of ports in the form x..x, or a series of ports separated by commas.

.PARAMETER Pn
    Optional. Disable ping for host verification before scanning.
	
.PARAMETER n
    Optional. Disable dns lookup.
	
.EXAMPLE
    TCP Scan providing a hostname with DSN Lookup and Ping validation.
    .\PortScanner.ps1 -Hosts google.com -Ports 80,443

.EXAMPLE
    TCP Scan providing an IPv4 address with no DSN Lookup.
	.\PortScanner.ps1 -Hosts 192.168.88.10 -n -Ports 80

.EXAMPLE
    TCP Scan providing a network address disabling both DNS lookup and ping verification..
	.\PortScanner.ps1 -Hosts 192.168.88.0/24 -n -Pn -Ports 20..8080
	
.NOTES
    Autore: Giuseppe Argento
    Versione: 1.0
    Data: 28/11/2023
#>

param(
	[CmdletBinding()]
	[Parameter(Mandatory=$true, Position=0)]
	[string]$Hosts,
	
	[Parameter(Mandatory=$true, Position=1)]
	[string]$Ports,
	
	[System.Management.Automation.SwitchParameter]$Pn,

	[System.Management.Automation.SwitchParameter]$n

)

function CheckResourceFile {
    $PortList_Path = "$PSScriptRoot\Resources\service-names-port-numbers.csv"

    If(-not(Test-Path -Path $PortList_Path)){
        Write-Error "Missing service-names-port-numbers.csv file." -ErrorAction Stop
    }

    $PortServices = @{}
    ForEach($line in Get-Content -Path $PortList_Path) {
        If(-not [string]::IsNullOrEmpty($line)){
            Try{
                $data = $line -split ","
        
                If ($data[2] -eq "tcp"){
                    If([string]::IsNullOrEmpty($data[0])){
                        $data[0] = "-"
                    }
                    $PortServices.Add([int]$data[1], $data[0])
                }
            }Catch [System.ArgumentException]{}
        }
    }
    return $PortServices

}

function SendPing {
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
        [object]$ps,
        [Parameter(Mandatory=$true)]
        [object]$PortList,
        [System.Management.Automation.SwitchParameter]$Open
    )
    $res = @()
    $i = 1

    ForEach ($p in $ps){
        $port_res = @{}
        $port_res["Port"] = $p

        If($PortList.Get_Item($p)){
            $port_res["Service"] = $PortList.Get_Item($p)
        }else{
            $port_res["Service"] = "Unkwnown"
        }

        
        try{
            $socket = New-Object System.Net.Sockets.TcpClient
            $connect = $socket.BeginConnect($h,$p, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne(100, $false)
            
            if(-not $wait){
                $port_res["Status"] = "Closed"
            }else{
                $port_res["Status"] = "Open"
            }
            $res += $port_res
        }catch{
            $port_res["Status"] = "Closed"
            $res += $port_res
        }

        #$percentage = ($i / $ps.Length) * 100
        #Write-Progress -Id 2 -Activity "Scanning ports..." -Status "Port: $p" -PercentComplete $percentage
        $i += 1
    }
    return $res
}

function Printer{
    param(
        [Parameter(Mandatory=$true)]
        [object]$Scan
    )

    ForEach ($target in $Scan){
        Write-Host "Scan results for "$target["Hostname"]
        Write-Host "Ping results: "$target["Ping"]
        $target["ScanResult"] | ForEach{[PSCustomObject]$_} | Format-Table -AutoSize
    }
}



$Hrange = @()
$dPorts = @()

$PortList = CheckResourceFile

$t1 = Get-Date
Write-Host "Scan started at: $t1"
Write-Host "----------------------------------------------"

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

$Result = @()
$i = 1

#Start Scan
ForEach($target in $Hrange){
	$ObjTarget = @{}
	#If DNS resolution
	if(-not $n){
		$ObjTarget["Hostname"] = (Resolve-DnsName -Name $target -Type A).IPAddress 
	}else{
		$ObjTarget["Hostname"] = $target
	}
	#If Ping option
	if(-not $Pn){
		#If host is reachable
		if((SendPing -Hostname $target)){
			$ObjTarget["Ping"] = "Reachable"
			##Scan Host
			$ObjTarget["ScanResult"] = Scan -h $target -ps $dPorts -PortList $PortList
		}else{
			$ObjTarget["Ping"] = "Unreachable"
		}
	}
	#No Ping options
	else{
		$ObjTarget["Ping"] = "Not Requested"
		##Scan Host
		$ObjTarget["ScanResult"] = Scan -h $target -ps $dPorts -PortList $PortList
	}
	$percentage = ($i / $Hrange.Length) * 100
	Write-Progress -Id 1 -Activity "Scanning Host" -Status "Current host: $target" -PercentComplete $percentage
	
	$Result += $ObjTarget
	$i += 1
}

Printer -Scan $Result

Write-Host "----------------------------------------------"
$t2 = Get-Date
$elapsed = ($t2-$t1).totalseconds
Write-Host "Script execution is terminated at: $t2"
Write-Host "Elapsed: " $elapsed

#PortScanner -Hosts "192.168.1.0/24" -Ports "22,80,443,445" -Pn -n
