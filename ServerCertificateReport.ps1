<#
.SYNOPSIS
Generate various realtime reports of certificates installed on servers within an Active Directory domain.

.DESCRIPTION
The idea behind this script is to allow system administrators to generate a health check of their respective Active Directory domains so they can clean up their PKI environment as needed.
This script contains three main functions. 
The Get-All-ServerCertificates function generates a complete report of all certificates installed within the computer account's personal certificate directory.
The Get-Expiring-ServerCertificates function generates a complete a report of expiring certificates installed within the computer account's personal certificate directory.
The Get-Expired-ServerCertificates function generates a complete report of expired certificates installed within the computer account's personal certificate directory.

By default, computers included in the report are those within Active Directory and have "server" within their OperatingSystem property.

For email reports, please adjust the email information within this script to suit your environment

.PARAMETER ReportType
[REQUIRED] This determines which type of certificate report is ran. Options are: All, Expiring, or Expired

.PARAMTER MailReport
[OPTIONAL] If used, this parameter will email the respective report using the email information embedded within this script

.NOTES
Author: 		Bryce Haviland
Last Modified:	04/27/2016
#>
[CmdletBinding()]
Param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet('All', 'Expiring', 'Expired')]
    [String]$ReportType,

    [Parameter(Position=1)]
    [Switch]$MailReport = $true
)
function Get-All-ServerCertificates()
{
	$csvResults = @()
    #Variable for storing a list of server connection errors
    $connFails = ""
    #Variables for storing expiring certificate information
    #$data1 stores expiring certificate information for the first timing window.
    $data = ""
    $mailMessage = ""
    Import-Module ActiveDirectory
	$servers = Get-ADComputer -Filter {operatingsystem -like "*server*"} -Property *
	foreach($server in $servers)
	{
		Try
		{
			$store=New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$($server.Name)\My","LocalMachine")
			$store.Open("ReadOnly")
			foreach($cert in $store.Certificates)
			{
                $DaysToExpire = ($($cert.NotAfter)-(date))
				$certObject = New-Object System.Object
    			$certObject | Add-Member -type NoteProperty -name ServerName -value "$($server.Name)"
			    $certObject | Add-Member -type NoteProperty -name ServerIP -value "$($server.IPv4Address)"
				$certObject | Add-Member -type NoteProperty -name ValidCert -value "$($cert.Verify())"
				$certObject | Add-Member -type NoteProperty -name CertSubjectName -value "$($cert.Subject)"
				$certObject | Add-Member -type NoteProperty -name CertFriendlyName -value "$($cert.FriendlyName)"
				$certObject | Add-Member -type NoteProperty -name CertUsageList -value "$($cert.EnhancedKeyUsageList)"
				$certObject | Add-Member -type NoteProperty -name CertThumbprint -value "$($cert.Thumbprint)"
				$certObject | Add-Member -type NoteProperty -name CertIssuer -value "$($cert.Issuer)"
				$certObject | Add-Member -type NoteProperty -name CertIssueDate -value "$($cert.NotBefore)"
				$certObject | Add-Member -type NoteProperty -name CertExpireDate -value "$($cert.NotAfter)"
				$certObject | Add-Member -type NoteProperty -name CertDaysUntilExpire -value "$($DaysToExpire.Days)"
				$csvResults += $certObject
    			$data += "---------------------------------------------------`n"
                $data += "Server Name: $($server.Name)`n"
                $data += "Server IP: $($server.IPv4Address)`n"
				if ($($cert.Verify()) -eq 1)
				    {
					    $data += "[Y]Certificate is valid`n"
				    }
				    else
				    {
					    $data += "[X]Certificate is not valid`n"
				    }
				$data += "Certificate Subject Name   : $($cert.Subject)`n"
				$data += "Certificate Friendly Name  : $($cert.FriendlyName)`n"
				$data += "Certificate Usage List     : $($cert.EnhancedKeyUsageList)`n"
				$data += "Certificate Thumbprint     : $($cert.Thumbprint)`n"
				$data += "Certificate issued by      : $($cert.Issuer)`n"
				$data += "Certificate Issue Date     : $($cert.NotBefore)`n"
				$data += "Certificate Expiration Date: $($cert.NotAfter)`n"
				$data += "Days until expiration      : $($DaysToExpire.Days)`n"
			}
			$store.close()
		}
		Catch
		{
			$connFails += "[*]There was an issue either connecting to $($server.Name) or retrieving certificate information`n"
		}
	}
    
    if($data -eq "")
    {
        $mailMessage += "[*]This script found no expiring certificates within the personal stores of the servers`n"
    }
    else
    {
        $mailMessage += "===================================================`n"
        $mailMessage += "[*]Complete Certificate Report`n"
        $mailMessage += "===================================================`n"
        $mailMessage += "$($data)"
        $mailMessage += "===================================================`n"

    }
    $mailMessage += "[*]Information Retreival Errors`n"
    $mailMessage += "[*]These might be worth manually checking...`n"
    $mailMessage += "===================================================`n"
    $mailMessage += "$($connFails)"
    $mailMessage += "===================================================`n"
    if($MailReport -eq $false)
    {
        Write-Host "$mailMessage"
    }
    else
    {
        New-Item -Path "$($tmpPath)" -Type directory | Out-Null
	    $csvResults | Export-Csv -Path ($tmpPath + $csvFile)
        $smtp = new-object Net.mail.SmtpClient($smtpserver)
	    $smtpDetails = New-Object System.Net.Mail.MailMessage
	    $attach = New-Object Net.Mail.Attachment($tmpPath + $csvFile)
	    $smtpDetails.From = $emailFrom
	    $smtpDetails.To.Add($emailTo)
	    $smtpDetails.Subject = $subject
	    $smtpDetails.body = $mailMessage
	    $smtpDetails.Attachments.Add($attach)
        $smtp.Send($smtpDetails)
	    $attach.Dispose()
	    $smtpDetails.Dispose()
	    Remove-Item ($tmpPath + $csvFile)
        Remove-Item -Path $tmpPath
    }
}
function Get-Expiring-ServerCertificates()
{
	$csvResults = @()
    #Variable for storing a list of server connection errors
    $connFails = ""
    #The $time1,2,3 variables are used for timing windows. These should be integer values
    #$time1 is the earilest you would want to know about a certificate (e.g., 180). This should be the greatest number
    $time1 = 180
    #$time2 is the starting point of another time window (e.g., 90). This should be less than $time1 and greater than $time3
    $time2 = 90
    #$time3 is the starting point of another time window (e.g., 30). This would be the least of the time variables.
    $time3 = 30
    #Variables for storing expiring certificate information
    #$data1 stores expiring certificate information for the first timing window.
    #For example, certificates expiring between 180 to 90 days
    $data1 = ""
    #data2 stores expiring certificate information for the second timing window.
    #For example, 90 to 30 days
    $data2 = ""
    #data3 stores expiring certificate information for the third timing window.
    #For example, 30 to 0 days
    $data3 = ""
    #Variable for email reporting format
    $mailMessage = ""
    Import-Module ActiveDirectory
	$servers = Get-ADComputer -Filter {operatingsystem -like "*server*"} -Property *
	foreach($server in $servers)
	{
		Try
		{
			$store=New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$($server.Name)\My","LocalMachine")
			$store.Open("ReadOnly")
			foreach($cert in $store.Certificates)
			{
                $DaysToExpire = ($($cert.NotAfter)-(date))
				if($($DaysToExpire.Days) -lt $($time1) -and ($($DaysToExpire.Days) -gt 0))
                {
				    $certObject = New-Object System.Object
    				$certObject | Add-Member -type NoteProperty -name ServerName -value "$($server.Name)"
				    $certObject | Add-Member -type NoteProperty -name ServerIP -value "$($server.IPv4Address)"
				    $certObject | Add-Member -type NoteProperty -name ValidCert -value "$($cert.Verify())"
				    $certObject | Add-Member -type NoteProperty -name CertSubjectName -value "$($cert.Subject)"
				    $certObject | Add-Member -type NoteProperty -name CertFriendlyName -value "$($cert.FriendlyName)"
				    $certObject | Add-Member -type NoteProperty -name CertUsageList -value "$($cert.EnhancedKeyUsageList)"
				    $certObject | Add-Member -type NoteProperty -name CertThumbprint -value "$($cert.Thumbprint)"
				    $certObject | Add-Member -type NoteProperty -name CertIssuer -value "$($cert.Issuer)"
				    $certObject | Add-Member -type NoteProperty -name CertIssueDate -value "$($cert.NotBefore)"
				    $certObject | Add-Member -type NoteProperty -name CertExpireDate -value "$($cert.NotAfter)"
				    $certObject | Add-Member -type NoteProperty -name CertDaysUntilExpire -value "$($DaysToExpire.Days)"
				    $csvResults += $certObject
				    If(($($DaysToExpire.Days) -gt 0) -and ($($DaysToExpire.Days) -lt $($time3)))
					{
					    $data3 += "---------------------------------------------------`n"
                        $data3 += "Server Name: $($server.Name)`n"
                        $data3 += "Server IP: $($server.IPv4Address)`n"
					    if ($($cert.Verify()) -eq 1)
					    {
						    $data3 += "[Y]Certificate is valid`n"
					    }
					    else
					    {
						    $data3 += "[X]Certificate is not valid`n"
					    }
					    $data3 += "Certificate Subject Name   : $($cert.Subject)`n"
					    $data3 += "Certificate Friendly Name  : $($cert.FriendlyName)`n"
					    $data3 += "Certificate Usage List     : $($cert.EnhancedKeyUsageList)`n"
					    $data3 += "Certificate Thumbprint     : $($cert.Thumbprint)`n"
					    $data3 += "Certificate issued by      : $($cert.Issuer)`n"
					    $data3 += "Certificate Issue Date     : $($cert.NotBefore)`n"
					    $data3 += "Certificate Expiration Date: $($cert.NotAfter)`n"
						$data3 += "Days until expiration      : $($DaysToExpire.Days)`n"
					}
					ElseIf(($($DaysToExpire.Days) -gt $($time3)) -and ($($DaysToExpire.Days) -lt $($time2)))
					{
					    $data2 += "---------------------------------------------------`n"
                        $data2 += "Server Name: $($server.Name)`n"
                        $data2 += "Server IP: $($server.IPv4Address)`n"
					    if ($($cert.Verify()) -eq 1)
					    {
						    $data2 += "[Y]Certificate is valid`n"
					    }
					    else
					    {
						    $data2 += "[X]Certificate is not valid`n"
					    }
					    $data2 += "Certificate Friendly Name  : $($cert.FriendlyName)`n"
					    $data2 += "Certificate Usage List     : $($cert.EnhancedKeyUsageList)`n"
					    $data2 += "Certificate Thumbprint     : $($cert.Thumbprint)`n"
					    $data2 += "Certificate issued by      : $($cert.Issuer)`n"
					    $data2 += "Certificate Issue Date     : $($cert.NotBefore)`n"
					    $data2 += "Certificate Expiration Date: $($cert.NotAfter)`n"
						$data2 += "Days until expiration      : $($DaysToExpire.Days)`n"
					}
					ElseIf(($($DaysToExpire.Days) -gt $($time2)))
					{
					    $data1 += "---------------------------------------------------`n"
                        $data1 += "Server Name: $($server.Name)`n"
                        $data1 += "Server IP: $($server.IPv4Address)`n"
					    if ($($cert.Verify()) -eq 1)
					    {
						    $data1 += "[Y]Certificate is valid`n"
					    }
					    else
					    {
						    $data1 += "[X]Certificate is not valid`n"
					    }
					    $data1 += "Certificate Subject Name   : $($cert.Subject)`n"
					    $data1 += "Certificate Friendly Name  : $($cert.FriendlyName)`n"
					    $data1 += "Certificate Usage List     : $($cert.EnhancedKeyUsageList)`n"
					    $data1 += "Certificate Thumbprint     : $($cert.Thumbprint)`n"
					    $data1 += "Certificate issued by      : $($cert.Issuer)`n"
					    $data1 += "Certificate Issue Date     : $($cert.NotBefore)`n"
					    $data1 += "Certificate Expiration Date: $($cert.NotAfter)`n"
						$data1 += "Days until expiration      : $($DaysToExpire.Days)`n"
					}
				}
			}
			$store.close()
		}
		Catch
		{
			$connFails += "[*]There was an issue either connecting to $($server.Name) or retrieving certificate information`n"
		}
	}
    
    if(($($data1) -eq "") -and ($($data2) -eq "") -and ($($data3) -eq ""))
    {
        $mailMessage += "[*]This script found no expiring certificates within the personal stores of the servers`n"
    }
    else
    {
        $mailMessage += "===================================================`n"
        $mailMessage += "[*]Certificates that expire within $($time3) days`n"
        $mailMessage += "===================================================`n"
        $mailMessage += "$($data3)"
        $mailMessage += "===================================================`n"
        $mailMessage += "[*]Certificates that expire within $($time2) days`n"
        $mailMessage += "===================================================`n"
        $mailMessage += "$($data2)"
        $mailMessage += "===================================================`n"
        $mailMessage += "[*]Certificates that expire within $($time1) days`n"
        $mailMessage += "===================================================`n"
        $mailMessage += "$($data1)"
        $mailMessage += "===================================================`n"
    }
    $mailMessage += "[*]Information Retreival Errors`n"
    $mailMessage += "[*]These might be worth manually checking...`n"
    $mailMessage += "===================================================`n"
    $mailMessage += "$($connFails)"
    $mailMessage += "===================================================`n"
    if($MailReport -eq $false)
    {
        Write-Host "$mailMessage"
    }
    else
    {
        New-Item -Path "$($tmpPath)" -Type directory | Out-Null
	    $csvResults | Export-Csv -Path ($tmpPath + $csvFile)
        $smtp = new-object Net.mail.SmtpClient($smtpserver)
	    $smtpDetails = New-Object System.Net.Mail.MailMessage
	    $attach = New-Object Net.Mail.Attachment($tmpPath + $csvFile)
	    $smtpDetails.From = $emailFrom
	    $smtpDetails.To.Add($emailTo)
	    $smtpDetails.Subject = $subject
	    $smtpDetails.body = $mailMessage
	    $smtpDetails.Attachments.Add($attach)
        $smtp.Send($smtpDetails)
	    $attach.Dispose()
	    $smtpDetails.Dispose()
	    Remove-Item ($tmpPath + $csvFile)
        Remove-Item -Path $tmpPath
    }
}
function Get-Expired-ServerCertificates()
{
	$csvResults = @()
    #Variable for storing a list of server connection errors
    $connFails = ""
    $data = ""
    $mailMessage = ""
    Import-Module ActiveDirectory
	$servers = Get-ADComputer -Filter {operatingsystem -like "*server*"} -Property *
	foreach($server in $servers)
	{
		Try
		{
			$store=New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$($server.Name)\My","LocalMachine")
			$store.Open("ReadOnly")
			foreach($cert in $store.Certificates)
			{
                $DaysToExpire = ($($cert.NotAfter)-(date))
				if($($DaysToExpire.Days) -lt 0)
                {
				    $certObject = New-Object System.Object
    				$certObject | Add-Member -type NoteProperty -name ServerName -value "$($server.Name)"
				    $certObject | Add-Member -type NoteProperty -name ServerIP -value "$($server.IPv4Address)"
				    $certObject | Add-Member -type NoteProperty -name ValidCert -value "$($cert.Verify())"
				    $certObject | Add-Member -type NoteProperty -name CertSubjectName -value "$($cert.Subject)"
				    $certObject | Add-Member -type NoteProperty -name CertFriendlyName -value "$($cert.FriendlyName)"
				    $certObject | Add-Member -type NoteProperty -name CertUsageList -value "$($cert.EnhancedKeyUsageList)"
				    $certObject | Add-Member -type NoteProperty -name CertThumbprint -value "$($cert.Thumbprint)"
				    $certObject | Add-Member -type NoteProperty -name CertIssuer -value "$($cert.Issuer)"
				    $certObject | Add-Member -type NoteProperty -name CertIssueDate -value "$($cert.NotBefore)"
				    $certObject | Add-Member -type NoteProperty -name CertExpireDate -value "$($cert.NotAfter)"
				    $certObject | Add-Member -type NoteProperty -name CertDaysUntilExpire -value "$($DaysToExpire.Days)"
				    $csvResults += $certObject
				    
				    $data += "---------------------------------------------------`n"
                    $data += "Server Name: $($server.Name)`n"
                    $data += "Server IP: $($server.IPv4Address)`n"
				    if ($($cert.Verify()) -eq 1)
				    {
					    $data += "[Y]Certificate is valid`n"
				    }
				    else
				    {
					    $data += "[X]Certificate is not valid`n"
				    }
				    $data += "Certificate Subject Name   : $($cert.Subject)`n"
				    $data += "Certificate Friendly Name  : $($cert.FriendlyName)`n"
				    $data += "Certificate Usage List     : $($cert.EnhancedKeyUsageList)`n"
				    $data += "Certificate Thumbprint     : $($cert.Thumbprint)`n"
				    $data += "Certificate issued by      : $($cert.Issuer)`n"
				    $data += "Certificate Issue Date     : $($cert.NotBefore)`n"
				    $data += "Certificate Expiration Date: $($cert.NotAfter)`n"
					$data += "Days until expiration      : $($DaysToExpire.Days)`n"
				}
			}
			$store.close()
		}
		Catch
		{
			$connFails += "[*]There was an issue either connecting to $($server.Name) or retrieving certificate information`n"
		}
	}
    
    if(($($data1) -eq ""))
    {
        $mailMessage += "[*]This script found no expiring certificates within the personal stores of the servers`n"
    }
    else
    {
        $mailMessage += "===================================================`n"
        $mailMessage += "[*]Expired certificate report`n"
        $mailMessage += "===================================================`n"
        $mailMessage += "$($data)"
        $mailMessage += "===================================================`n"
    }
    $mailMessage += "[*]Information Retreival Errors`n"
    $mailMessage += "[*]These might be worth manually checking...`n"
    $mailMessage += "===================================================`n"
    $mailMessage += "$($connFails)"
    $mailMessage += "===================================================`n"
    if($MailReport -eq $false)
    {
        Write-Host "$mailMessage"
    }
    else
    {
        New-Item -Path "$($tmpPath)" -Type directory | Out-Null
	    $csvResults | Export-Csv -Path ($tmpPath + $csvFile)
        $smtp = new-object Net.mail.SmtpClient($smtpserver)
	    $smtpDetails = New-Object System.Net.Mail.MailMessage
	    $attach = New-Object Net.Mail.Attachment($tmpPath + $csvFile)
	    $smtpDetails.From = $emailFrom
	    $smtpDetails.To.Add($emailTo)
	    $smtpDetails.Subject = $subject
	    $smtpDetails.body = $mailMessage
	    $smtpDetails.Attachments.Add($attach)
        $smtp.Send($smtpDetails)
	    $attach.Dispose()
	    $smtpDetails.Dispose()
	    Remove-Item ($tmpPath + $csvFile)
        Remove-Item -Path $tmpPath
    }
}

#csvFile information
$global:tmpPath = "C:\CertTmpReport\"
$global:csvFile = "Report.csv"
#Email information
$global:emailFrom = "SENDER@YOURDOMAIN.COM"
$global:emailTo = "RECIPIENT@YOURDOMAIN.COM"
$global:subject = "Certificate Report: $(date)"
$global:smtpserver = "YOURSMTPSERVER"

If($ReportType -eq "All")
{
    Get-All-ServerCertificates
}
ElseIf($ReportType -eq "Expiring")
{
    Get-Expiring-ServerCertificates
}
ElseIf($ReportType -eq "Expired")
{
    Get-Expired-ServerCertificates
}

