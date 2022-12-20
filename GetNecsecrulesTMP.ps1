
# ########## Define variables for execution ############
# Update with information specific to your environment #
########################################################

#clusterdeets elimiates the need to code in userids and passwords, and allows a single execution of the script to be run against multiple Prism Centrals.

$clusterdeets = Import-Csv /Users/keith.olsen/Documents/GitHub/GetNetSecRules/clusters.csv # csv file with cluster details (IP, userid, password)


# Establishes variables for cluster details

foreach ($c in $clusterdeets) {
  $prisCentIP = $c.IP
  $RESTAPIUser = $c.login
  $RESTAPIPassword = $c.password
  Write-Host $prisCentIP
  Write-Host $RESTAPIUser
  Write-Host $RESTAPIPassword


  # Creates variable with base API BaseURL

  $BaseURL = "https://" + $prisCentIP + ":9440/api/nutanix/v3/"
  Write-Host $BaseURL

  # Creates header file for API calls

  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("Content-Type", "application/json")
  $headers.Add("Authorization", "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RESTAPIUser+":"+$RESTAPIPassword)))
 

  Write-Host $headers.'Authorization'
  Write-Host $headers.'Content-Type'

  # Get security policies from Prism Central

  $body = "{`"kind`": `"network_security_rule`"}"

  $NRlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'network_security_rules/list' -Method 'POST' -Headers $headers -Body $body

 $NRresponse =  $NRlist.entities | Convertto-Json -depth 100

 #Write-Host $NRresponse

  foreach ($r in $NRlist.entities) {

    #sets base path for quarantine adn application rules
    $quarrule = $r.spec.resources.quarantine_rule
    $apprule = $r.spec.resources.app_rule
      Write-Host ""
      Write-Host "######################"
      Write-Host ""
      write-host "Name:" $r.status.name
      write-host "Description:" $r.status.description
      Write-Host ""
      
      # if ($r.spec.name -eq "Quarantine") {
      #   if ($quarrule.action -eq "APPLY") {
      #     $state = "ENFORCED"
      #   }else {
      #     $state = "MONITORING"
      #   }
      #   Write-Host "State: " $state
      #   Write-Host "---- INBOUND SOURCE(S)------"
      #   foreach ($sg in $quarrule.inbound_allow_list) {

      #       Write-Host "RuleID:" $sg.rule_id
      #       Write-Host "SOURCE : ALLOWED"
  
      #       if ($sg.peer_specification_type -eq "ALL") {
      #         Write-Host "ALL : ALL"
      #       }
            
      #       if ($sg.ip_subnet.ip -ne $null) {
      #         $ip = $sg.ip_subnet.ip
      #         $cidr = $sg.ip_subnet.prefix_length
      #         if ($sg.protocol -eq "TCP") {
      #         $stprt = $sg.tcp_port_range_list.start_port
      #         $eprt = $sg.tcp_port_range_list.end_port
      #         Write-Host "Subnet: "$ip"/"$cidr "TCP Port Range: " $stprt "-" $eprt
      #         }
      #         elseif ($sg.protocol -eq "UDP") {
      #           $stprt = $sg.udp_port_range_list.start_port
      #           $eprt = $sg.udp_port_range_list.end_port
      #           Write-Host "Subnet: "$ip"/"$cidr "UDP Port Range: " $stprt "-" $eprt
      #           }
      #         elseif ($sg.service_group_list.kind -eq "service_group") {
      #           $SGuuid = $sg.service_group_list.uuid
      #           $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
      #           $sgn = $SGlist.service_group.name
      #           }
      #         elseif ($sg.protocol -eq "ALL") {
      #           Write-Host "Subnet: "$ip"/"$cidr ": ALL"
      #         }
      #         }
      #       if ($sg.address_group_inclusion_list.kind -eq "address_group"){
      #         $AGuuid = $sg.address_group_inclusion_list.uuid
      #         $AGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/address_groups/'$AGuuid -Method 'GET' -Headers $headers
      #         $agn = $AGlist.address_group.name
      #         if ($sg.protocol -eq "TCP") {
      #           $stprt = $sg.tcp_port_range_list.start_port
      #           $eprt = $sg.tcp_port_range_list.end_port
      #           Write-Host "Address Group:" $agn "TCP Port Range: " $stprt "-" $eprt
      #           }
      #           elseif ($sg.protocol -eq "UDP") {
      #             $stprt = $sg.udp_port_range_list.start_port
      #             $eprt = $sg.udp_port_range_list.end_port
      #             Write-Host "Address Group:" $agn "UDP Port Range: " $stprt "-" $eprt
      #             }
      #           elseif ($sg.service_group_list.kind -eq "service_group") {
      #             $SGuuid = $sg.service_group_list.uuid
      #             $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
      #             $sgn = $SGlist.service_group.name
      #             Write-Host "Address Group:" $agn ":" $sgn
      #             }
      #         }
  
      #       if ($sg.service_group_list.kind -eq "service_group") {
      #         $SGuuid = $sg.service_group_list.uuid
      #         $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
      #         $sgn = $SGlist.service_group.name
      #         $ip = $sg.ip_subnet.ip
      #         $cidr = $sg.ip_subnet.prefix_length
              
      #         if ($sg.ip_subnet.ip -ne $null) {Write-Host "Subnet: "$ip"/"$cidr ":" $sgn}
      #           }    
      #         elseif ($sg.protocol -eq "ALL") {
      #         $sgn = "ALL"
      #           } 
    
      #       foreach ($p in $sg.filter.params) {
      #         $param = Get-Member -InputObject $p -membertype noteproperty 
      #         foreach ($x in $param.name) {
      #           Write-Host $x ":" $sg.filter.params.$x ":" $sgn
      #         }
      #       }
      #       Write-Host ""
      #     }
      # }
      $tg = $apprule.target_group.filter.params
      Write-Host ""
      Write-Host "------PROTECTING------"
      foreach ($t in $tg) {
        $param = Get-Member -InputObject $t -membertype noteproperty 
        foreach ($x in $param.name) {
          Write-Host $x ":" $tg.$x
        }
        Write-Host ""
      }
        Write-Host "---- INBOUND SOURCE(S)------"
        foreach ($sg in $apprule.inbound_allow_list) {
          Write-Host "RuleID:" $sg.rule_id
          Write-Host "SOURCE : ALLOWED"

          if ($sg.peer_specification_type -eq "ALL") {
            Write-Host "ALL : ALL"
          }
          
          if ($sg.ip_subnet.ip -ne $null) {
            $ip = $sg.ip_subnet.ip
            $cidr = $sg.ip_subnet.prefix_length
            if ($sg.protocol -eq "TCP") {
            $stprt = $sg.tcp_port_range_list.start_port
            $eprt = $sg.tcp_port_range_list.end_port
            Write-Host "Subnet: "$ip"/"$cidr "TCP Port Range: " $stprt "-" $eprt
            }
            elseif ($sg.protocol -eq "UDP") {
              $stprt = $sg.udp_port_range_list.start_port
              $eprt = $sg.udp_port_range_list.end_port
              Write-Host "Subnet: "$ip"/"$cidr "UDP Port Range: " $stprt "-" $eprt
              }
            elseif ($sg.service_group_list.kind -eq "service_group") {
              $SGuuid = $sg.service_group_list.uuid
              $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
              $sgn = $SGlist.service_group.name
              }
            elseif ($sg.protocol -eq "ALL") {
              Write-Host "Subnet: "$ip"/"$cidr ": ALL"
            }
            }
          if ($sg.address_group_inclusion_list.kind -eq "address_group"){
            $AGuuid = $sg.address_group_inclusion_list.uuid
            $AGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/address_groups/'$AGuuid -Method 'GET' -Headers $headers
            $agn = $AGlist.address_group.name
            if ($sg.protocol -eq "TCP") {
              $stprt = $sg.tcp_port_range_list.start_port
              $eprt = $sg.tcp_port_range_list.end_port
              Write-Host "Address Group:" $agn "TCP Port Range: " $stprt "-" $eprt
              }
              elseif ($sg.protocol -eq "UDP") {
                $stprt = $sg.udp_port_range_list.start_port
                $eprt = $sg.udp_port_range_list.end_port
                Write-Host "Address Group:" $agn "UDP Port Range: " $stprt "-" $eprt
                }
              elseif ($sg.service_group_list.kind -eq "service_group") {
                $SGuuid = $sg.service_group_list.uuid
                $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
                $sgn = $SGlist.service_group.name
                Write-Host "Address Group:" $agn ":" $sgn
                }
            }

          if ($sg.service_group_list.kind -eq "service_group") {
            $SGuuid = $sg.service_group_list.uuid
            $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
            $sgn = $SGlist.service_group.name
            $ip = $sg.ip_subnet.ip
            $cidr = $sg.ip_subnet.prefix_length
            
            if ($sg.ip_subnet.ip -ne $null) {Write-Host "Subnet: "$ip"/"$cidr ":" $sgn}
              }    
            elseif ($sg.protocol -eq "ALL") {
            $sgn = "ALL"
              } 
  
          foreach ($p in $sg.filter.params) {
            $param = Get-Member -InputObject $p -membertype noteproperty 
            foreach ($x in $param.name) {
              Write-Host $x ":" $sg.filter.params.$x ":" $sgn
            }
          }
          Write-Host ""
        }

        Write-Host "---- OUTBOUND TARGETS(S)------"
        foreach ($sg in $apprule.outbound_allow_list) {
          Write-Host "RuleID:" $sg.rule_id
          Write-Host "TARGET : ALLOWED"

          if ($sg.peer_specification_type -eq "ALL") {
            Write-Host "ALL : ALL"
          }
          
          if ($sg.ip_subnet.ip -ne $null) {
            $ip = $sg.ip_subnet.ip
            $cidr = $sg.ip_subnet.prefix_length
            if ($sg.protocol -eq "TCP") {
            $stprt = $sg.tcp_port_range_list.start_port
            $eprt = $sg.tcp_port_range_list.end_port
            Write-Host "Subnet: "$ip"/"$cidr "TCP Port Range: " $stprt "-" $eprt
            }
            elseif ($sg.protocol -eq "UDP") {
              $stprt = $sg.udp_port_range_list.start_port
              $eprt = $sg.udp_port_range_list.end_port
              Write-Host "Subnet: "$ip"/"$cidr "UDP Port Range: " $stprt "-" $eprt
              }
            elseif ($sg.service_group_list.kind -eq "service_group") {
              $SGuuid = $sg.service_group_list.uuid
              $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
              $sgn = $SGlist.service_group.name
              }
            elseif ($sg.protocol -eq "ALL") {
              Write-Host "Subnet: "$ip"/"$cidr ": ALL"
            }
            }
          if ($sg.address_group_inclusion_list.kind -eq "address_group"){
            $AGuuid = $sg.address_group_inclusion_list.uuid
            $AGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/address_groups/'$AGuuid -Method 'GET' -Headers $headers
            $agn = $AGlist.address_group.name
            if ($sg.protocol -eq "TCP") {
              $stprt = $sg.tcp_port_range_list.start_port
              $eprt = $sg.tcp_port_range_list.end_port
              Write-Host "Address Group:" $agn "TCP Port Range: " $stprt "-" $eprt
              }
              elseif ($sg.protocol -eq "UDP") {
                $stprt = $sg.udp_port_range_list.start_port
                $eprt = $sg.udp_port_range_list.end_port
                Write-Host "Address Group:" $agn "UDP Port Range: " $stprt "-" $eprt
                }
              elseif ($sg.service_group_list.kind -eq "service_group") {
                $SGuuid = $sg.service_group_list.uuid
                $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
                $sgn = $SGlist.service_group.name
                Write-Host "Address Group:" $agn ":" $sgn
                }
            
            }

          if ($sg.service_group_list.kind -eq "service_group") {
            $SGuuid = $sg.service_group_list.uuid
            $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/'$SGuuid -Method 'GET' -Headers $headers
            $sgn = $SGlist.service_group.name
            $ip = $sg.ip_subnet.ip
            $cidr = $sg.ip_subnet.prefix_length
            
            if ($sg.ip_subnet.ip -ne $null) {Write-Host "Subnet: "$ip"/"$cidr ":" $sgn}
              }    
            elseif ($sg.protocol -eq "ALL") {
            $sgn = "ALL"
              } 
  
          foreach ($p in $sg.filter.params) {
            $param = Get-Member -InputObject $p -membertype noteproperty 
            foreach ($x in $param.name) {
              Write-Host $x ":" $sg.filter.params.$x ":" $sgn
            }
          }
          Write-Host ""
        }
    }
  }
        # if ($sg.service_group_list.kind -eq "service_group") {
        #   #Write-Host $sg.service_group_list.uuid
        # $SGuuid = $sg.service_group_list.uuid
        # #Write-Host $SGuuid
        # $body = "{`"kind`": `"service_group`", `"length`": 100}"
        # $SGlist = Invoke-RestMethod -SkipCertificateCheck -Uri $BaseURL'/service_groups/list' -Method 'POST' -Headers $headers -Body $body
        # $response =  $SGlist.entities | Convertto-Json -depth 100
        #   foreach ($sn in $SGlist.entities){
        #     if ($sn.uuid -eq $SGuuid) {
        #       Write-Host $sn.service_group.name
        
