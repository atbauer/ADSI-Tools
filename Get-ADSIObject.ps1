Function Get-ADSIObject #v1.8.10
{
    [CmdletBinding(DefaultParameterSetName='ObjectName',SupportsShouldProcess)]
    PARAM
    (        
        [Parameter(ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$true,Mandatory=$false,ParameterSetName='ObjectName',Position=0)]
        [Alias('ComputerName','UserName','Computer','User','Identity')]
        [String]$ObjectName
        ,
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false,Mandatory=$false,ParameterSetName='SamAccountName')]
        [String]$SamAccountName
        ,
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false,Mandatory=$false,ParameterSetName='DistinguishedName')]
        [String]$DistinguishedName
        ,       
        [ValidateSet('computer','user','group','organizationalunit')]
        [String]$ObjectClass
        ,
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false,Mandatory=$false,ParameterSetName='Mail')]
        $Mail
        ,
        #[ValidateSet('accountexpires','adspath','cn','codepage','countrycode','description','displayname','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogontimestamp','localpolicyflags','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usercertificate','usnchanged','usncreated','whenchanged','whencreated','*')]
        [Alias('Property')]
        $Properties
        ,
        [Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
        ,
        [Parameter(ValueFromPipelineByPropertyName=$false)]
		[Alias("Domain",'DomainDN')]
        #$(([adsisearcher]"").Searchroot.path)
        $Server = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain)).Name
        ,
        $SearchBase
        ,
        [Parameter(ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false,Mandatory=$false,ParameterSetName='LDAPFilter')]
        $LDAPFilter
        ,
        [Switch]$Disabled
        ,
        [Switch]$Recurse
        ,
        [int]$SizeLimit = 0
    )

    Begin
    {    
        Function Convert-ResultsPropertyCollection
        {
                    Param
                    (
                        [Parameter(ValueFromPipeline)]
                        [System.DirectoryServices.ResultPropertyCollection]$ResultPropertyCollection     
                    )
    
                    Process
                    {
                        $Properties = [System.Collections.Hashtable]::new()

                        $Properties.Add('PsTypeName', 'AdsiResultPropertyCollection')

                        Switch ($ResultPropertyCollection.Keys | Sort)
                        {
                            {$_ -like 'member;range=*'}
                            {Continue}#Skip this one#>

                            'objectsid'
                            {$Properties.Add('SID', [System.Security.Principal.SecurityIdentifier]::new([byte[]]$ResultPropertyCollection[$_][0],0)); Continue}

                            'objectguid'
                            {$Properties.Add('objectguid',[System.Guid]$ResultPropertyCollection[$_][0]);Continue}


                            'pwdlastset'
                            {$Properties.Add('PasswordLastSet',[datetime]::fromfiletime($ResultPropertyCollection[$_][0]));Continue}            
                            
                            {$ResultPropertyCollection[$_].Count -gt 1}
                            {$Properties.Add($_, $ResultPropertyCollection[$_])}

                            'useraccountcontrol'
                            {
                                $Properties.Add($_, $ResultPropertyCollection[$_][0])

                                Switch ($ResultPropertyCollection[$_])
                                {
                                    #PASSWD_CANT_CHANGE
                                    {[convert]::ToBoolean($_ -band 0x0040)}
                                    {$Properties.Add('CannotChangePassword', $True)}

                                    {-not [convert]::ToBoolean($_ -band 0x0040)}
                                    {$Properties.Add('CannotChangePassword', $False)}

                                    #ACCOUNTDISABLE
                                    {[convert]::ToBoolean($_ -band 0x0002)}
                                    {$Properties.Add('Enabled', $False)}

                                    {-not [convert]::ToBoolean($_ -band 0x0002)}
                                    {$Properties.Add('Enabled', $True)}

                                    #LOCKOUT
                                    {[convert]::ToBoolean($_ -band 0x0010)}
                                    {$Properties.Add('LockedOut', $True)}
            
                                    {-not [convert]::ToBoolean($_ -band 0x0010)}
                                    {$Properties.Add('LockedOut', $False)}
                                        
                                    #PASSWORD_EXPIRED
                                    {[convert]::ToBoolean($_ -band 0x800000)}
                                    {$Properties.Add('PasswordExpired', $True)}

                                    {-not [convert]::ToBoolean($_ -band 0x800000)}
                                    {$Properties.Add('PasswordExpired', $False)}

                                    #DONT_EXPIRE_PASSWORD
                                    {[convert]::ToBoolean($_ -band 0x10000)}
                                    {$Properties.Add('PasswordNeverExpires', $True)}

                                    {-not [convert]::ToBoolean($_ -band 0x10000)}
                                    {$Properties.Add('PasswordNeverExpires', $False)}

                                    #PASSWD_NOTREQD
                                    {[convert]::ToBoolean($_ -band 0x0020)}
                                    {$Properties.Add('PasswordNotRequired', $True)}

                                    {-not [convert]::ToBoolean($_ -band 0x0020)}
                                    {$Properties.Add('PasswordNotRequired', $False)}
                                }
                            }

                            Default
                            {$Properties.Add($_, $ResultPropertyCollection[$_][0])}
                        }

                        $OutputProps = [System.Collections.Specialized.OrderedDictionary]::new()

                        $Properties.GetEnumerator() | Sort -Property Name | ForEach-Object { $OutputProps.Add($_.Key, $_.Value) }
                
                        [PsCustomObject]$OutputProps
                    }
                }

        function Get-RecursiveMembership
        {
                    [CmdletBinding()]
                    param
                    (
                        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                        [String[]]$Object
                        ,
                        $Server = ([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain))).Name
                    )
    
                    begin 
                    {
                        # introduce two lookup hashtables. First will contain cached AD groups,
                        # second will contain user groups. We will reuse it for each user.
                        # format: Key = group distinguished name, Value = ADGroup object
        
                        $ADGroupCache = @{}
                        $UserGroups = @{}

                        # define recursive function to recursively process groups.
                        function Get-GroupPath
                        {
                            [CmdletBinding()]
                            Param
                            (
                                [string]$currentGroup
                            )

                            Write-Verbose "Processing group: $currentGroup"
                            # we must do processing only if the group is not already processed.
                            # otherwise we will get an infinity loop
                            if (-not $UserGroups.ContainsKey($currentGroup))
                            {
                                # retrieve group object, either, from cache (if is already cached)
                                # or from Active Directory
                                $groupObject = 
                                    if ($ADGroupCache.ContainsKey($currentGroup))
                                    {
                                        #Write-Verbose "Found group in cache: $currentGroup"
                                        $ADGroupCache[$currentGroup]
                                    }
                                    else
                                    {                        
                                        #Write-Verbose "Group: $currentGroup is not presented in cache. Retrieve and cache."
                                        Try
                                        {
                                            $Group = Get-ADSIObject -Server $Server -Identity $currentGroup -Properties DistinguishedName,MemberOf -Verbose:$false -ErrorVariable $Global:GetRecursiveMembershipErr -ErrorAction Stop -Recurse:$False
                                        }
                                        Catch
                                        {
                                            Write-Warning "An error ocurred while processing '$Object': $($_.Exception.InnerException.Message)"
                                        }
                                        # immediately add group to local cache:
                                        If ($Group)
                                        {
                                            $ADGroupCache.Add($Group.DistinguishedName, $Group)
                                            $Group
                                            $Group = $null
                                        }                        
                                    }

                                # add current group to user groups
                                $UserGroups.Add($currentGroup, $groupObject)
                                #Write-Verbose "Member of: $currentGroup"
                                foreach ($Member in $groupObject.MemberOf)
                                {
                                    Get-GroupPath $Member
                                }
                            }
                            else
                            {
                                #Write-Verbose "Closed walk or duplicate on '$currentGroup'. Skipping."
                            }
                        }
                    }
                    process
                    {
                        foreach ($Obj in $Object)
                        {
                            Write-Verbose "Processing object '$Obj'."
                            # clear group membership prior to each user processing
                            $O = Get-ADSIObject -Server $Server -Identity $Obj -Properties Name,MemberOf -Verbose:$false -Recurse:$False
                            If ($O.MemberOf)
                            {
                                $O.MemberOf | ForEach-Object {Get-GroupPath $_}
                                [PsCustomObject]@{
                                    UserName = $O.Name;
                                    MemberOf = $UserGroups.Values | Sort-Object {$_.Name} | Foreach-Object {$_.distinguishedname}
                                }
                            }
                            Else
                            {
                                Write-Warning "The Recurse parameter was specified, but '$Obj' is not a member of any groups."
                            }
                    
                            $UserGroups.Clear()
                        }
                    }
                }

        $ObjectCategories = @{
            computer = 'Computer'
            user = 'Person'
            group = 'Group'
            #organizationalunit = 'CN=Organizational-Unit,' + (Get-ADSIObject -LDAPFilter "(name=Schema)" -Properties objectcategory -Verbose:$false).objectcategory.split(',')[1..10] -join (',')
        }
                                
        $DefaultProps = ('DistinguishedName','GivenName','Name','ObjectClass','ObjectGUID','SamAccountName','SN','UserPrincipalName','DNSHostName','Enabled','ObjectSID','UserPrincipalName','UserAccountControl')                
        $SpecialChars = @('(',')','\') #characters that need to be escaped '*',
        $Partitions = [System.Collections.Hashtable]::new()                
        $Searcher = [DirectoryServices.DirectorySearcher]::new()
        $Searcher.PageSize = 1000
        $Searcher.SizeLimit = $SizeLimit
        #$Searcher.ServerTimeLimit = 0
        #$Searcher.ClientTimeout = 0               

        Switch ($PSBoundParameters)
        {
            {$Server -notlike 'LDAP://*'}
            {$Server = "LDAP://$Server"}

            {$_.ContainsKey('Server') -and ($_.Server -like 'LDAP://*')}
            {$Server = $_.Server}

            {$Server}
            {
                $Config = [System.DirectoryServices.DirectoryEntry]::new("$Server/RootDSE").Get('configurationNamingContext')
                $Searcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Partitions,$config")
                $Searcher.Filter = '(&(objectclass=Crossref)(netBIOSName=*))'
                $Searcher.FindAll() | ForEach-Object {$Partitions.Add($_.Properties.ncname[0], $_.Properties.netbiosname[0])}
                $Searcher.Filter = $null
            }

            {$_.ContainsKey('SearchBase') -and (-not $_.ContainsKey('Credential'))}
            {$AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$SearchBase")}

            {$_.ContainsKey('Credential') -and $_.ContainsKey('SearchBase')}
            {
                Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                #Create AdEntry object with credentials                
                $AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$SearchBase",$Credential.UserName,$Credential.GetNetworkCredential().password,[System.DirectoryServices.AuthenticationTypes]::Secure)
            }

            {(-not $_.ContainsKey('SearchBase')) -and $_.ContainsKey('Credential')}
            {
                Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                #Create AdEntry object with credentials                
                $AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server,$Credential.UserName,$Credential.GetNetworkCredential().password,[System.DirectoryServices.AuthenticationTypes]::Secure)   
            }

            {(-not $_.ContainsKey('SearchBase')) -and (-not $_.ContainsKey('Credential'))}
            {$AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server)}
        }

        $Searcher.SearchRoot = $AdEntry                

        Write-Verbose "Search path is '$($Searcher.SearchRoot.Path)'."
    }

    Process
    {   
        #Build a filter list. Use data supplied in valid properties directly. Or, use RegEx to figure out the correct properties from data supplied in ObjectName.
        $Filters = New-Object System.Collections.ArrayList

        Switch ($PsBoundParameters)
        {
            {$_.ContainsKey('ObjectClass')}            
            {[void]$Filters.Add("(objectclass=$($_.ObjectClass))")}

            {$_.ContainsKey('ObjectClass') -and $ObjectCategories[$_.ObjectClass]}
            {[void]$Filters.Add("(objectcategory=$($ObjectCategories[$_.ObjectClass]))")}

            {$_.ContainsKey('Mail')}
            {[void]$Filters.Add("(mail=$($_.Mail))")}

            {$_.ContainsKey('SamAccountName')}
            {[void]$Filters.Add("(samaccountname=$($_.SamAccountName))")}

            {$_.ContainsKey('DistinguishedName')}
            {[void]$Filters.Add("(distinguishedname=$($_.DistinguishedName))")}

            {$_.ContainsKey('ObjectName')}
            {
                $Object = $PsBoundParameters['ObjectName']
                Switch -Regex ($Object)
                {
                    '^CN=.*'
                    {
                        Write-Verbose "ObjectName appears to be a DistinguishedName. Setting LDAP filter property to DistinguishedName." -Verbose
                        If (($SpecialChars | Foreach-Object {$Object.ToCharArray() -contains $_}) -contains $true)
                        {
                            $EscapedObject = ($Object.ToCharArray() | ForEach-Object {if ($_ -in $SpecialChars){"\$([System.Convert]::ToString([System.Text.Encoding]::Unicode.GetBytes($_)[0],16))"}Else{$_}}) -join ''
                            [void]$Filters.Add("(distinguishedname=$EscapedObject)")
                        }
                        Else
                        {
                            [void]$Filters.Add("(distinguishedname=$Object)")
                        }
                    }

                    '(?<DOMAIN>.*)\\(?<NAME>.*)'
                    {                    
                        Write-Verbose "ObjectName contained a domain name. Using domain '$($Matches.DOMAIN)' to find this object." -Verbose
                        $Searcher.SearchRoot = "LDAP://$(([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain,$Matches.DOMAIN))).Name)"
                        Write-Verbose -Message "Using server: $($Searcher.SearchRoot.Path)."

                        If (($SpecialChars | Foreach-Object {$Matches.Name.ToCharArray() -contains $_}) -contains $true)
                        {
                            $EscapedObject = ($Matches.Name.ToCharArray() | ForEach-Object {if ($_ -in $SpecialChars){"\$([System.Convert]::ToString([System.Text.Encoding]::Unicode.GetBytes($_)[0],16))"}Else{$_}}) -join ''
                            [void]$Filters.Add("(name=$EscapedObject)")
                        }
                        Else
                        {
                            [void]$Filters.Add("(name=$($Matches.Name))")
                        }
                    }

                    Default
                    {
                        If (($Object -is [System.String]) -and (($SpecialChars | Foreach-Object {$Object.ToCharArray() -contains $_}) -contains $true))
                        {
                            $EscapedObject = ($Object.ToCharArray() | ForEach-Object {if ($_ -in $SpecialChars){"\$([System.Convert]::ToString([System.Text.Encoding]::Unicode.GetBytes($_)[0],16))"}Else{$_}}) -join ''
                            [void]$Filters.Add("(name=$EscapedObject)")
                        }
                        Else
                        {
                            [void]$Filters.Add("(name=$Object)")
                        }
                    }
                }                
            }

            {-not $PsBoundParameters.ContainsKey('Disabled') -and ($_['objectclass'] -ne 'organizationalunit')}
            {[void]$Filters.Insert(0,'(!userAccountControl:1.2.840.113556.1.4.803:=2)')}

            {$_.ContainsKey('LDAPFilter')}
            {$Searcher.Filter = $_.LDAPFilter}

            {(-not $_.ContainsKey('LDAPFilter')) -and $Filters.Count -eq 1}
            {$Searcher.Filter = $Filters[0]}

            {(-not $_.ContainsKey('LDAPFilter')) -and $Filters.Count -gt 1}
            {$Searcher.Filter = '(&' + $($Filters -join "") + ')'}

            {$_.ContainsKey('Properties')}
            {
                $Searcher.PropertiesToLoad.Clear()
                $Searcher.PropertiesToLoad.AddRange($DefaultProps)
                $Searcher.PropertiesToLoad.AddRange($Properties)
            }

            {-not $_.ContainsKey('Properties')}
            {
                $Searcher.PropertiesToLoad.Clear()
                $Searcher.PropertiesToLoad.AddRange($DefaultProps)
            }
        }

        Write-Verbose "ADSI Filter: '$($Searcher.Filter)'"     
        
        $Results = $Searcher.FindAll()
            <#If ($Searcher.Filter.ToCharArray() -contains '*')
            {
                $Searcher.FindAll()
            }
            Else
            {
                $Searcher.FindOne()
            }#>

        #I don't remember why this is here...
        #$Results.Path | Where {$_ -match '\S'} | Write-Verbose  -Verbose

        If ($Results.count -ge 1)
        {
            Foreach ($Result in $Results)
            {
                $Return = $Result.Properties | Convert-ResultsPropertyCollection

                #if range exists because group is large        
                If ($result.Properties.PropertyNames | where {$_ -like "member;range=*"})
                {
                    Write-Warning "$($Return.Name) has a large Member collection. Enumeration may take some time."

                    $Searcher.Filter = "(distinguishedname=$($Result.Properties.Item('DistinguishedName')))"

                    $Member = [System.Collections.ArrayList]::new()

                    #if group has more than 1500 members
                    $AllRanges=$false
                    $RangeBegin = 0
                    $RangeEnd = 0
    
                    while (-not ($AllRanges)) 
                    {
                        $RangeEnd = $RangeBegin + 1499

                        #set new range
                        $memberRange = "member;range=$RangeBegin-$RangeEnd"
                        $searcher.PropertiesToLoad.Clear()
                        [void]$searcher.PropertiesToLoad.Add("$memberRange")
               
                        try 
                        {
                            #if range invalid, throw exception
                            $Members = $searcher.FindOne()
                            $rangedProperty = $Members.Properties.PropertyNames -like "member;range=*"
                    
                            if (($Members.Properties.item($rangedProperty)).count -eq 0)
                            #if (($result.Properties.item('member')).count -gt 0)
                            {
                                $AllRanges=$true
                            }
                            else
                            {
                                $Members.Properties.item($rangedProperty) | Foreach-Object {[void]$Member.Add($_)}
                            }

                        } 
                        catch 
                        {
                            $AllRanges=$true
                        }

                        #increment bottom of range for next iteration
                        $RangeBegin += 1500
                    }
                        
                    $Return | Add-Member -MemberType NoteProperty -Name Member -Value $Member -Force
                }

                If ($PSBoundParameters.Recurse)
                {                   
                    $RecurseSearch = Get-RecursiveMembership -Object $Result.properties.item('name')[0] -Server $Searcher.SearchRoot.Path -Verbose:$false
                    $Return | Add-Member -MemberType NoteProperty -Name MemberOf -Value ($RecurseSearch.MemberOf | Sort {$_}) -Force
                }

                $Domain = ($Result.Properties.distinguishedname[0].Split(',') | Where {$_ -like "DC=*"}) -join ','
                $Return | Add-Member -MemberType NoteProperty -Name Domain -Value $Partitions[$Domain] -Force


                $Return
            }
        }
        else
        {
            Write-Error "No results returned using LDAP query: '$($Searcher.Filter)'."
        }
        
        
        $Searcher.SearchRoot = $ADEntry #$Server
    }

    END
    {
        $Searcher.Dispose()
    }
}