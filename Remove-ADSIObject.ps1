Function Remove-ADSIObject
{
    [CmdletBinding(DefaultParameterSetName='DistinguishedName',SupportsShouldProcess)]
    Param
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
        [Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
        ,
        [Parameter(ValueFromPipelineByPropertyName=$false)]
		[Alias("Domain",'DomainDN')]
        [String]$Server = "LDAP://$(([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain))).Name)"
        ,
        $SearchBase
        ,
        [Parameter(ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false,Mandatory=$false,ParameterSetName='LDAPFilter')]
        $LDAPFilter        
    )
        
    Begin
    {        
        [adsisearcher]$Searcher = ""

        $ObjectCategories = @{
            computer = 'Computer'
            user = 'Person'
            group = 'Group'
        }

        Switch ($PSBoundParameters)
        {
            {$_.ContainsKey('Server') -and ($_.Server -notlike 'LDAP://*')}
            {$Server = "LDAP://$($_.Server)"}

            {$_.ContainsKey('Server') -and ($_.Server -like 'LDAP://*')}
            {$Server = $_.Server}

            {$_.ContainsKey('SearchBase') -and (-not $_.ContainsKey('Credential'))}
            {$AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$SearchBase")}

            {$_.ContainsKey('Credential') -and $_.ContainsKey('SearchBase')}
            {
                Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                #Create AdEntry object with credentials                
                $AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$SearchBase",$Credential.UserName,$Credential.GetNetworkCredential().password,[System.DirectoryServices.AuthenticationTypes]::Encryption)
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
            {
                [void]$Filters.Add("(objectclass=$($_.ObjectClass))")
                [void]$Filters.Add("(objectcategory=$($ObjectCategories[$_.ObjectClass]))")
            }

            {$_.ContainsKey('SamAccountName')}
            {
                [void]$Filters.Add("(samaccountname=$($_.SamAccountName))")
            }

            {$_.ContainsKey('DistinguishedName')}
            {
                [void]$Filters.Add("(distinguishedname=$($_.DistinguishedName))")
            }

            {$_.ContainsKey('ObjectName')}
            {
                $Object = $_.ObjectName
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

            {$_.ContainsKey('LDAPFilter')}
            {$Searcher.Filter = $_.LDAPFilter}

            {(-not $_.ContainsKey('LDAPFilter')) -and $Filters.Count -eq 1}
            {$Searcher.Filter = $Filters[0]}

            {(-not $_.ContainsKey('LDAPFilter')) -and $Filters.Count -gt 1}
            {$Searcher.Filter = '(&' + $($Filters -join "") + ')'}
        }

        Write-Verbose "ADSI Filter: '$($Searcher.Filter)'"

        #Search AD for object; returns a Searcher object
        $Obj = $Searcher.FindOne()

        #Split the DN into the OU and CN parts
        $CN,$OUPath = $obj.Properties.distinguishedname.Split(',')

        #Set the AdEntry object to the path of the OU
        $AdEntry.Path = "$Server/$($OUPath -join ',')"
        
        #Get the Object from the OU
        $Object = $ADEntry.Children.Find($CN)

        #Delete the object
        If ($PsCmdlet.ShouldProcess($Object.DistinguishedName))
        {
            $AdEntry.Children.Remove($Object)
        }
    }

    End 
    {
        $AdEntry.Close()
        $AdEntry.Dispose()
    }
}