Function New-ADSIObject #v1.4
{
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Mandatory=$false)]        
        [Alias('ComputerName','UserName','Computer','User')]
        [String]$ObjectName
        ,
        [string]$Path #= 'OU=Deployment-Policy,OU=Groups,OU=SJM-Global,DC=ad,DC=sjm,DC=com'
        ,
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$false,Mandatory=$false)]
        [String]$DistinguishedName
        ,
       
        [ValidateSet('computer','user','group')]
        [Parameter(Mandatory=$true)]
        [String]$ObjectClass
        ,
        $Description
        ,
        [ValidateSet('Global','DomainLocal','Universal','Security')]
        $GroupType = ('DomainLocal','Security')
        ,
        [Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
        ,
        [Parameter(ValueFromPipelineByPropertyName=$false)]
		[Alias("Domain",'DomainDN')]
        $Server = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain)).Name
        ,

        [HashTable]$OtherAttributes
    )

    Begin
    {
        $GroupTypeHT = @{
            Global      = 0x00000002
            DomainLocal = 0x00000004
            Universal   = 0x00000008
            Security    = 0x80000000
        }

        Try
        {
            Switch ($PSBoundParameters)
            {
                {$_.ContainsKey('Server') -and ($_.Server -notlike 'LDAP://*')}
                {$Server = 'LDAP://' + $_.Server.TrimEnd('/')}

                {$_.ContainsKey('Server') -and ($_.Server -like 'LDAP://*')}
                {$Server = $_.Server.TrimEnd('/')}

                {$_.ContainsKey('Path') -and (-not $_.ContainsKey('Credential'))}
                {$AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$Path")}

                {$_.ContainsKey('Credential') -and $_.ContainsKey('Path')}
                {
                    Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                    #Create AdEntry object with credentials                
                    $AdEntry = [System.DirectoryServices.DirectoryEntry]::new("$Server/$Path",$Credential.UserName,$Credential.GetNetworkCredential().password,[System.DirectoryServices.AuthenticationTypes]::Secure)
                }

                {(-not $_.ContainsKey('Path')) -and $_.ContainsKey('Credential')}
                {
                    Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                    #Create AdEntry object with credentials                
                    $AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server,$Credential.UserName,$Credential.GetNetworkCredential().password,[System.DirectoryServices.AuthenticationTypes]::Secure)   
                }

                {(-not $_.ContainsKey('Path')) -and (-not $_.ContainsKey('Credential'))}
                {$AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server)}
            }
        }
        Catch
        {
            Throw $_
        }

        Write-Verbose -Message "Using Domain: $Server"
    }

    Process
    {
        Switch ($PsBoundParameters)
        {
            {$true}
            {$Object = $AdEntry.Children.Add(”CN=$($PsBoundParameters['ObjectName'])”,$ObjectClass)}

            {$_.ObjectClass -eq 'computer'}
            {
                $ObjectName = $ObjectName.ToUpper() + "$"
                $null = $Object.Put(“UserAccountControl”,4130) #disabled by default
            }

            {$_.ObjectClass -eq 'group'}
            {
                $GroupTypeHT[$GroupType] | ForEach-Object -Begin {$Sum=0} -Process {$Sum += $_}
                $null = $Object.put('grouptype',$Sum)
            }

            {$true}
            {$Object.Put(“SamAccountName”,”$ObjectName”)}

            {$_.ContainsKey('Description')}
            {$Null = $Object.put(“Description”,$description)}

            {$_.ContainsKey('Enabled')}
            {$Null = $Object.Put(“UserAccountControl”,4128)} #enabled

            {$_.ContainsKey('OtherAttributes')}
            {$PSBoundParameters.OtherAttributes.Keys | Foreach-Object {$Object.Put($_,$PSBoundParameters.OtherAttributes.$_)}}

            {$PsCmdlet.ShouldProcess("CN=$ObjectName,$Path")}
            {$Object.CommitChanges()}

            {$Object.DistinguishedName}
            {
                Write-Verbose "Successfully created '$($Object.ObjectCategory)' '$($Object.DistinguishedName)'."
                Return $Object
            }
        }
    }    
} #New-ADSIObject