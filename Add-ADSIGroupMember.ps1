Function Add-ADSIGroupMember #v3
{
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(ValueFromPipeline,Mandatory,Position=0)]
        [Alias('Group')]
        $Identity
        ,
        [Parameter(Mandatory,Position=1)]
        $Members
        ,
        [Parameter(Position=3)]
        [ValidateSet('computer','user','group')]
        [String]$ObjectClass
        ,
        [Parameter(Position=4)]
		[Alias("Domain",'DomainDN')]
        [String]$Server = "LDAP://$(([System.DirectoryServices.ActiveDirectory.DomainController]::FindOne([System.DirectoryServices.ActiveDirectory.DirectoryContext]::new([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain))).Name)"
        ,
        [Parameter(Position=5)]
        [Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
        ,
        [Switch]$PassThru
    )

    Begin
    {
        #If ($Global:Err){Remove-Variable Err -Scope Global}
        #Create an object for interactig with Active Directory
        $AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server)
        
        #Create a generic searcher object with parameters we can edit later
        [adsisearcher]$Searcher = ""
        $Searcher.PageSize = 100
        $Searcher.PropertiesToLoad.AddRange(('name','distinguishedname','objectclass','memberof'))

        Switch ($PSBoundParameters)
        {
            {$_.Server}
            {                
                IF ($Server -notlike "LDAP://*") 
                {
                    $Server = "LDAP://$Server"                
                }

                Write-Verbose -Message "Using Domain: '$Server'."

                $AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server)
                
                $Searcher.SearchRoot = $Server
            }

            {$_.Credential}
            {
                Write-Verbose -Message "Using supplied Credential: $($Credential.UserName)"
            
                #Create AdEntry object with credentials
                $AdEntry = [System.DirectoryServices.DirectoryEntry]::new($Server,$($Credential.UserName),$($Credential.GetNetworkCredential().password))

                #Add the AdEntry object path to the $Searcher; we'll use this for searching Active Driectory
                $Searcher.SearchRoot = $Server
            }

            {$_.ObjectClass}
            {
                $ObjectClassFilter = "(objectclass=$ObjectClass)"
            }
        }
                
        #array to hole group(s) in the pipeline
        $Groups = [System.Collections.ArrayList]::new()
                
        Write-Verbose "Searching '$Server' for member objects." 
        
        #Collect member objects into an array        
        $MembersArray = [System.Collections.ArrayList]::new()

        Foreach ($Member in $Members)
        {
            If ($Member -like 'CN=*')
            {
                $Searcher.Filter = "(&(distinguishedname=$Member)$ObjectClassFilter)"
            }
            Else
            {
                $Searcher.Filter = "(&(name=$Member)$ObjectClassFilter)"
            }
            
            $Object = $Searcher.FindOne()

            If ($Object)
            {
                [void]$MembersArray.Add($Object)
            }
            Else
            {
                Write-Warning "Could not find object '$Member' in '$Server'."
            }
        }
    }#Begin

    Process
    {        
        #Collect all the groups from the pipeline and add them to an array
        Foreach ($Grp in $Identity)
        {
            If ($Grp -like 'CN=*')
            {
                $Searcher.Filter = "(&(objectclass=group)(distinguishedname=$Grp))"
            }
            Else
            {
                $Searcher.Filter = "(&(objectclass=group)(name=$Grp))"
            }

            #$Searcher.SearchRoot = $(([adsisearcher]"$DomainDN").Searchroot.path)
            $Group = $Searcher.FindOne()

            If (-not $Group)
            {
                Throw "Could not find object '$Grp' in '$Server'."
            }
            Else
            {
                [void]$Groups.Add($Group)
            }
        }
    }

    End
    {
        Write-Verbose "Processing '$($MembersArray.Count)' object(s) into '$($Groups.Count)' group(s)."

        Foreach ($Member in $MembersArray)
        {
            Foreach ($Group in $Groups)
            {
                $AdEntry.Path = $Group.Path

                If ($PSCmdlet.ShouldProcess($($Group.Properties.distinguishedname),"Add object: $($Member.Properties.distinguishedname)"))
                {
                    Try
                    {
                        $AdEntry.Add($Member.Path)
                    }
                    Catch
                    {
                        Write-Error $_ -TargetObject $Member -ErrorVariable +Global:err
                        #Write-Error $_ -TargetObject $Group -ErrorVariable +Global:err
                    }
                }
            }

            If ($PassThru)
            {
                $AdEntry.Path = $Member.Path
                $AdEntry | Select distinguishedname,@{n='memberof';e={$_.memberof | Where {$_ -in $Groups.Properties.distinguishedname}}}
            }
        }
        $Searcher.Dispose()
    }
}

break

        

       