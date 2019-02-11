#################################################################################
# Updates attributes in Active Directory by reading one
# or multiple CSV files given as input.
#################################################################################

$logPrefix = Get-Date -UFormat "%Y-%m-%dT%H"
$global:logfilePath = '{0}\{1}-{2}' -f $PSScriptRoot, $logPrefix, "csv2AdLog.log"

function Write-To-Debug-Log {
    param(
        [string]$filepath,
        [string]$message
    )
    $d = Get-Date -f s
    $message = '{0}: {1}' -f $d, $message
    $message | Out-File $filepath -append
    Write-Debug -Message $message 
}

function printLdapAttributes([ref]$ldapPropsToSync, [ref]$de){
    $propertiesAvailable = @()
    $propertiesNA = @()
       
    # Print all properties for debug/test purpose
    foreach ($prop in $ldapPropsToSync.Value)
    {
        $o = $de.Value.psbase
        $v = getObjProp ([ref]$o) $prop
        if($v -eq $null){
            $message = '{0}:{1}' -f $prop, "--- N/A in LDAP ---"
            $propertiesNA += $message
            continue
        }
        # properties available in LDAP #######
        $message = '{0}:{1}' -f $prop, $v
        $propertiesAvailable += $message
    }
    $m = $propertiesAvailable -join ', '
    $message = 'Available LDAP Attributes: {0}' -f $m
    Write-To-Debug-Log $global:logfilePath $message
    $m = $propertiesNA -join ', '
    $message = 'Non-existent LDAP Attributes: {0}' -f $m
    Write-To-Debug-Log $global:logfilePath $message
}

function connectToLdap([ref]$htAppConfigArg){
    $htAppConfig = $htAppConfigArg.Value
    $rootFolderCsv = $htAppConfig["RootFolderCsvFiles"]
    $archiveFolderRel = $htAppConfig["CSVArchivePathRelative"]
    $archiveFolderAbs = '{0}\{1}' -f $rootFolderCsv, $archiveFolderRel

    #### Connect LDAP ##########
    $ldapConnectionString = $htAppConfig["ldapConnectionString"]
    if($ldapConnectionString -eq $null) {
        $username = $htAppConfig["ldapUser"]
        $password = $htAppConfig["ldapPassword"]
        $DomainControllerIpAddress = $htAppConfig["ldapServerIP"]
        $port = $htAppConfig["ldapServerPort"]
        $ldapSearchRoot=$htAppConfig["ldapSearchRoot"]

        $LdapDn = $ldapSearchRoot
        $uri = "LDAP://$($DomainControllerIpAddress):$port/$LdapDn"
        $message = 'Connecting to LDAP: {0} [Login:{1}, Password:{2}]...' -f $uri, $username, $password
        Write-To-Debug-Log $global:logfilePath $message
        $dn = New-Object System.DirectoryServices.DirectoryEntry ($uri, $username, $password)
    }
    else {
        $dn = New-Object System.DirectoryServices.DirectoryEntry ($ldapConnectionString)
        $message = 'Connecting to LDAP: {0}...' -f $ldapConnectionString
        Write-To-Debug-Log $global:logfilePath $message
    }

    if ([string]::IsNullOrEmpty($dn.Path))
    {
        $message = 'ERROR: Failed to connect to LDAP:{0}!' -f $uri
        Write-Error $global:logfilePath $message
        $dnArg.Value = $null
        return $null 
    }
    $message = 'Connected to LDAP:{0}.' -f $dn.Path
    Write-To-Debug-Log $global:logfilePath $message
    return $dn 
}

function performSync([ref]$htAppConfigParam){
    $message = 'Script execution started ("{0}")...' -f $PSScriptRoot
    Write-To-Debug-Log $global:logfilePath  $message

    #$psversiontable
    #######################################################
    $rootfolderConfig = '{0}\{1}' -f $PSScriptRoot, "Config"
    $rootfolderData = '{0}\{1}' -f $PSScriptRoot, "Sample Data"
    #######################################################
    # $appConfigFilePath = '{0}\{1}' -f $rootfolderConfig, "csv2AdConfigDEV.xml"
    $appConfigFilePath = '{0}\{1}' -f $rootfolderConfig, "csv2AdConfig.xml"
    $htAppConfig = readConfigFile $appConfigFilePath
    $global:logfilePath = $htAppConfig["absolutePathOfLogFile"]

    $message = 'Execution started ("{0}")...' -f $PSScriptRoot
    Write-To-Debug-Log $global:logfilePath  $message

    $message = '{0}# of Config KVP read successfully from file: "{1}" .' -f $htAppConfig.count, $appConfigFilePath
    Write-To-Debug-Log $global:logfilePath  $message

    #### Connect LDAP ############################
    $dn = $null
    $dn = connectToLdap ([ref]$htAppConfig)
    if ($dn -eq $null)
    {
        $message = 'ERROR: Failed to connect to LDAP:{0}!' -f $uri
        Write-Error $global:logfilePath $message
        return 
    }
    $message = 'Connected to LDAP:{0}.' -f $dn.Path
    Write-To-Debug-Log $global:logfilePath $message
    ############################################

    $fieldMapJsonFilePath = '{0}\{1}' -f $PSScriptRoot, $htAppConfig["fieldMapDefRelativeToScript"]
    $message = 'Field Map Json File to consider:{0}' -f $fieldMapJsonFilePath
    Write-To-Debug-Log $global:logfilePath  $message 
 
    $message = 'Parsing Field Map file: "{0}"...' -f $fieldMapJsonFilePath
    Write-To-Debug-Log $global:logfilePath  $message 
    $htFieldMap = readFieldMapFile($fieldMapJsonFilePath)
    #$htFieldMap
    $message = '{0}# of field map records read successfully.' -f $htFieldMap.count
    Write-To-Debug-Log $global:logfilePath  $message 
    #######################################################
    syncAllCsvFilesInFolder ([ref]$htAppConfig) ([ref]$htFieldMap) ([ref]$dn)
    #######################################################
    $message = 'Exiting application.'
    Write-To-Debug-Log $global:logfilePath  $message 
}

function processSingleCsvFile($csvFilePath, [ref]$htAppConfigArg, [ref]$htFieldMapArg, [ref]$dn){
    $htFieldMap = $htFieldMapArg.Value
    $htAppConfig = $htAppConfigArg.Value

    ############################
    $message = 'Parsing Employees from CSV file: "{0}"...' -f $csvFilePath
    Write-To-Debug-Log $global:logfilePath  $message 
    
    $CSVFieldToIdentifyADUser = $htAppConfig["CSVFieldToIdentifyADUser"]
    $delimeter = $htAppConfig["CSVFieldSeparator"]
    $employeeDetailFromCsv = readCSVFile $csvFilePath $delimeter $CSVFieldToIdentifyADUser
    #$ed
    $message = '{0}# of Employee records parsed successfully.' -f $employeeDetailFromCsv.count
    Write-To-Debug-Log $global:logfilePath  $message 
    ############################
    $message = 'Transforming Field Named (CSV=>LDAP) for {0}# of employees...' -f $employeeDetailFromCsv.Count
    Write-To-Debug-Log $global:logfilePath  $message 
    $htLdapData = performAttributeMapping ($htAppConfigArg) ($htFieldMapArg)  ([ref]$employeeDetailFromCsv) ($dn) ($CSVFieldToIdentifyADUser)
    ############################
    $message = 'Updating LDAP for {0}# of employees...' -f $employeeDetailFromCsv.Count
    Write-To-Debug-Log $global:logfilePath  $message 
    updateLdap ([ref]$htLdapData) ($htFieldMapArg) ($htAppConfigArg) ($dn)
    $message = 'Updated LDAP for {0}# of employees.' -f $employeeDetailFromCsv.Count
    Write-To-Debug-Log $global:logfilePath  $message 
}

function syncAllCsvFilesInFolder([ref]$htAppConfigArg, [ref]$htFieldMap, [ref]$dn){
    $htAppConfig = $htAppConfigArg.Value
    $rootFolderCsv = $htAppConfig["RootFolderCsvFiles"]
    $archiveFolderRel = $htAppConfig["CSVArchivePathRelative"]
    $archiveFolderAbs = '{0}\{1}' -f $rootFolderCsv, $archiveFolderRel

    $b = isDirExists($archiveFolderAbs)
    if ($b -eq $false) { 
        New-Item -Path $rootFolderCsv -Name $archiveFolderRel -ItemType "directory"
    }

    $message = 'Determining CSV Files from folder:{0} for LDAP Sync ...' -f $rootFolderCsv
    Write-To-Debug-Log $global:logfilePath  $message
    $i = 0
    Get-ChildItem $rootFolderCsv -Filter *.csv | sort LastWriteTime|
    Foreach-Object {
        $message = 'Processing CSV File:{0}...' -f $_.FullName
        Write-To-Debug-Log $global:logfilePath  $message
        #### Do processing ######
        processSingleCsvFile $_.FullName ($htAppConfigArg) ($htFieldMap) ($dn)
        #########################
        $message = 'Processing of CSV File:{0} completed. Archiving the file to folder:{1}.' -f $_.FullName, $archiveFolderAbs
        Write-To-Debug-Log $global:logfilePath  $message
        $i += 1
        Move-Item -Path $_.FullName -Destination $archiveFolderAbs -Force
    }
    $message = 'Windows-AD Sync. completed, total:{0}# of CSV files processed.' -f $i
    Write-To-Debug-Log $global:logfilePath  $message
}

function isDirExists($path) { 
 
    if ([IO.Directory]::Exists($path)) 
    { 
        return $true; 
    } 
    return $false; 
} 

function readConfigFile($appConfigFilePath){
    #
    $ht = @{}
    [System.Xml.XmlDocument] $xdoc = new-object System.Xml.XmlDocument
    $xfile = resolve-path($appConfigFilePath)
    $xdoc.load($xfile)
    $rows = $xdoc.selectnodes("/configuration/settings/add") # XPath is case sensitive
    foreach ($row in $rows) {
      $k = $row.getAttribute("key")
      $v = $row.getAttribute("value")
      $ht[$k] = $v
    }
    $d = Get-Date -UFormat "%Y-%m-%dT%H"
    $logFolderRelative = $ht["logFilePathRelativeToScript"]
    $logFolderAbsolute = '{0}\{1}' -f $PSScriptRoot, $logFolderRelative
    $absolutePathOfLogFile = '{0}\{1} {2}' -f $logFolderAbsolute, $d, $ht["logFilePrefix"]
    $ht["absolutePathOfLogFile"] = $absolutePathOfLogFile
    $ht["absolutePathOfFieldMap"] = '{0}\{1}' -f $PSScriptRoot, $ht["fieldMapDefRelativeToScript"]
    
    return $ht
}

function readCSVFile($dataFile, $delimeter, $CSVFieldToIdentifyADUser){
    $userColumnHeaderName = $CSVFieldToIdentifyADUser

    if ($delimeter.Length -eq 0) {
        $message = 'CSV Field to Identify AD User: "{0}". Delimiter "{1}" will be used to read file:{2}.' -f $CSVFieldToIdentifyADUser, "<tab>", $dataFile
        Write-To-Debug-Log $global:logfilePath $message
    
        $p = Import-Csv $dataFile -Delimiter `t
    }
    else {
        $message = 'CSV Field to Identify AD User: "{0}". Delimiter "{1}" will be used to read file:{2}.' -f $CSVFieldToIdentifyADUser, $delimeter, $dataFile
        Write-To-Debug-Log $global:logfilePath $message
       
        $p = Import-Csv $dataFile -Delimiter $delimeter
    }
    $htUserIdVsFieldsAsHt = @{}

    Foreach ($o in $p)
    {
        $htFieldNameAndValue = @{}
        Foreach ($c in $o.psobject.Properties)
        {
            $htFieldNameAndValue[$c.Name]=$c.Value 
        }
        $user = $htFieldNameAndValue[$userColumnHeaderName]
        if ($user.Length -eq 0) {
            $message = 'ERROR: No column named "{0}" exists in CSV File:{1}; Delimiter Used:{2}!' -f $userColumnHeaderName,  $dataFile, $delimeter
            Write-To-Debug-Log $global:logfilePath $message
            Write-Error -Message $message
        }

        $htUserIdVsFieldsAsHt[$user] = $htFieldNameAndValue 
    }
    return $htUserIdVsFieldsAsHt
}

function readFieldMapFile($fieldMapJsonFilePath){
    $json=(Get-Content -Raw $fieldMapJsonFilePath | ConvertFrom-Json)
    $ht = @{}
    $ignoredFields = @()
    Foreach ($o in $json)
    {
        if ($o.IsDisabled -eq $TRUE)
        {
            $message = '[CSV:{0}, LDAP:{1}]' -f $o.ColCSV,  $o.AttrLDAP
            $ignoredFields += $message

            continue
        }
        #$ht[$o.ColCSV]=$o.AttrLDAP
        $ht[$o.ColCSV] = $o
    }
    $m = $ht.Keys -join ', '
    $message = '{0}# of columns identified for Sync, identified Keys: [{1}]' -f $ht.Count, $m
    Write-To-Debug-Log $global:logfilePath  $message
    $m = $ignoredFields -join ', '
    $message = '{0}# of columns IGNORED for Sync! IGNORED Fields: [{1}]' -f $ignoredFields.Length, $m
    Write-To-Debug-Log $global:logfilePath  $message

    return $ht
}

function performAttributeMapping([ref]$htAppConfigArg, [ref]$htFieldMap, [ref]$htCSVData, [ref]$dn, $CSVFieldToIdentifyADUser){
    $htLdapData = @{}
    Foreach ($userId in $htCSVData.Value.Keys)
    {
        $message = 'Transforming columns (CSV->LDAP) for user:{0}...' -f $userId
        Write-To-Debug-Log $global:logfilePath  $message

        $htUserAttributes = $htCSVData.Value[$userId]
        $ht = performAttributeMappingForUser ($htAppConfigArg) ($htFieldMap) ([ref]$htUserAttributes) ($dn) ($CSVFieldToIdentifyADUser)
        $ht = $ht.Data
        $htLdapData[$userId] = $ht
    }
    return $htLdapData
}
 
function performAttributeMappingForUser([ref]$htAppConfigArg, [ref]$htFieldMap, [ref]$htUserAttributes, [ref]$dn, $CSVFieldToIdentifyADUser){
    $ht = @{}
    $propertiesIgnored = @()
    Foreach ($ColCSV in $htUserAttributes.Value.Keys)
    {
        if($htFieldMap.Value.ContainsKey($ColCSV))
        {
            $o = $htFieldMap.Value[$ColCSV]
            $fieldValueToSet = $htUserAttributes.Value[$ColCSV]
            if($o.IsUserReferenceField -ne $null){
                $fieldValueToSet = getReferencedUserData ($htAppConfigArg) ($htUserAttributes) ([ref]$o) ($dn) ($CSVFieldToIdentifyADUser)
                if ($fieldValueToSet -eq $null -or $fieldValueToSet.Length -eq 0) {
                    $propertiesIgnored += $ColCSV
                    continue
                }
            }

            $ldapKey = $o.AttrLDAP
            $ht[$ldapKey] = $fieldValueToSet
            continue
        }
        $propertiesIgnored += $ColCSV
    }
    @{"Data" = $($ht);}
    return $ht
}
 
function getReferencedUserData([ref]$htAppConfigArg, [ref]$htUserDataFromCsvArg, [ref]$fieldMapRecArg, [ref]$dnArg, $CSVFieldToIdentifyADUser){
    $htUserAttributes = $htUserDataFromCsvArg.Value
    $htAppConfig = $htAppConfigArg.Value
    $enableLdapWrite = $htAppConfig["enableLdapWrite"] -eq "true"
    $fieldMapRecord = $fieldMapRecArg.Value
    
    # {
    #    "AttrLDAP": "manager",
    #    "ColCSV": "ManagerName",
    #    "IsUserReferenceField": true,
    #    "IsDisabled": false
    # }

    $userToSearch = $htUserAttributes[$fieldMapRecord.ColCSV] #Example: Manager's Name; user_id_col_name_in_AD
    if ($userToSearch -eq $null -or $userToSearch.Length -eq 0) {
        $message = 'Warning: Field value is not set for Field: "{0}" defined in CSV file!' -f $fieldMapRecord.ColCSV
        Write-To-Debug-Log $global:logfilePath $message
        return
    }
    $fieldToExtract = $fieldMapRecord.LdapAttribToExtractFromReferencedUser
 
    #Search User ###########
    $userSearchExpressionFmt = $htAppConfig["ldapRefUserSearchExpressionFormat"]
    $ldapFieldToLoad = $htAppConfig["ldapFieldToMapToRefUser"]
    $arrayAttribsToLoad = @()
    $arrayAttribsToLoad += $ldapFieldToLoad

    $userSearchExpression = $userSearchExpressionFmt -f $userToSearch
    $r = findUserInLdap ($userSearchExpression) ([ref]$arrayAttribsToLoad) ($dnArg)
    $r = $r.Data;
    if ($r -eq $null) {
        $message = 'Warning: Reference User "{0}" does not exist LDAP. LDAP Filter Criteria Used "{1}"' -f $userToSearch, $userSearchExpression
        Write-To-Debug-Log $global:logfilePath $message
        return $null
    }
    #Extract property ($field) from the matching employee
    $fieldValue = $r.Properties[$ldapFieldToLoad]
    
    $message = 'Successfully extracted reference user detail ID ["{0}"="{1}"] for sAMAccountName="{2}".' -f $ldapFieldToLoad, $userToSearch, [string]$fieldValue
    Write-To-Debug-Log $global:logfilePath  $message
    return $fieldValue 
}

function updateLdap([ref]$htLdapDataArg, [ref]$htFieldMap, [ref]$htAppConfig, [ref]$dn){
    $htLdapData = $htLdapDataArg.Value
    Foreach ($user in $htLdapData.Keys)
    {
        $htAttribsToUpdForUser = $htLdapData[$user]
        $message = 'Updating LDAP for user:{0}...' -f $user
        Write-To-Debug-Log $global:logfilePath  $message

        updateUserInLdap ($user) ([ref]$htAttribsToUpdForUser) ($htAppConfig) ($dn)
    }
}

function updateUserInLdap($userToUpdateInLdap, [ref]$htAttribsToUpdForUser, [ref]$htAppConfigArg, [ref]$dnArg){
    $htAppConfig = $htAppConfigArg.Value
    
    $userSearchExpressionFmt = $htAppConfig["ldapUserSearchExpressionFormat"]
    $enableLdapWrite = $htAppConfig["enableLdapWrite"] -eq "true"
    $arrayAttribsToLoad = @()
    $arrayAttribsToLoad += $htAttribsToUpdForUser.Value.Keys

    $userSearchExpression = $userSearchExpressionFmt -f $userToUpdateInLdap
    $r = findUserInLdap ($userSearchExpression) ([ref]$arrayAttribsToLoad) ($dnArg)
    $r = $r.Data;
    if ($r -eq $null) {
        $message = 'User "{0}" does not exist LDAP. LDAP Filter Criteria Used "{1}"' -f $userToUpdateInLdap, $userSearchExpression
        Write-To-Debug-Log $global:logfilePath $message
        return
    }
    $de = $r.GetDirectoryEntry()

    printLdapAttributes ([ref]$arrayAttribsToLoad) ([ref]$de)

    if ($enableLdapWrite -eq $True) {
        updateLdapAttributes ($htAttribsToUpdForUser) ([ref]$de)
        $affectedAttribs = $arrayAttribsToLoad -join ', '
        $message = 'User attributes for "{0}" has been updated to LDAP. Affected Attributes: [{1}]' -f $userToUpdateInLdap, $affectedAttribs
        Write-To-Debug-Log $global:logfilePath $message
    }
    else
    {
        $message = 'LDAP update DISABLED as per application configuration file, UPDATE SKIPPED for user: {0}!' -f $userToUpdateInLdap
        Write-To-Debug-Log $global:logfilePath $message
    }
}

function findUserInLdap ($userSearchExpression, [ref]$arrayAttribsToLoad, [ref]$dnArg){
    $dn = $dnArg.Value
    $ds = new-object System.DirectoryServices.DirectorySearcher($dn)
    #$rc = $ds.filter = "(&(objectClass=user)(sAMAccountName=$userToUpdateInLdap))"
    #$rc = $ds.filter = "(&(objectClass=person)(CN=$userToUpdateInLdap))"
    $rc = $ds.filter = $userSearchExpression
    $rc = $ds.SearchScope = "SubTree"

    foreach ($prop in $arrayAttribsToLoad.Value)
    { 
        $ds.propertiesToLoad.add($prop)
    } 

    $result = $ds.FindOne()
    if ($result -eq $null -or $result.Count -lt 1){
        $message = 'No matching elements found in LDAP with filter: {0}!' -f $ds.filter
        Write-To-Debug-Log $global:logfilePath $message
        $result = $null
    }
    @{"Data" = $($result);}
}

function updateLdapAttributes([ref]$htAttribsKeyValToUpdArg, [ref]$de){
    $htAttribsToUpdForUser = $htAttribsKeyValToUpdArg.Value
    $propertiesToPrint = @()

    foreach ($prop in $htAttribsToUpdForUser.Keys)
    {
        $valueToSet = $htAttribsToUpdForUser[$prop]
        if ($valueToSet -eq $null -or $valueToSet.ToString().Length -le 0){
            $message = 'Skipping propoerty update for: {0} to ({1})' -f $prop, $valueToSet
            Write-To-Debug-Log $global:logfilePath $message
            continue
        }
        $o = $de.Value.psbase

        $propDataType = "--Undefined--"
        $p = $o.Properties[$prop]
        if ($p -ne $null -and $p.Value -ne $null){
            $propDataType = $p.Value.GetType().Name
        }
        ########################
        $message = 'Trying to set propoerty: {0} to ({1})' -f $prop, $valueToSet
        Write-To-Debug-Log $global:logfilePath $message
        setObjProp ([ref]$o) ($prop) ($valueToSet)
        $de.value.SetInfo()
        ########################
        $message = '{0} ({1})' -f $prop, $propDataType
        $propertiesToPrint += $message
    }
    return
    Try
    {
        $de.value.SetInfo()
    }
    Catch
    {
        $m = $propertiesToPrint -join ', '
        $message = 'ERROR: Failed to update LDAP Attributes: "{0}"! Possible reason data type mismatch. Ensure all the CSV fields having correctly formatted data (as per LDAP data type). Exception Message:{1}' -f $m, $_.Exception.Message
        Write-To-Debug-Log $global:logfilePath $message
    }
}

function getObjProp([ref]$o, $propName){
    Try
    {
        $v = $o.Value.InvokeGet($propName)
        return $v
    }
    Catch
    {
        $message = 'ERROR: LDAP Attribute "{0}" does not exist for user! Exception Message:{1}' -f $propName, $_.Exception.Message
        Write-To-Debug-Log $global:logfilePath $message
    }
    return $null
}
 
function setObjProp([ref]$o, $propName, $valueToSet){
    $propDataType = "--Not Retrieved--"
    Try
    {
        $p = $o.Value.Properties[$propName]
        if($p -eq $null){
            return
        }
        $o.Value.InvokeSet($propName, $valueToSet)
        $propDataType = $p.Value.GetType().Name
        return $valueToSet
    }
    Catch
    {
        $message = 'ERROR: Failed to set LDAP Attribute "{0}", Attribute does not exist for user! Exception Message:{1}' -f $propName, $_.Exception.Message
        Write-To-Debug-Log $global:logfilePath $message
    }
    return $null
}

function main(){
	$Time = Get-Date
    $ErrorActionPreference = "Stop"
    $DebugPreference = "Continue"

    $rootfolderConfig = '{0}\{1}' -f $PSScriptRoot, "Config"
    $appConfigFilePath = '{0}\{1}' -f $rootfolderConfig, "csv2AdConfig.xml"
    #######################################################
    $htAppConfig = readConfigFile $appConfigFilePath
     
    $message = '{0}: {1}# of Config Keys/Values read successfully from file: "{2}" .' -f $Time, $htAppConfig.count, $appConfigFilePath
    Write-To-Debug-Log $global:logfilePath  $message 

    Try
    {
        $message = 'Performing CSV to Windows-AD-2003 Sync.' -f $Time
        Write-To-Debug-Log $global:logfilePath $message
        
        performSync ([ref]$htAppConfig)
        
        $message = 'CSV to Windows-AD-2003 Sync. completed' -f $Time
        Write-To-Debug-Log $global:logfilePath $message
    }
    Catch [System.OutOfMemoryException]
    {
        $message = '{0}: Out Of Memory Exception encounterd, Exiting application, Exception: "{1}" .' -f $Time , $_.Exception.Message
        Write-To-Debug-Log $global:logfilePath $message
    }
    Catch
    {
        $message = "{0}: Application Terminated due to error: Failed Item: {1}; The error message was:{2}.`n" -f $Time, $FailedItem, $_.Exception.Message
        $formatstring = "{0} : {1}`n{2}`n" +
                        "    + CategoryInfo          : {3}`n"
                        "    + FullyQualifiedErrorId : {4}`n"
        $fields = $_.InvocationInfo.MyCommand.Name,
                  $_.ErrorDetails.Message,
                  $_.InvocationInfo.PositionMessage,
                  $_.CategoryInfo.ToString(),
                  $_.FullyQualifiedErrorId

        $m = $formatstring -f $fields
        $message = '{0}: {1}.' -f $message, $m

        Write-To-Debug-Log $global:logfilePath $message

        $from = $htAppConfig["errorNotificationMailTo"]
        $to = $htAppConfig["errorNotificationMailFrom"]
        $subject = $htAppConfig["errorNotificationSubject"]
        $smtpServer = $htAppConfig["SmtpServer"]
        $smtpUserId = $htAppConfig["smtpUserId"]
        $smtpPassword = $htAppConfig["smtpPassword"]
        
        if ([string]::IsNullOrEmpty($smtpPassword))
        {
            return #No need to send mail
        }
       
        $pw = ConvertTo-SecureString $smtpPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential $smtpUserId, $pw

        Send-MailMessage `
            -To $to `
            -Subject $subject `
            -Body $message `
            -UseSsl `
            -Port 587 `
            -SmtpServer $smtpServer `
            -From $from `
            -Credential $cred
        Break
    }
    Finally
    {
    }
}

###########################################################
function executeMain(){
    main
}

###########################################################
executeMain
