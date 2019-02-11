# csvToActiveDirectorySync
[Powershell script](./csv2Ad.ps1) to update ['user'](https://docs.microsoft.com/en-us/windows/desktop/adsi/ldap-user-object) attributes in Active Directory by reading one or multiple CSV files given as input.

The ['user'](https://docs.microsoft.com/en-us/windows/desktop/adsi/ldap-user-object) attributes in Active Directory are updated if the object (user in CSV) exists in Active Directory, i.e. [The script](./csv2Ad.ps1) will not create any user if the same does not exist in Active Directory.
The attributes for update is configured by defining a field map between CSV columns and User Attributes in Active Directory in file.
An execution Log gets created in a predefined location to verify execution outcome.

# Prerequisites
* Windows Server 2008 R264 bit
* PowerShell  Version 4.0
* .Net Framework 3.5 SP1
* Microsoft Active Directory User Account with Read/Write Access to 'user' Objects.

# Configuration
The below 2 files need to be configured correctly for 'Active Directory update' to work.

## [csv2AdAttributeMap.json](./Config/csv2AdAttributeMap.json)
This configuration is for mapping CSV columns with User Attributes in LDAP. Below is an example column or field map.

```json
[
  {
    "AttrLDAP": "employeeNumber",
    "ColCSV": "EMPLOYEE_NUMBER",
    "IsDisabled": false
  },
  {
    "AttrLDAP": "dispName",
    "ColCSV": "EMPLOYEE_NAME",
    "IsDisabled": true
  },
  {
    "AttrLDAP": "telNumber",
    "ColCSV": "WORK_TELEPHONE",
    "IsDisabled": false
  },
  {
    "AttrLDAP": "bu",
    "ColCSV": "BUSINESS_UNIT",
    "IsDisabled": false
  },
  {
    "AttrLDAP": "company",
    "ColCSV": "COMPANY",
    "IsDisabled": false
  },
  {
    "AttrLDAP": "user_id_col_name_in_AD",
    "ColCSV": "user_id_col_name_in_AD",
    "IsDisabled": true
  }
]
```

## [csv2AdConfig.xml](./Config/csv2AdConfig.xml)
Configurations related to LDAP connection, Field Map (CSV & LDAP) and folder to read CSV files from are set here. The XML file contains comments in each section for better understanding of the parameters. 
Below are few key parameters:
1.	fieldMapDefRelativeToScript
2.	ldapConnectionString 
3.	RootFolderCsvFiles
4.	CSVFieldToIdentifyADUser
5.	enableLdapWrite 	

Given below the important config keys from [csv2AdConfig.xml](./Config/csv2AdConfig.xml).

```xml
<?xml version="1.0"?>
<configuration>
  <settings><add key="fieldMapDefRelativeToScript" value=".\Config\csv2AdAttributeMap.json"/>
    <add key="ldapConnectionString" value="LDAP://DC=exampleOrg,DC=local"/>
    <add key="ldapSearchRoot" value="CN=Users,DC=exampleOrg,DC=com"/>
    <add key="RootFolderCsvFiles" value="D:\Example\csvToAD\Data"/>
    <add key="CSVFieldSeparator" value=","/>
    <add key="CSVFieldToIdentifyADUser" value="EMPLOYEE_NAME"/>
    <add value="False" key="enableLdapWrite"/>
  </settings>
</configuration>
```

# Steps for Execution

1. Create a folder for CSV Files as given in 'RootFolderCsvFiles' key and add .csv files into the folder.
2. Launch Windows PowerShell 
3. Navigate to the directory where the [script](./csv2Ad.ps1) lives
4. Execute the script [script](./csv2Ad.ps1)
5. After execution of script a log file will be generated at .\Logs folder. 
6. Text files created in .\Logs folder provide info on no. of fields updated with LDAP along with no. of fields ignored.


# Limitations 
1.	Error is reported when an LDAP field gets initialized by the script 1st time, but the values get updated in LDAP successfully.
2.	The script ignores CSV fields having Zero length string, hence Zero length strings can’t be set to any LDAP field. The workaround is to use a space character instead of Zero length strings in CSV.

