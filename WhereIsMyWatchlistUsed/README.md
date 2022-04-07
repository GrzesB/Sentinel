### PowerShell script WhereIsMyWatchlistUsed.
<br />
Requirements - PowerShell modules:

    Az.Accounts


**WhereIsMyWatchlistUsed.ps1** script looks for Watchlists defined in Microsoft Sentinel and then looks for alert rules that are using these watchlists.  
<br />

![Example](https://github.com/GrzesB/Sentinel/blob/master/IMG/WhereIsMyWatchlistUsed.png)

<br />
To get detailed help about running the script call Get-Help cmdlet, i.e.:

    Get-Help WhereIsMyWatchlistUsed.ps1
