This MediaWiki (1.27+) extension allows users in an [Elkarte Forum](https://www.elkarte.net/) or [SMF forum](https://www.simplemachines.org/) to be automatically signed in if they are of the appropriate usergroup while logged into the forum.

For examples of this in action, see:

* [Elliquiy Role-Playing Forums Wiki](https://elliquiy.com/wiki/Welcome_to_Elluiki) (Gated adult writing community. Wiki active since 2006. Adult stuff is sequestered to private namespaces.)
* [Legends of a World Unbent](https://worldunbent.com/) (Site I made for Minecraft and Exalted stuff - because they're both flat. Used as a testbed for this and OpenImporter.)
* [Hexwiki](https://hexwiki.com/) (I store technical documentation here when I get to writing it.)

I wrote this to be compatible with Elkarte (1.0 and 1.1) and SMF (2.0 and 2.1). Changing from one to another is as simple as updating the software variable (see below) and updating the path, if necessary. Adding other SMF forks is generally a trivial process.

 ----
To use, the contents of the ForumSessionProvider directory need to be placed into extensions/ForumSessionProvider. It is then loaded using the 'new' plugin loading method in LocalSettings.php:

    wfLoadExtension('ForumSessionProvider');
    
**If you are upgrading from a truly ancient MediaWiki version you will need to make sure $wgSecretKey is set.**
    
    $wgSecretKey = "someextraordinarilylongstringgoesheremediawikilikesitlongwithsomethingsomething"
    
You will also want to lock down editing and creating accounts normally. For example:

    $wgGroupPermissions['*']['createaccount']     = false;
    $wgGroupPermissions['*']['read']              = true;
    $wgGroupPermissions['*']['edit']              = false;
    $wgGroupPermissions['*']['createtalk']        = false;
    $wgGroupPermissions['*']['createpage']        = false;
    $wgGroupPermissions['*']['writeapi']          = false;
    
    $wgGroupPermissions['user']['move']           = true;
    $wgGroupPermissions['user']['read']           = true;
    $wgGroupPermissions['user']['edit']           = true;
    $wgGroupPermissions['user']['upload']         = true;
    $wgGroupPermissions['user']['autoconfirmed']  = true;
    $wgGroupPermissions['user']['emailconfirmed'] = true;
    $wgGroupPermissions['user']['createtalk']     = true;
    $wgGroupPermissions['user']['createpage']     = true;
    $wgGroupPermissions['user']['writeapi']       = true;
    
This is more than necessary but I like to be thorough, personally.

Options
-------

**$wgFSPPath** Mandatory, path to the Settings.php file without the trailing /

    $wgFSPPath = "../elkarte";
    
**$wgFSPSoftware** Mandatory if not running the default (Elkarte). Possible values are:
 
* elk1.1
* smf2.0
* smf2.1


    $wgFSPSoftware = "smf2.0";

**$wgFSPNameStyle** Optional, defines how to handle illegal usernames. Defaults to 'smf'. Possible values are:

* smf - Mimics previous Auth extension behavior, where characters MediaWiki can't use are swapped out with characters SMF can't use.
* domain - Requires usernames to only use \[a-zA-Z0-9 .-\]. Doesn't sign people in otherwise.
* anything else - Invalid usernames are not signed in.


    $wgFSPNameStyle = "domain";

**$wgFSPAdminGroups** Optional array, defaults to \[1\]. Assigns sysop group. User group 1 (Administrators) is always added even if missing.

**$wgFSPInterfaceGroups** Optional array, defaults to \[1\]. Assigns interface-admin group. User group 1 (Administrators) is always added even if missing.

**$wgFSPAllowGroups** Technically optional array. Those signed into this group gain normal user rights.

**$wgFSPDenyGroups** Optional array. Anyone in one of the groups doesn't get signed in, unless they are part of an admin group. Supersedes AllowGroups.

**$wgFSPSuperGroups** Optional array. Grants the bureaucrat group. Not forced onto admins.

    $wgFSPDenyGroups = [38, 42];
    $wgFSPAllowGroups = [10, 14];
    $wgFSPAdminGroups = [1, 2, 91];
    $wgFSPInterfaceGroups = [1, 2, 97];
    $wgFSPSuperGroups = [1];
    
**$wgFSPSpecialGroups** Optional associative array of arrays to map forum groups to wiki groups.

    $wgFSPSpecialGroups = [
        'coolpeople' => [4, 15, 92], 
        'sanepeople' => [3, 234, 413]
    ];
    
**$wgFSPEnableBanCheck** Optional, defaults to false. Checks Elkarte's SMF/Ban tables for bans.

    $wgFSPEnableBanCheck = true;

----
Troubleshooting
---------------

Set $wgDebugLogFile in your LocalSettings.php:

    $wgDebugLogFile = "/some/private/path/mediawiki.log";
    
Search for ForumSessionProvider and it will tell you what it is thinking.

This bloats pretty quickly, so you'll want to comment it out after you have resolved your problem.

----
Stuff To Do
----------------------------------------
* Add more forks, as needed.
* Add MediaWiki's 1.28+ caching support (I can't test this personally yet)

----
Getting New SMF Forks In
------------------------
If you are familiar with how your fork's authentication works, feel free to submit a pull request. 

If I am overestimating the readability of my code, feel free to submit an issue.
