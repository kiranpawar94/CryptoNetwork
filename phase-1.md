Group Members (Name, Email, Github ID): 
* Kiran Pawar, kip28@pitt.edu, kiranpawar94
* Nicolas Campuzano Jimenez, nic89@pitt.edu, nic89
* Steve Zhu, haz79@pitt.edu, haz79-zhu

# Section 1: Security Properties

## 1. Hierarchical Structure 
There is a hierarchical structure within the organization utilizing the system. This will facilitate the implementation of Role Based Access Control (RBAC), which will is further explained in Property 9. 
1. Admin - server-wide permissions Administrators will have full control of servers, their contents, and users 
2. Moderator - group-wide permission, similar to admin privileges but restricted to the group(s) they govern 
3. User - basic level permissions, can only download and upload files with appropriate authorizations. Cannot interfere with other users or their contents. 

## 2. Functionality to Create/Delete User  

***Assumptions:***
- Users can only create and delete their own accounts and cannot interfere with other user accounts nor use administrative tools unless the user is specified to be an admin. 
- Users already know at least one group they want access to when requesting the creation of an account. Upon creation, users are assigned to such group after approval form an administrator/moderator.  

***Security Properties:***
1. ***Property: User Creation Privileges.*** Anyone can request the creation of regular user accounts, which will require approval from authorized users.  Users will need to specify the group they want to join, for moderators of that group or system administrators to grant them access. 
1. ***User Creation Access Level Designation Restrictions.*** Newly created users are by default only allowed user level access privileges. Creating new administrative accounts will require some other level of user creationrequire admin privileges. This is necessary as users by default should not be able to create accounts with any privileges. Admins will also have the permissions to designate group moderators. <br />
There will also be restrictions on the way in which creations requests are allowed: Email verification will be required, with a limit to one request per email at a time. Human verification will be required  as well. Banned accounts, and associated emails, will be blacklisted. 
1. ***Property: Identity/Account Uniqueness.*** One identity shall be used to create one and only one account in the system. Without this property, one identity can be used to create multiple accounts, which will increase the attack surface of the system.  
1. ***Property: User Deletion Privileges.*** Deletion of a particular user profile can only be accomplished by the user in control of that account as well as by admins. If an admin wants to delete a user’s account, another admin needs to confirm the action. This requirement prevents the deletion of a user account by other users, including mass-deletion from a compromised admin account by applying an implicit separation of privileges. 

## 3. Functionality to Create/Delete Group

***Assumptions:***
- Groups are created by administrators, when there’s at least one user requesting to pariticpate in such group, and are comprised of authorized users who are able to only access the files within the group

***Security Properties:***
1. ***Property: Group Creation Privileges.*** Groups can only be created by authorized users or admins to prevent the creation of unnecessary groups. The groups will also need a verified initial user, other than the admin creating it. This avoids flooding the server with new groups if the system is compromised, by applying an implicit separation of privileges. 
1. ***Property: Group Modification Privileges.*** Moderators only can apply modifications – which refers to any action that changes the state of the group other than group creation/deletion.  Any of such changes will requires permission from two moderators (unless there’s only one). In case of large groups, this avoids one moderator’s retaliation by applying separation of privileges. 
1. ***Property: Group Deletion Privileges.*** Group deletion can only occur from a moderator requesting deletion and an admin fulfilling the request, thus applying separation of privileges. 
1. ***Property: Authentication.*** Creation and deletion of groups will require further authentication from admins. This is to prevent session hijacking by applying complete mediation. 
1. ***Property: Group Sanitization.*** The system will perform sanity checks in case that some group was left in the system after all users/files were removed. This will reduce the attack vector in case there exist backdoors in the form of malicious files or compromised accounts that seem inactive. 

## 4. Functionality to Add/Remove User u to/from Group g 

***Assumptions:***
- Users belong to particular groups where they are allowed to upload (if they are moderators) and download files that are within that particular group, and new users can be added or removed from that group.
- Group members can only be added via a user with elevated privileges and may only request to join group.
- Group members can leave out of their own volition or can be ejected by a user with elevated privileges.

***Security Properties:***
1. ***Property: Add User to Group g.*** Users can only be added to a group g after submitting a request that shall be reviewed and either approved or rejected by a moderator of said group. This is to mitigate users that have been blacklisted in other groups for malicious behavior and may pose a threat to group g . This property applies the principle of fail-safe defaults. 
1. ***Property: Remove User from Group g.*** Users can be removed from a group either by removing themselves voluntarily or by moderators users, and no other users without the appropriate permissions. Authorized users can forcefully remove a user from a group for engaging in malicious behavior, but they will need confirmation from at least one more authorized user. This is a measure to ensure separation of privilege. 
1. ***Property: Authentication.*** Creation and deletion of groups will require further authentication from admins. This is to prevent session hijacking by applying the principle of complete mediation. 

## 5. Functionality to Upload/Overwrite File f to be shared with members of group g

***Assumptions:***
- File f can only be shared among members of group g and no one else 
- File f can only be overwritten by the original uploader or other users with elevated privileges (Admins) 
- File f is group-specific. If users from a different group want to access files from a different group, they can either join the group, or have a common member request an upload it to their group. 

***Security Properties***
1. ***Property: Upload File Privilege.*** Only moderators within the specified group are able to upload files. This is to ensure that no users (those outside of the group) are able to upload files without the proper privileges, reducing the attack vector. This property applied the principle of least privilege. 
1. ***Property: Malicious File Check.*** Every uploaded file in the file system shall be scanned to check if they contain malicious code that can potentially damage the integrity of the file system. 
1. ***Property: File Correctness***. The file uploaded from a user and the file received at the file system shall be consistent (i.e. data integrity).
1. ***Property: File Write Authentication.*** Files can only be written, or overwritten, by authorized individuals/admins to preserve the integrity of the data. Overwriting a file must first be verified that the user has appropriate privileges, as a unauthorized code can change files to differ than what they originally were or outright delete files. This property applies the principle of complete mediation. 
1. ***Property: File size limit.*** The size of uploaded files will be limited to prevent overflowing the system’s capacity. 

## 6. Functionality to Download file f

***Assumptions:***
- Files can only be downloaded by members within a particular group g 

***Security Properties:***
1. ***Property: File Correctness.*** The file downloaded by a user and the file stored at the file system shall be consistent (i.e. data integrity). 
1. ***Property: File Download Privileges.*** File f can only be downloaded by users within a particular group g.  
1. ***Property : Group-based File Isolation.*** Files cannot be shared across groups – re-uploading the file to the new group will be necessary for the data to be accessible from more than one group. This applies the least common mechanism principle in an attempt to contain the spread of malicious files in case they are successfully uploaded to a group. 

## 7. Functionality to Delete file f 

***Assumptions:***
- Files can only be deleted from the group by original uploader/admins

***Security Properties:***
- ***Property: File Deletion Privileges.*** Files can only be deleted by moderators. This is to prevent the unwanted or malicious deletion of files. Authorized users can only be from the same group the file is contained in. The deletion of a file will require the approval of two moderators to provide separation of privileges. 
- ***Property: Authentication.*** Deletion of files will require further authentication from the moderators. This is to prevent session hijacking by applying complete mediation. 

## 8. General Authentication Enforcement 

***Assumptions:***
- The network is not reliable and insecure during the data transmission. Authentication is required to protect the system from eavesdroppers. 
- The encryption protocol is secure.

***Security Properties:***
- ***Property: Encryption.***  To provide continued authentication, the session traffic will be encrypted since the user connects to the file server. This will preserve data confidentiality and provide enough authentication to trust non-privileged user actions such as file download, which are unlikely compromise the whole system. 
- ***Property: Complete mediation.*** Users and moderators will need to reauthenticate every time they want to perform actions within a different group than the current one. This is to prevent session hijacking by applying complete mediation. Additionally, any privileged user action which escapes the security properties above defined, will require further authentication. 


## 9. System isolation

***Assumptions***
- Fail-safe defaults are applied to the system to prevent privilege escalation or the inverse, privileged users compromising the whole system.
1. ***Property: Role-Based Access Control.*** If the same person has different roles in the system, they will need different accounts. This is an attempt to apply separation of privileges and least common mechanism principles. 
1. ***Property: Filesystem isolation.*** Moderators only have permissions in the path where their group lives, in an attempt to apply the least common mechanism principle to isolate breaches in a single group. 
1. ***Property: Administrator limitation*** Administrators will have limited access to group contents to prevent compromising all the system information after an admin account is compromised. This is an attempt to preserve data confidentiality after and admin’s account is compromised. 

# Section 2: Threat Models

# Model 1
The file sharing system, composed of a file server and group server, shall be accessed via a terminal that is securely connected to a network. Issues arise in the fallibility of users, who can pose a threat to the data within group servers or the system as a whole. All users who do not have proper, pre-approved authorization shall be restricted to the most basic level of privileges to prevent the unwanted alteration or destruction of data (least privilege). Furthermore, the system will be designed with the assumption that every new user has a reason to be, either membership to a group or administrative purposes, so the number of active users are kept to the minimum necessary.  

This scenario assumes any user can be a malicious user acting from a compromised account. 

Administrators are trusted individuals with server-wide permissions; they have complete control over most aspects of the servers and users and can make almost any modifications as they wish. However, in the interest of separation of privilege, certain actions will require the authorization of more than one administrator, such as a complete server wipe or deletion of a group, as having additional input is necessary to prevent megalomaniacal decisions. Also, in an attempt to contain the consequences of a breached administrator account, a single admin’s actions will be limited, requiring further confirmation from another admin. 

Depending on the size, having administrators govern the entire system can become unviable given the human element. Therefore it is necessary to implement a moderation mechanism for each group; trusted users can be appointed by admins to govern a group and possess administrative privileges within that group only; these privileges do not extend outside of the group. 

Moderators within a group may upload files to their group, however all files should have a mechanism that checks whether the file is malicious or not using. 

# Model 2

Since the main application is a File Server, and not necessarily an FTP Server, it seems reasonable to assume the server will be suitable for small to medium size companies at most, such as smaller technology companies or educational institutions where the server would not be accessible to the general public (I.e. regular employees or students) but only to those who require access to perform their jobs. Therefore, it seems reasonable to assume the server will be located in an intranet. 

In any of the two given scenarios, it seems unlikely the users’ work machines will be isolated from the rest of their devices (phones, tablets, personal computers, email servers, cloud storage, etc.). Therefore, they will be opening data paths to the outside and creating an indirect connection to the internet, even if the system is in an intranet. 

For that reason, non-privileged users won’t be trusted with any permissions other than reading files (including download) in their corresponding group. If complete mediation is not feasible due to the size of the organization and upload requests cannot go through an administrator, more automated measures (like heuristic scanners) might be necessary in order to allow users to upload files. 

It is also very probable that there is a WLAN in place at the workspace to which some of the computers granted access to the system may be connected. Therefore, traffic should be encrypted, even if the connection to the file server is wired. It takes just one computer in the network connected to the WLAN ( or to any other device that is connected to a WLAN) to open a path to eavesdroppers, either through network traffic interception tools or spyware infections.

# Model 3

Considering the previous model, it is necessary that the server will be deployed in a place where the physical security is enforced.  

The user will access the server through a network client on an on-site computer. We assume that the stability of network connection is provided by network service companies. We do not assume that the network connection is secure. We assume that the group creator can be trusted and is given the group moderator privilege by default. The group moderator will manage the privilege of each member and assess the risk of giving privilege to potentially malicious users. We assume that the user will not give their account login credentials (temporary tokens, username/password pairs, etc.) to people with malicious purposes. 

# References
Stallings, William, and Lawrie Brown. Computer Security. Pearson Education (US), 2017.
