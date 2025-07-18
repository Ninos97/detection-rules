# Detection Rule: Attempt to Logon to a Dormant Account

## KQL Query
```kql
// Attempt to Logon to a Dormant Account
// Definition: Dormant Account is an Account which has not attempted to Logon (interactive) for over 180 days
// Reference: https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference?tabs=log-analytics
// Exclude AuditLog -> Enabled Account (because it means user is back)
let LogonFromManagedDevice = DeviceLogonEvents
| where TimeGenerated > ago(1d)
| distinct InitiatingProcessAccountUpn;
let RecentylyEnabledAccounts = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Enable account"
| extend userPrincipalName_ = tostring(TargetResources[0].userPrincipalName)
| distinct userPrincipalName_;
let DisabledAccountsSignins = SigninLogs
| where ResultType == "50057"
| where TimeGenerated > ago(1h)
| distinct UserPrincipalName;
let AccountDomain = dynamic([""]); // Optional: Use watchlist to populate known valid domains
let UPN_Suffix = "@<company_site>.<tld>"; // Customize for your organization
BehaviorAnalytics
| where TimeGenerated > ago(1h)
| where ActivityType in ("LogOn", "FailedLogOn")
| where UsersInsights.IsDormantAccount == True
| extend AccountType = iff(tostring(UsersInsights.AccountDomain) in (AccountDomain) or UserPrincipalName endswith UPN_Suffix, "Member", "Guest")
| extend AccountDomain_ = tostring(UsersInsights.AccountDomain)
| where UserPrincipalName !in~ (RecentylyEnabledAccounts)
| where UserPrincipalName !in~ (DisabledAccountsSignins)
| where UserPrincipalName !in~ (LogonFromManagedDevice)
| where AccountType == "Member" or isnotempty(AccountDomain_)
| project-reorder AccountDomain_, AccountType, ActivityType, ActionType, UserPrincipalName, SourceIPAddress, UsersInsights, DevicesInsights, ActivityInsights
```
# Logic Behind the Rule

This rule detects logon attempts from dormant accounts which are defined as accounts with no interactive logons in the last 180 days, as determined by Microsoft UEBA (User and Entity Behavior Analytics) via the UsersInsights.IsDormantAccount field.


## Key Components:

| Signal                 | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| **DeviceLogonEvents**  | Identifies accounts that signed into any managed endpoint.              |
| **AuditLogs**          | Excludes recently enabled accounts that were intentionally reactivated. |
| **SigninLogs (50057)** | Excludes attempts from **disabled accounts** (considered an IoA, not an IoC).      |
| **BehaviorAnalytics**  | Primary source to identify dormant accounts and user activity type.     |


## Definitions:
**Dormant Account**: UsersInsights.IsDormantAccount == True means no successful logons for >180 days.

**Disabled Account**: Signin ResultType 50057 (User account is disabled).

## Scenarios Detected:
Accounts of employees who are no longer with the company whose account was not disabled.

Accounts used in a service context which are no longer in use and forgotten about. 

Any other scenario where an account should've been disabled but was not like a test account.

## Known Limitations
| Limitation | Explanation |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **False Positives** | Admin testing or legitimate reactivation before full enablement logs appear. |
| **Recently enabled accounts** | If an account was enabled (ex: employee back to work after leave), but the enablement occurred outside of timeframe defined in the rule, it will trigger. |


## Investigation Steps
When the rule triggers, follow these steps to investigate:

**Check AuditLogs:**

1. Was the account recently enabled?
2. Any password reset or account update?

**Validate the Dormancy Claim:**

1. Use raw SigninLogs or AD logon records to confirm long inactivity.
2. Cross-reference with HR/Identity Sources:
3. Dormant accounts may belong to former employees or contractors.

**Check Source IP:**

1. Internal vs external? Suspicious geolocation? Tor/VPN/IP abuse?
2. Did the device activity actually originate from a corporate-managed endpoint?

**Contextualize**
1. was the logon successful
2. what app was used
3. any activities occurred post login
  
## Rule Customization and Fine-Tuning
  This is a general-purpose rule. It must be tailored to fit your specific environment.
  
  Investigate flagged results thoroughly to understand the root cause.
  
  Adjust exclusions, watchlists, or timeframes as needed to reduce false positives.
