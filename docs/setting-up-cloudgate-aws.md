# Setting up CloudGate with AWS

Cloudgate works using the STS functionality of AWS IAM.
There are 3 main paths inside the AWS code:
1. Get the list of accounts/roles the user can assum
2. Get an STS token for an account+Role.
3. Get a console URL redirection for an Account+Role.

Cloudgate uses an IAM user that is allowed to list roles in each account and is also trusted to assume certain roles in that account. Cloudgate assumes there is a common role in each account that permits is to list the roles in that account. By default the name of this role is: `CPEBrokerRole`, but it can be selected on the configuration (as aws_list_roles_role_name). Whatever name it is it MUST be the same across all accounts.

This `aws_list_roles_role_name`  should have the following policy in each account:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "iam:ListRoles",
                "iam:GetRole"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "BrokerIAMRoleReadonly"
        }
    ]
 }
 ```

The IAM user associated with CloudGate MUST have a trust relationship with this role. On the IAM console you should see something like:
```
Trusted entities:
arn:aws:iam:$SOMEACCOUNTID:user/$CLOUDGATE_IAM_USER
```

Then for each role that you want to be assumable by CloudGate you need to:
1. Create the role in AWS and make is trusted by CloudGate's IAM user.
2. Create a group in LDAP/AD with the following naming convention:
$COMMON_PREFIX-$ACCOUNT_NAME-$aws_list_roles_role_name


## Example
Lets suppose you have account 0123456789012 as the account where the CloudGate user lives and the name for this IAM user is: auto-cloudgate.
We also have account 123456789012 with roles admin, SystemsEngineering, and NetworkEngineering. Lets also assume that your LDAP group prefix is AWS-ACCESS-GROUPS

So
1. You need to get security credentials for the cloudgate user: `arm:aws:iam:0123456789012:user/auto-cloudgate` and put these credentials in CloudGate's credentials file
2. You need to create a new role in the 123456789012 with name `CPEBrokerRole` and attach the policy defined previously in this document.
3. You need to setup a trust relationShip on the `CPEBrokerRole` to trust `arm:aws:iam:0123456789012:user/auto-cloudgate`
4. You need to setup the accounts.yml file with at least the following contents:
```
aws:
   group_prefix: "AWS-ACCESS-GROUPS-"
   account:
      - name: "base-mainAccount"
        account_id: "0123456789012"
      - name: "developmentaccount"
        account_id: "123456789012"
        display_name: "Development Account"
```
5. You need to create the ldap groups: `AWS-ACCESS-GROUPS-developmentaccount-admin`, `AWS-ACCESS-GROUPS-developmentaccount-SystemsEngineering`, and `AWS-ACCESS-GROUPS-developmentaccount-NetworkEngineering`.
6. For each of the roles you want to enable on cloudgate within the account 123456789012(admin, SystemsEngineering, and NetworkEngineering) you need to setup a trust relationship against `arm:aws:iam:0123456789012:user/auto-cloudgate`
