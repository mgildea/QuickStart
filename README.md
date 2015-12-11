QuickStart
==========

Quick Start MVC .NET project with individual user accounts

To rename the Solution and project refer to the following tutorial:
http://www.codeproject.com/Articles/697108/Visual-Studio-Painlessly-Renaming-Your-Project-and

To reserve a new SSL Port:
Highlight Project
in properties pane set SSL Enabled to false and save
reset SSL Enabled to true.  A new SSL Url will be generated.
Updated the project properties > Web > Start and Project url.  Create Virtual Directory


project requires:

~/ConnectionStrings.config

<connectionStrings>
  <add name="DefaultConnection" connectionString="..." providerName="System.Data.SqlClient" />
</connectionStrings>

~/PrivateSettings.config

<appSettings>
  <add key="sendGridAccount" value="..."/>
  <add key="sendGridPassword" value="..."/>
  <add key="twilioAccount" value="..."/>
  <add key="twilioAuthToken" value="..."/>
  <add key="twitterConsumerKey" value="..."/>
  <add key="twitterConsumerSecret" value="..."/>
  <add key="facebookAppId" value="..."/>
  <add key="facebookAppSecret" value="..."/>
  <add key="googleClientId" value="..."/>
  <add key="googleClientSecret" value="..."/>
  <add key="smsFromPhone" value="..." />
  <add key="mailFromAddress" value="..."/>
  <add key="mailFromDisplay" value="..."/>
</appSettings>