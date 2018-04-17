//Step 1: Open fiddler rules JS file by going to Rules->Customize Rules...
//Alternatively, you can use CTRL+R


//Step 2: Insert this fragment at the beginning of rules.js
public static RulesOption("&Highlight Azure AD Traffic", "Azure A&D")
var m_HighlightAAD: boolean = false;
	
public static RulesOption("&Show only Azure AD Traffic", "Azure A&D")
var m_FilterAAD: boolean = false;


//Step 3: Copy this static function inside the Handlers class
static function ApplyAzureADRules(oSession : Session)
{
	if (m_HighlightAAD || m_FilterAAD )
	{			
		var hideFrame = true;
		var backgroundColor = "";
		
		//Case 1: Orange: show any requests that redirect to AAD			
		if (oSession.responseCode == 302 && 
			(
			oSession.ResponseHeaders.ExistsAndContains("Location","login.microsoftonline.com") ||
			oSession.ResponseHeaders.ExistsAndContains("Location","login.windows.net") ||		
			oSession.ResponseHeaders.ExistsAndContains("Location","device.login.microsoftonline.com")
			)
			)
		{
			backgroundColor = "Orange";	
			hideFrame = false;
		}
		
		//Case 2: Lavender: Show all Authn Requests
		if (
			(oSession.oRequest.host == "login.microsoftonline.com" || 
			oSession.oRequest.host == "login.windows.net" ||
			oSession.oRequest.host == "device.login.microsoftonline.com") && (!oSession.fullUrl.Contains("/common/login/telemetry"))
			)
		{
			backgroundColor = "Lavender";
			hideFrame = false;
		}
		
		//FiddlerApplication.Log.LogString(oSession.oRequest.headers.AllValues("Referer"));
		
		//Case 3: Pink: show any requests that are referred from AAD
		if (
			oSession.oRequest.headers.ExistsAndContains("Referer","login.microsoftonline.com") ||
			oSession.oRequest.headers.ExistsAndContains("Referer","login.windows.net") ||		
			oSession.oRequest.headers.ExistsAndContains("Referer","device.login.microsoftonline.com")
			)
		{
			backgroundColor = "Pink";	
			hideFrame = false;
			
			//Case 2: Green: Show all Frames with Responses
			var requestBody = oSession.GetRequestBodyAsString()
			if (requestBody.Contains("code=") || requestBody.Contains("token=") || requestBody.Contains("SAMLResponse="))
			{
				backgroundColor = "Lime";
				hideFrame = false;
			}
		
			if (oSession.fullUrl.Contains("token=") && oSession.fullUrl.Contains("#"))
			{				
				backgroundColor = "Lime";
				hideFrame = false;
			}

		}
		
		
				
		if (hideFrame && m_FilterAAD)
		{
			oSession["ui-hide"] = "Hide";
		}
		
		if (backgroundColor != "" && m_HighlightAAD)
		{
			oSession["ui-backcolor"] = backgroundColor;
		}
	}
}

//Step 4: Call the function at OnPeekAtResponseHeaders
ApplyAzureADRules(oSession);
