package httpd

type cloudAccountInfo struct {
	Name           string
	AvailableRoles []string
}

type consolePageTemplateData struct {
	Title         string `json:",omitempty"`
	AuthUsername  string
	JSSources     []string `json:",omitempty"`
	ErrorMessage  string   `json:",omitempty"`
	CloudAccounts map[string]cloudAccountInfo
	TokenConsole  bool
}

//Should be a template
const consoleAccessTemplateText = `
{{define "consoleAccessPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
	<link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/common.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
        <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> {{if .TokenConsole}} AWS Token Access {{else}}AWS Console Access {{end}} </h2>
        {{if .ErrorMessage}}
        <p style="color:red;">{{.ErrorMessage}} </p>
        {{end}}
        <p>
	Go to:  {{if .TokenConsole}} <a href="/">Web Console</a> {{else}} <a href="/?mode=genToken">Token Console </a> {{end}} 
	</p>

        {{with $top := . }}
	<div id="accounts">
          <table class="table table-striped table-sm">
	     <tr>
	       <th>Account</th>
	       <th>Roles</th>
	     </tr>
	   {{range $key, $value := .CloudAccounts}}
	     <tr>
	     <form action={{if $top.TokenConsole}}"/generatetoken"{{else}}"/getconsole" target="_blank"{{end}}>
		<input type="hidden" name="accountName" value="{{$value.Name}}">
	        <td>{{$key}}
		</td>
		<td>
		{{range $index, $role:= $value.AvailableRoles}}
		    <button class="btn btn-info ml-1 mr-1 btn-sm"
		            style="background-color:#00a4b7;margin-bottom: .1rem !important;margin-top: .1rem !important;"
		            type="submit" name="roleName" value="{{$role}}">
	            {{$role}}
		    </button>
		{{end}}
		</td>
		</form>
	     </tr>
	   {{end}}
	   {{end}}
	  </table>
	</div>
        </div>
    {{template "footer" . }}
    </div>
    </body>
</html>
{{end}}
`

type generateTokenPageTemplateData struct {
	Title           string `json:",omitempty"`
	AuthUsername    string
	JSSources       []string `json:",omitempty"`
	ErrorMessage    string   `json:",omitempty"`
	AccountName     string
	RoleName        string
	SessionId       string `json:"sessionId"`
	SessionKey      string `json:"sessionKey"`
	SessionToken    string `json:"sessionToken"`
	TokenExpiration string `json:"tokenExpiration"`
	Region          string `json:"region,omitempty"`
}

const generateTokaneTemplateText = `
{{define "generateTokenPagePage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/common.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
        <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> Token Output </h2>
        {{if .ErrorMessage}}
        <p style="color:red;">{{.ErrorMessage}} </p>
        {{end}}
        <p>
	Go to:  <a href="/?mode=genToken">Token Console </a>
	</p>
	<div>
	<code class="aws_token_text">
	[{{.AccountName}}-{{.RoleName}}] <br>
	{{if .Region}}<p>region = {{.Region}}<br>{{end}}
	aws_access_key_id = {{.SessionId}}<br>
        aws_secret_access_key= {{.SessionKey}}<br>
	aws_session_token = {{.SessionToken}}<br>
	token_expiration = {{.TokenExpiration}}<br>
	</code>
	</div>
        </div>
    {{template "footer" . }}
    </div>
    </body>
</html>
{{end}}
`

type unsealingFormPageTemplateData struct {
	Title        string `json:",omitempty"`
	AuthUsername string
	JSSources    []string `json:",omitempty"`
	ErrorMessage string   `json:",omitempty"`
}

const unsealingFormPageTemplateText = `
{{define "unsealingFormPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/custom_static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/common.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
        <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> CloudGate Unsealing </h2>
        {{if .ErrorMessage}}
        <p style="color:red;">{{.ErrorMessage}} </p>
        {{end}}
        <p>
        Go to:  <a href="/status">Status </a>
        </p>
        <div>

        <form enctype="application/x-www-form-urlencoded" action="/unseal" method="post">
            <p>Unsealing Secret: <INPUT TYPE="password" NAME="unsealing_secret" SIZE=18  autocomplete="off"></p>
            <INPUT TYPE="hidden" NAME="username" VALUE={{.AuthUsername}}>
            <p><input type="submit" value="Submit" /></p>
        </form>

        </div>
        </div>
    {{template "footer" . }}
    </div>
    </body>
</html>
{{end}}
`

const commonCSS = `
body{
    padding:0;
    border:0;
    margin:0;
    height:100%;
    font-family: "Droid Sans", sans-serif;
    color: #212424;
    background-color: #f4f4f4;
}

h1,h2,h3{
    line-height:1.2;
}


.bodyContainer {
}

@media print{body{max-width:none}}
`

const headerTemplateText = `
{{define "header"}}
   <nav class="navbar pt-0 pb-0" style="background-color: #213c60; color: #f4f4f4;">
      {{template "header_extra"}}
     <span class="navbar-text navbar-right h6 mb-0">{{if .AuthUsername}} {{.AuthUsername}}  {{end}} </span>
   </nav>
{{end}}
`

const footerTemplateText = `
{{define "footer"}}
<footer class="footer fixed-bottom">
<hr>
<center>
Copyright 2018 Symantec Corporation. {{template "footer_extra"}}
</center>
</footer>
{{end}}
`
