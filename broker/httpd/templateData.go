package httpd

type consolePageTemplateData struct {
	Title        string
	AuthUsername string
	JSSources    []string
	ErrorMessage string
}

//Should be a template
const consoleAccessTemplateText = `
{{define "consoleAccessPage"}}
<!DOCTYPE html>
<html style="height:100%; padding:0;border:0;margin:0">
    <head>
        <meta charset="UTF-8">
        <title>{{.Title}}</title>
        <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Droid+Sans" />
        <link rel="stylesheet" type="text/css" href="/static/customization.css">
        <link rel="stylesheet" type="text/css" href="/static/common.css">
    </head>
    <body>
    <div style="min-height:100%;position:relative;">
    {{template "header" .}}
        <div style="padding-bottom:60px; margin:1em auto; max-width:80em; padding-left:20px ">
        <h2> AWS Console Access </h2>
        {{if .ErrorMessage}}
        <p style="color:red;">{{.ErrorMessage}} </p>
        {{end}}
        </div>
    {{template "footer" . }}
    </div>
    </body>
</html>
{{end}}
`

const customizationCSS = `
.header {
font-size: 95%;
height:35px;
color: #f4f4f4;
background-color: #213c60; /*Symantec yelllow: #FDBB30*/
width:100%;
}

.header a:link {
        font-size: 85%;
        color: #FDBB30
}
.header a:visited {
        font-size: 85%;
        color:  #FDBB30
        }

.header_extra{
        font-size: 140%;
        padding-left: 1.2em;
        line-height:normal;
}

.footer {
    font-size: 95%;
    height:60px;
    position:absolute;
    width:100%;
    bottom:0;
}
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
<div class="header">
<table style="width:100%;border-collapse: separate;border-spacing: 0;">
<tr>
<th style="text-align:left;"> <div class="header_extra">Symantec Cloud-Gate</div></th>
<th style="text-align:right;padding-right: .5em;">  {{if .AuthUsername}} <b> {{.AuthUsername}}  {{end}}</th>
</tr>
</table>
</div>

{{end}}
`

const footerTemplateText = `
{{define "footer"}}

<div class="footer">
<hr>
<center>
Copright 2018 Symantec Corporation. 
</center>
</div>
{{end}}
`
