# windows_coraza_waf
A very simple Web Application Firewall based on Coraza (https://github.com/corazawaf/coraza). This is a work in progress. 

## Build

Create Exectuable: 
```
GOOS=windows GOARCH=amd64 go build -o CorazaWindowsWAFProxy.exe
```

## Run
Either download the release and extract the zip file or build the executable from source. If you build the executable from source, you need to download this folder https://github.com/corazawaf/coraza-coreruleset/tree/main/rules and put it in the same directory as the executable. 

If you download the release, you can run the executable directly with these arguments: 
```
.\CorazaWindowsWAFProxy.exe -service install -listen 8083 -target 80
sc start CorazaWindowsWAFProxy
```

It will install the service and its files in the ProgramData folder. This includes a config.json file, which can be edited to change the port forwarding settings. 