# GOPsExec

Clone of psexec, but in golang. Embedded service binary is written in C++

# Usage
`gopsexec.exe -h 192.168.56.108 -d hackerlab -u turtleadmin -p 123456 -c systeminfo -v`
```
Usage of gopsexec.exe:
  -c string
        Command to run on target, will be passed like this to cmd.exe /c {yourcommandhere} NOTE command cannot exceed 1000 characters. (default "whoami")
  -d string
        Domain (default ".")
  -h string
        Host (default "localhost")
  -p string
        Password
  -u string
        Username
  -v    Verbose Flag
```
