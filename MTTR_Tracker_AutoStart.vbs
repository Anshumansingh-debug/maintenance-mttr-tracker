Set objShell = CreateObject("WScript.Shell")

Function IsServerUp()
    Dim objHTTP
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    On Error Resume Next
    objHTTP.Open "GET", "http://localhost:4100/health", False
    objHTTP.Send
    If Err.Number = 0 And objHTTP.Status = 200 Then
        IsServerUp = True
    Else
        IsServerUp = False
    End If
    On Error Goto 0
End Function

objShell.CurrentDirectory = "C:\Users\LENOVO\Downloads\MTTR_Tracker"

If Not IsServerUp() Then
    objShell.Run "cmd /c node server.js > server_out.log 2> server_err.log", 0, False

    Dim waited
    waited = 0
    Do While waited < 20000
        WScript.Sleep 500
        waited = waited + 500
        If IsServerUp() Then Exit Do
    Loop
End If

objShell.Run "cmd /c ""C:\Users\LENOVO\Downloads\MTTR_Tracker\start_tunnel.bat""", 0, False
