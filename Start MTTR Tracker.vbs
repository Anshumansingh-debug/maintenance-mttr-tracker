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

If Not IsServerUp() Then
    objShell.CurrentDirectory = "C:\Users\LENOVO\Downloads\MTTR_Tracker"
    objShell.Run "cmd /c node server.js > server_out.log 2> server_err.log", 0, False

    Dim waited, ready
    waited = 0
    ready = False
    Do While waited < 20000
        WScript.Sleep 500
        waited = waited + 500
        If IsServerUp() Then
            ready = True
            Exit Do
        End If
    Loop
End If

objShell.Run "http://localhost:4100", 1, False
